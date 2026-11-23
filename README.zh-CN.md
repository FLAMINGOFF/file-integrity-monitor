# 文件完整性监控 (File Integrity Monitor)

[English](README.md) | **简体中文**

一个小巧的 Python 命令行工具：监控关键目录，发现文件被**新增、修改、删除或改了权限**
就告警。原理和 [Tripwire](https://github.com/Tripwire/tripwire-open-source) / AIDE 一样：
先记录一份 SHA-256「已知良好」基线，之后拿当前状态和它比较。

只用标准库，不需要 `pip install`。Python 3.8+。

## 用法

```bash
# 1. 生成基线（可选签名，见「保护基线」）
export FIM_KEY='一串足够长的随机密钥'
python3 fim.py init ~/.ssh /etc/hosts -b fim_baseline.json -e '*.log'

# 2. 检查一次
python3 fim.py check -b fim_baseline.json
python3 fim.py check -b fim_baseline.json --json     # 机器可读的输出

# 3. 持续监控，有变化就告警
python3 fim.py watch -b fim_baseline.json -i 30 --log alerts.log --notify

# 测试（离线，在临时目录里进行）
python3 -m unittest -v
```

输出示例：

```
[+] 新增  /Users/me/.ssh/authorized_keys2
[*] 修改  /etc/hosts  sha256 87428fc52280… → 0263829989b6…
[-] 删除  /Users/me/.ssh/known_hosts
[~] 权限  /Users/me/.ssh/id_ed25519  -rw------- → -rw-r--r--
⚠️  发现变化：新增 1，修改 1，删除 1，权限 1
```

| 退出码 | 含义 |
|---|---|
| `0` | 与基线一致 |
| `1` | 发现变化 |
| `2` | 出错（路径不存在、基线读不了等） |
| `3` | **基线本身签名校验失败** |

确认某个变化是正常的？重新运行一次 `init` 更新基线即可。

## 工作原理

```
init                                 check / watch
────                                 ─────────────
遍历目录 ─► 对每个文件记录：          再次遍历 ─► 当前快照
           SHA-256、大小、权限                      │
           │                         读取基线 ──────┤ 先校验 HMAC
           ▼                                        ▼
  fim_baseline.json  ◄─ HMAC(密钥)   按路径比较：
                                       只在新快照里  → 新增
                                       只在基线里    → 删除
                                       哈希不同      → 修改
                                       只有权限不同  → 权限
```

### 为什么要算哈希，而不是只看修改时间？
大小和 `mtime` 检查起来很快，但很容易伪造：攻击者可以写入同样字节数的内容，再用
`touch -r` / `os.utime` 把时间戳改回去。测试里专门有一条验证这种情况
（`test_same_size_same_mtime_still_detected`）。而文件哪怕只改一个比特，SHA-256 都会
完全不同，要构造出哈希相同的另一个文件在计算上不可行。

### 设计细节
- **流式哈希**：按 1 MiB 分块读取，大文件也不会占满内存。
- **不跟随符号链接**。对符号链接，哈希的是它*指向的路径字符串*，所以把
  `link` 改指向 `/etc/passwd` 也能发现，同时链接也没法把扫描引到监控范围之外。
- **没权限读的文件**会记录错误信息，不会让整个扫描中断。
- **基线文件自己会被跳过**：如果它放在被监控的目录里，否则每次都会报自己被修改。
- **原子、私有写入**：基线先写到权限为 `600` 的临时文件，再用 `os.replace` 替换。
- **watch 模式不刷屏**：只有当「变化集合」和上一轮不同时才告警，恢复正常时也会提示。
- macOS 下 `--notify` 通过 `osascript` 弹系统通知；消息作为参数传入，而不是拼进脚本，
  文件名里带引号也不会造成 AppleScript 注入。

## 保护基线

完整性监控的可信度取决于基线的可信度。能改 `/etc/hosts` 的攻击者，多半也能改
`fim_baseline.json`，把旧哈希换成新哈希，检查结果就成了「一切正常」。

本工具的办法是 **HMAC-SHA256 签名**：

- 设置了 `FIM_KEY` 时，`init` 会用它对基线的规范化 JSON 签名。
- `check` / `watch` 会重新计算 HMAC，不匹配就拒绝继续（退出码 `3`）；设置了密钥但基线
  没签名（降级攻击）也会拒绝。
- 比较使用 `hmac.compare_digest`（恒定时间）。
- `--require-key` 让工具在没有密钥时拒绝运行，防止忘记签名。

**密钥不存放在基线里。** 请放在攻击者读不到的地方，比如 macOS 钥匙串：

```bash
security add-generic-password -a "$USER" -s fim -w '一串足够长的随机密钥'
export FIM_KEY="$(security find-generic-password -a "$USER" -s fim -w)"
```

更进一步的加固（由弱到强）：把基线放在只读或可移动介质上；复制一份到另一台机器；
从另一台主机上运行检查。

## 局限性
- **轮询而非实时。** 在两次检查之间改了又改回去的操作会被漏掉。实时方案要用内核事件
  （macOS FSEvents / Linux inotify），需要第三方库或平台 API。
- **不知道是谁、为什么改的。** 它只负责发现，不负责溯源，应和系统日志（macOS 统一日志、
  Linux auditd）配合使用。
- **拿到 root 的攻击者可以绕过它**：停掉进程、从进程环境里读出 `FIM_KEY`，或者用
  rootkit 劫持文件系统。FIM 提高的是隐藏的成本，不是绝对保证。
- **第一次基线必须在干净的系统上生成。** 如果那时已经被入侵，入侵状态就成了「正常」。
- 不跟踪目录本身（空目录、目录权限），也不比较属主/属组和扩展属性，这些都容易扩展。
- 监控经常变化的目录会产生大量噪音。应选择稳定且敏感的目标（配置、密钥、程序），并用
  `-e` 排除日志和缓存。

## 文件
- `fim.py`：命令行工具，结构为 扫描/哈希 → 基线/HMAC → 比较 → 告警
- `test_fim.py`：离线测试（篡改、同大小同时间戳修改、符号链接改指向、伪造/未签名基线、
  watch 日志）

## 参考
- NIST SP 800-53，控制项 SI-7「软件、固件和信息完整性」
- Python `hmac` 文档：https://docs.python.org/zh-cn/3/library/hmac.html
- AIDE：https://aide.github.io/
