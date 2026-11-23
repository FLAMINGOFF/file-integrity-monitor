#!/usr/bin/env python3
"""
文件完整性监控 (File Integrity Monitor, FIM)

思路和 Tripwire / AIDE 这类工具一样：
  1. init  ：对关键目录里的每个文件算 SHA-256，连同大小、权限一起存成「基线」
  2. check ：重新扫描，和基线比较，报告 新增 / 修改 / 删除 / 权限变化
  3. watch ：每隔 N 秒自动 check 一次，发现新的异常就告警

基线本身也可能被攻击者改掉（改完文件顺手重建基线），所以支持用
HMAC-SHA256 给基线签名：密钥放在环境变量 FIM_KEY 里，不写进基线文件。

只依赖 Python 标准库，Python 3.8+ 可直接运行。
"""

import argparse
import datetime as dt
import fnmatch
import hashlib
import hmac
import json
import os
import platform
import stat
import subprocess
import sys
import time

VERSION = 1
CHUNK = 1024 * 1024          # 分块读取，大文件也不会占满内存
DEFAULT_BASELINE = "fim_baseline.json"
KEY_ENV = "FIM_KEY"

# 退出码
EXIT_OK, EXIT_CHANGED, EXIT_ERROR, EXIT_TAMPERED = 0, 1, 2, 3


# ───────────────────────── 第 1 步：扫描与哈希 ─────────────────────────

def sha256_file(path: str) -> str:
    """流式计算文件的 SHA-256。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def file_record(path: str) -> dict:
    """为单个路径生成一条记录。符号链接不跟随，只记录它指向哪里。"""
    st = os.lstat(path)
    rec = {"size": st.st_size, "mode": stat.filemode(st.st_mode)}
    if stat.S_ISLNK(st.st_mode):
        # 只哈希链接目标字符串：链接被改指向别处也能发现
        rec["type"] = "symlink"
        rec["sha256"] = hashlib.sha256(os.readlink(path).encode()).hexdigest()
    else:
        rec["type"] = "file"
        try:
            rec["sha256"] = sha256_file(path)
        except OSError as e:          # 没权限读等情况：记下来，不中断扫描
            rec["sha256"] = None
            rec["error"] = e.strerror or str(e)
    return rec


def is_excluded(rel_path: str, patterns) -> bool:
    name = os.path.basename(rel_path)
    return any(fnmatch.fnmatch(rel_path, p) or fnmatch.fnmatch(name, p) for p in patterns)


def scan(roots, excludes=()) -> dict:
    """扫描若干目录（或单个文件），返回 {绝对路径: 记录}。"""
    result = {}
    for root in roots:
        root = os.path.abspath(root)
        if os.path.isfile(root) or os.path.islink(root):
            result[root] = file_record(root)
            continue
        if not os.path.isdir(root):
            raise FileNotFoundError(f"路径不存在: {root}")
        for dirpath, dirnames, filenames in os.walk(root):   # 默认不跟随目录符号链接
            rel_dir = os.path.relpath(dirpath, root)
            # 原地修改 dirnames，让 os.walk 不进入被排除的目录
            dirnames[:] = sorted(d for d in dirnames
                                 if not is_excluded(os.path.normpath(os.path.join(rel_dir, d)), excludes))
            for name in sorted(filenames):
                rel = os.path.normpath(os.path.join(rel_dir, name))
                if is_excluded(rel, excludes):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    result[full] = file_record(full)
                except FileNotFoundError:     # 扫描途中被删掉了
                    pass
    return result


# ───────────────────────── 第 2 步：基线（含 HMAC 签名） ─────────────────────────

def _canonical(data: dict) -> bytes:
    """确定性的 JSON 序列化：同样的内容永远得到同样的字节，签名才可复现。"""
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def sign(data: dict, key: str) -> str:
    return hmac.new(key.encode(), _canonical(data), hashlib.sha256).hexdigest()


def drop_self(files: dict, baseline_path: str) -> dict:
    """基线文件放在被监控目录里时，不要把它自己算进去（否则每次都报「修改」）。"""
    me = os.path.abspath(baseline_path)
    for p in (me, me + ".tmp"):
        files.pop(p, None)
    return files


def build_baseline(roots, excludes, key=None, baseline_path=DEFAULT_BASELINE) -> dict:
    body = {
        "version": VERSION,
        "created": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "roots": [os.path.abspath(r) for r in roots],
        "excludes": list(excludes),
        "files": drop_self(scan(roots, excludes), baseline_path),
    }
    return {"baseline": body, "hmac": sign(body, key) if key else None}


def save_baseline(doc: dict, path: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.chmod(tmp, 0o600)          # 基线只给自己读写
    os.replace(tmp, path)         # 原子替换，避免写到一半留下坏文件


class BaselineTampered(Exception):
    pass


def load_baseline(path: str, key=None) -> dict:
    """读取基线并校验签名。返回 baseline 主体。"""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    body, mac = doc.get("baseline"), doc.get("hmac")
    if body is None or "files" not in body:
        raise BaselineTampered("基线文件格式不对")
    if key:
        if not mac:
            raise BaselineTampered("设置了 FIM_KEY，但基线没有签名（可能被替换成了未签名版本）")
        # compare_digest：恒定时间比较，防计时攻击
        if not hmac.compare_digest(mac, sign(body, key)):
            raise BaselineTampered("基线签名不匹配：基线文件被改过，或密钥不对")
    return body


# ───────────────────────── 第 3 步：比较 ─────────────────────────

def compare(old: dict, new: dict) -> dict:
    """比较两次扫描结果，返回四类变化（每类都是排好序的路径列表）。"""
    old_keys, new_keys = set(old), set(new)
    modified, perms = [], []
    for p in sorted(old_keys & new_keys):
        a, b = old[p], new[p]
        if a.get("sha256") != b.get("sha256") or a.get("type") != b.get("type"):
            modified.append(p)
        elif a.get("mode") != b.get("mode"):
            perms.append(p)
    return {
        "added": sorted(new_keys - old_keys),
        "modified": modified,
        "deleted": sorted(old_keys - new_keys),
        "permissions": perms,
    }


def has_changes(diff: dict) -> bool:
    return any(diff.values())


LABELS = {
    "added": ("[+] 新增", "added"),
    "modified": ("[*] 修改", "modified"),
    "deleted": ("[-] 删除", "deleted"),
    "permissions": ("[~] 权限", "permissions"),
}


def format_report(diff: dict, old: dict, new: dict) -> str:
    lines = []
    for kind, (label, _) in LABELS.items():
        for p in diff[kind]:
            extra = ""
            if kind == "modified":
                a, b = old[p], new[p]
                extra = f"  sha256 {(a.get('sha256') or '?')[:12]}… → {(b.get('sha256') or '?')[:12]}…"
            elif kind == "permissions":
                extra = f"  {old[p]['mode']} → {new[p]['mode']}"
            lines.append(f"{label}  {p}{extra}")
    return "\n".join(lines)


def summary(diff: dict) -> str:
    return "，".join(f"{LABELS[k][0][4:]} {len(v)}" for k, v in diff.items())


# ───────────────────────── 告警 ─────────────────────────

def now() -> str:
    return dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


def alert(message: str, log_path=None, notify=False) -> None:
    stamped = "\n".join(f"{now()} {line}" for line in message.splitlines())
    print(stamped, flush=True)
    if log_path:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(stamped + "\n")
    if notify and platform.system() == "Darwin":
        # macOS 系统通知。用 argv 传参而不是拼 shell 字符串，文件名里有引号也不会注入
        script = 'on run argv\ndisplay notification (item 1 of argv) with title "文件完整性告警"\nend run'
        subprocess.run(["osascript", "-e", script, message.splitlines()[0][:200]],
                       check=False, capture_output=True)


# ───────────────────────── 命令 ─────────────────────────

def get_key(args):
    key = os.environ.get(KEY_ENV)
    if args.require_key and not key:
        raise SystemExit(f"错误：使用了 --require-key，但环境变量 {KEY_ENV} 没有设置")
    return key


def cmd_init(args) -> int:
    key = get_key(args)
    doc = build_baseline(args.paths, args.exclude, key, args.baseline)
    save_baseline(doc, args.baseline)
    n = len(doc["baseline"]["files"])
    signed = "已用 HMAC 签名" if key else f"未签名，建议设置 {KEY_ENV}"
    print(f"[基线] 已记录 {n} 个文件 → {args.baseline}（{signed}）")
    return EXIT_OK


def run_check(args, key):
    base = load_baseline(args.baseline, key)
    current = drop_self(scan(base["roots"], base.get("excludes", [])), args.baseline)
    return base["files"], current, compare(base["files"], current)


def cmd_check(args) -> int:
    key = get_key(args)
    old, new, diff = run_check(args, key)
    if args.json:
        print(json.dumps(diff, ensure_ascii=False, indent=2))
    elif has_changes(diff):
        print(format_report(diff, old, new))
        print(f"⚠️  发现变化：{summary(diff)}")
    else:
        print(f"✅ 未发现变化（共检查 {len(new)} 个文件）")
    return EXIT_CHANGED if has_changes(diff) else EXIT_OK


def cmd_watch(args) -> int:
    key = get_key(args)
    print(f"[监控] 每 {args.interval} 秒检查一次，Ctrl+C 退出")
    last_reported = None
    try:
        while True:
            try:
                old, new, diff = run_check(args, key)
            except BaselineTampered as e:
                alert(f"🚨 {e}", args.log, args.notify)
                return EXIT_TAMPERED
            # 只在「变化集合」和上次不同时告警，避免同一个问题每轮刷屏
            fingerprint = json.dumps(diff, sort_keys=True)
            if fingerprint != last_reported:
                if has_changes(diff):
                    alert(f"⚠️  {summary(diff)}\n" + format_report(diff, old, new),
                          args.log, args.notify)
                elif last_reported is not None:
                    alert("✅ 已恢复到与基线一致", args.log)
                last_reported = fingerprint
            if args.once:
                return EXIT_CHANGED if has_changes(diff) else EXIT_OK
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[监控] 已停止")
        return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="文件完整性监控：SHA-256 基线 + 变化检测")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-b", "--baseline", default=DEFAULT_BASELINE,
                        help=f"基线文件路径（默认 {DEFAULT_BASELINE}）")
    common.add_argument("--require-key", action="store_true",
                        help=f"必须设置 {KEY_ENV}，否则拒绝运行（防止忘记签名）")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", parents=[common], help="扫描目录并生成基线")
    s.add_argument("paths", nargs="+", help="要监控的目录或文件")
    s.add_argument("-e", "--exclude", action="append", default=[],
                   help="排除的通配符，可多次使用，如 -e '*.log' -e '.git'")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("check", parents=[common], help="和基线比较一次")
    s.add_argument("--json", action="store_true", help="以 JSON 输出（方便接入其他工具）")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("watch", parents=[common], help="定时检查并告警")
    s.add_argument("-i", "--interval", type=float, default=10, help="检查间隔秒数（默认 10）")
    s.add_argument("--log", help="把告警追加写入这个日志文件")
    s.add_argument("--notify", action="store_true", help="macOS 下弹出系统通知")
    s.add_argument("--once", action="store_true", help=argparse.SUPPRESS)  # 测试用
    s.set_defaults(func=cmd_watch)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BaselineTampered as e:
        print(f"🚨 {e}", file=sys.stderr)
        return EXIT_TAMPERED
    except (OSError, json.JSONDecodeError) as e:
        print(f"错误：{e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
