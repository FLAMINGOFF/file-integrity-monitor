# File Integrity Monitor

**English** | [简体中文](README.zh-CN.md)

A small Python CLI that watches important directories and tells you when a file is
**added, modified, deleted, or has its permissions changed**. It works like a
miniature [Tripwire](https://github.com/Tripwire/tripwire-open-source) / AIDE: record
a SHA-256 "known good" baseline, then compare against it.

Standard library only: no `pip install`. Python 3.8+.

## Usage

```bash
# 1. Record a baseline (optionally signed, see "Protecting the baseline")
export FIM_KEY='some-long-random-secret'
python3 fim.py init ~/.ssh /etc/hosts -b fim_baseline.json -e '*.log'

# 2. Check once
python3 fim.py check -b fim_baseline.json
python3 fim.py check -b fim_baseline.json --json     # machine-readable

# 3. Keep watching, alert on changes
python3 fim.py watch -b fim_baseline.json -i 30 --log alerts.log --notify

# Tests (offline, use a temp directory)
python3 -m unittest -v
```

Example output (the CLI prints in Chinese):

```
[+] 新增  /Users/me/.ssh/authorized_keys2
[*] 修改  /etc/hosts  sha256 87428fc52280… → 0263829989b6…
[-] 删除  /Users/me/.ssh/known_hosts
[~] 权限  /Users/me/.ssh/id_ed25519  -rw------- → -rw-r--r--
⚠️  发现变化：新增 1，修改 1，删除 1，权限 1
```

`新增` = added, `修改` = modified, `删除` = deleted, `权限` = permissions.

| Exit code | Meaning |
|---|---|
| `0` | Matches the baseline |
| `1` | Changes found |
| `2` | Error (path missing, unreadable baseline…) |
| `3` | **Baseline itself failed its signature check** |

Accepted a legitimate change? Run `init` again to refresh the baseline.

## How it works

```
init                                 check / watch
────                                 ─────────────
walk dirs ─► for each file:          walk dirs again ─► current snapshot
             SHA-256, size, mode                         │
             │                       load baseline ──────┤ verify HMAC first
             ▼                                           ▼
  fim_baseline.json  ◄─ HMAC(key)    compare by path:
                                       only in new      → added
                                       only in old      → deleted
                                       hash differs     → modified
                                       only mode differs→ permissions
```

### Why hash the content, not just look at timestamps?
Size and `mtime` are cheap to check but trivial to fake: an attacker can write the same
number of bytes and reset the timestamp with `touch -r` / `os.utime`. There is a test
for exactly that (`test_same_size_same_mtime_still_detected`). SHA-256 changes completely
if one bit of the file changes, and finding a different file with the same hash is
computationally infeasible.

### Design details
- **Streaming hash**: files are read in 1 MiB chunks, so large files don't fill memory.
- **Symlinks are not followed**. For a symlink, the *link target string* is hashed, so
  re-pointing `link → /etc/passwd` is detected, and a link can't make the scanner wander
  outside the monitored tree.
- **Unreadable files** are recorded with an error instead of aborting the scan.
- **The baseline file is skipped** if it lives inside a monitored directory, otherwise it
  would always report itself as modified.
- **Atomic, private writes**: the baseline is written to a temp file with mode `600`, then
  `os.replace`d into place.
- **Watch mode doesn't spam**: it alerts only when the set of differences changes, and
  says when things are back to normal.
- `--notify` on macOS shows a system notification via `osascript`; the message is passed
  as an argument, not spliced into the script, so a filename with quotes can't inject
  AppleScript.

## Protecting the baseline

An integrity monitor is only as trustworthy as its baseline. An attacker who can modify
`/etc/hosts` can probably also edit `fim_baseline.json` and replace the old hash with the
new one, and the check would then report "all clear".

This tool's answer is an **HMAC-SHA256 signature**:

- If `FIM_KEY` is set, `init` signs the canonical JSON of the baseline with it.
- `check` / `watch` recompute the HMAC and refuse to continue (exit `3`) if it doesn't
  match, or if a key is set but the baseline is unsigned (a downgrade attack).
- The comparison uses `hmac.compare_digest` (constant time).
- `--require-key` makes the tool refuse to run without a key, so you can't forget.

**The key is not stored in the baseline.** Keep it somewhere the attacker can't read,
such as the macOS Keychain:

```bash
security add-generic-password -a "$USER" -s fim -w 'some-long-random-secret'
export FIM_KEY="$(security find-generic-password -a "$USER" -s fim -w)"
```

Further hardening, in increasing order of strength: store the baseline on read-only or
removable media; copy it to another machine; run the checker from a separate host.

## Limitations
- **Polling, not real-time.** A change that's made and reverted between two checks is
  missed. Real-time tools use kernel events (macOS FSEvents / Linux inotify), which need
  third-party libraries or platform APIs.
- **It can't tell who changed a file or why.** It detects; it doesn't attribute. Use it
  next to system logs (macOS Unified Log, Linux auditd).
- **A root-level attacker can beat it**: they could stop the process, read `FIM_KEY` from
  its environment, or hook the filesystem with a rootkit. FIM raises the cost of hiding;
  it is not a guarantee.
- **The first baseline must be taken from a clean system.** If it's already compromised,
  the compromise becomes "normal".
- Directories themselves aren't tracked (empty directories, directory permissions), and
  owner/group and extended attributes aren't compared. Those would be easy extensions.
- Monitoring frequently-changing directories produces noise. Pick stable, sensitive
  targets (config, keys, binaries) and use `-e` to exclude logs and caches.

## Files
- `fim.py`: the CLI, structured as scan/hash → baseline/HMAC → compare → alert
- `test_fim.py`: offline tests (tampering, same-size-same-mtime edits, symlink
  re-pointing, forged/unsigned baselines, watch logging)

## References
- NIST SP 800-53, control SI-7 "Software, Firmware, and Information Integrity"
- Python `hmac` docs: https://docs.python.org/3/library/hmac.html
- AIDE: https://aide.github.io/
