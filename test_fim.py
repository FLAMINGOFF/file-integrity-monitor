"""离线单元测试：在临时目录里造文件、改文件，验证检测逻辑。运行: python3 -m unittest -v"""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import fim


class FimTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "watched")
        os.makedirs(os.path.join(self.root, "sub"))
        self.write("a.txt", "hello")
        self.write("sub/b.conf", "port=22")
        self.baseline = os.path.join(self.tmp.name, "base.json")

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, rel):
        return os.path.join(self.root, rel)

    def write(self, rel, text):
        with open(self.path(rel), "w") as f:
            f.write(text)

    def run_cli(self, *argv, key=None):
        env = {fim.KEY_ENV: key} if key else {}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            if key is None:
                os.environ.pop(fim.KEY_ENV, None)
            code = fim.main(list(argv))
        return code, out.getvalue() + err.getvalue()

    def init(self, *extra, key=None):
        code, _ = self.run_cli("init", self.root, "-b", self.baseline, *extra, key=key)
        self.assertEqual(code, fim.EXIT_OK)

    def check_json(self, key=None):
        code, out = self.run_cli("check", "-b", self.baseline, "--json", key=key)
        return code, json.loads(out)


class TestHashing(FimTestCase):
    def test_sha256_known_value(self):
        # "hello" 的 SHA-256 是公开的已知值
        self.assertEqual(fim.sha256_file(self.path("a.txt")),
                         "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")


class TestDetection(FimTestCase):
    def test_clean(self):
        self.init()
        code, diff = self.check_json()
        self.assertEqual(code, fim.EXIT_OK)
        self.assertFalse(fim.has_changes(diff))

    def test_added_modified_deleted(self):
        self.init()
        self.write("a.txt", "hacked")            # 修改
        os.remove(self.path("sub/b.conf"))       # 删除
        self.write("sub/backdoor.sh", "nc -l")   # 新增
        code, diff = self.check_json()
        self.assertEqual(code, fim.EXIT_CHANGED)
        self.assertEqual(diff["modified"], [self.path("a.txt")])
        self.assertEqual(diff["deleted"], [self.path("sub/b.conf")])
        self.assertEqual(diff["added"], [self.path("sub/backdoor.sh")])

    def test_same_size_same_mtime_still_detected(self):
        """只看大小/时间戳会被骗；哈希不会。"""
        self.init()
        st = os.stat(self.path("a.txt"))
        self.write("a.txt", "HELLO")                         # 同样 5 字节
        os.utime(self.path("a.txt"), (st.st_atime, st.st_mtime))  # 时间戳改回去
        _, diff = self.check_json()
        self.assertEqual(diff["modified"], [self.path("a.txt")])

    @unittest.skipIf(os.name == "nt", "POSIX 权限")
    def test_permission_change(self):
        self.init()
        os.chmod(self.path("a.txt"), 0o777)
        _, diff = self.check_json()
        self.assertEqual(diff["permissions"], [self.path("a.txt")])
        self.assertEqual(diff["modified"], [])

    @unittest.skipIf(os.name == "nt", "符号链接")
    def test_symlink_retarget(self):
        os.symlink("a.txt", self.path("link"))
        self.init()
        os.remove(self.path("link"))
        os.symlink("/etc/passwd", self.path("link"))
        _, diff = self.check_json()
        self.assertEqual(diff["modified"], [self.path("link")])

    def test_exclude(self):
        self.init("-e", "*.log")
        self.write("noise.log", "x")
        _, diff = self.check_json()
        self.assertFalse(fim.has_changes(diff))

    def test_baseline_inside_watched_dir_is_ignored(self):
        self.baseline = self.path("base.json")
        self.init()
        _, diff = self.check_json()
        self.assertFalse(fim.has_changes(diff))


class TestBaselineProtection(FimTestCase):
    def test_tampered_baseline_rejected(self):
        """攻击者改了文件，又把基线里的哈希改成新值，HMAC 应该拦下来。"""
        self.init(key="s3cret")
        self.write("a.txt", "hacked")
        with open(self.baseline) as f:
            doc = json.load(f)
        doc["baseline"]["files"][self.path("a.txt")]["sha256"] = fim.sha256_file(self.path("a.txt"))
        with open(self.baseline, "w") as f:
            json.dump(doc, f)
        code, out = self.run_cli("check", "-b", self.baseline, key="s3cret")
        self.assertEqual(code, fim.EXIT_TAMPERED)
        self.assertIn("签名不匹配", out)

    def test_unsigned_baseline_rejected_when_key_set(self):
        self.init()  # 没有密钥 → 未签名
        code, _ = self.run_cli("check", "-b", self.baseline, key="s3cret")
        self.assertEqual(code, fim.EXIT_TAMPERED)

    def test_wrong_key_rejected(self):
        self.init(key="right")
        code, _ = self.run_cli("check", "-b", self.baseline, key="wrong")
        self.assertEqual(code, fim.EXIT_TAMPERED)

    def test_signed_clean(self):
        self.init(key="s3cret")
        code, _ = self.check_json(key="s3cret")
        self.assertEqual(code, fim.EXIT_OK)

    def test_require_key(self):
        with self.assertRaises(SystemExit):
            self.run_cli("init", self.root, "-b", self.baseline, "--require-key")


class TestWatch(FimTestCase):
    def test_watch_once_alerts_and_logs(self):
        self.init()
        self.write("a.txt", "hacked")
        log = os.path.join(self.tmp.name, "alerts.log")
        code, out = self.run_cli("watch", "-b", self.baseline, "--once", "--log", log)
        self.assertEqual(code, fim.EXIT_CHANGED)
        self.assertIn("修改", out)
        with open(log) as f:
            self.assertIn(self.path("a.txt"), f.read())


if __name__ == "__main__":
    unittest.main()
