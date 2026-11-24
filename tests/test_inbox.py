"""The inbox, without GitHub: packages sealed here as Manuscribe seals them, issues given as event files, attachments as
file:// addresses, and what would be done to GitHub read from the log (INBOX_DRY=1).

    python -m pip install cryptography
    python -m unittest discover -s tests -v
"""
import base64
import datetime
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = Path(__file__).resolve().parent.parent
INBOX = HERE / "tools" / "inbox.py"
sys.path.insert(0, str(HERE / "tools"))
import inbox  # noqa: E402

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
PNG = bytes.fromhex("89504e470d0a1a0a") + b"\0" * 64
WORDING = {"version": "1", "date": "2026-11-24", "approved": True, "title": "t", "paragraphs": ["p"], "question": "q", "rights": "r"}


def package(count=2, answer="yes", rights=True, wording="1", key=KEY, tamper=None, made=None, inner_count=None, extra=None, sides=0, script="sa-Deva",
            drawn="here"):
    """-> the bytes of a sealed package, as Manuscribe makes it"""
    made = made or datetime.datetime.now(datetime.timezone.utc).isoformat()
    consent = {"answer": answer, "rights": rights, "name": "Test library, MS 1", "date": "2026-11-24T10:00:00Z", "wording": wording}
    lines = [{"image": f"lines/1r_main_{i + 1:02d}.png", "text": f"line {i}", "proposed": f"lime {i}", "folio": "1r", "block": "main", "line": i + 1}
             for i in range(inner_count if inner_count is not None else count)]
    side_list = [{"image": f"sides/{k + 1}r.jpg", "geometry": f"sides/{k + 1}r.json", "folio": f"{k + 1}r", "layout": "linear", "lines": {"main": 8}}
                 for k in range(sides)]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("contribution.json", json.dumps({"format": "manuscribe-contribution", "version": 2, "made": made, "part": [1, 1],
                                                    "manuscript": {"name": consent["name"], "script": script}, "consent": consent,
                                                    "wording": dict(WORDING, version=wording), "lines": lines, "sides": side_list}))
        for l in lines:
            z.writestr(l["image"], PNG)
            z.writestr(l["image"].replace(".png", ".txt"), l["text"] + "\n")
        for sd in side_list:
            z.writestr(sd["image"], b"\xff\xd8\xff" + b"\0" * 64)
            z.writestr(sd["geometry"], json.dumps({"folio": sd["folio"], "drawn": drawn, "boxes": {"main": {"rect": [10, 10, 400, 200], "lines": 8}}}))
        for n, b in (extra or {}).items():
            z.writestr(n, b)
    k, iv = AESGCM.generate_key(bit_length=256), os.urandom(12)
    sealed = AESGCM(k).encrypt(iv, buf.getvalue(), None)
    wrapped = key.public_key().encrypt(k, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    sha = hashlib.sha256(sealed).hexdigest()
    pid = "c" + made[:10].replace("-", "") + "-" + sha[:12]
    about = {"format": "manuscribe-contribution", "version": 2, "sealed": True, "id": pid, "made": made, "manuscribe": "0.11.0",
             "inbox": "owner/inbox", "manuscript": {"name": consent["name"], "script": script}, "count": count, "sides": sides, "part": [1, 1], "consent": consent,
             "wording": dict(WORDING, version=wording),
             "seal": {"alg": inbox.ALG, "key": inbox.key_id(key.public_key()), "wrapped": base64.b64encode(wrapped).decode(),
                      "iv": base64.b64encode(iv).decode(), "file": "sealed.bin", "bytes": len(sealed), "sha256": sha}}
    if tamper:
        sealed = sealed[:-1] + bytes([sealed[-1] ^ 1])
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("contribution.json", json.dumps(about))
        z.writestr("sealed.bin", sealed)
    return out.getvalue(), pid


def rezip(data, change):
    """the package with its contribution.json changed"""
    z = zipfile.ZipFile(io.BytesIO(data))
    about = json.loads(z.read("contribution.json"))
    change(about)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as w:
        w.writestr("contribution.json", json.dumps(about))
        w.writestr("sealed.bin", z.read("sealed.bin"))
    return out.getvalue()


class Inbox(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.root = self.dir / "repo"
        self.root.mkdir()
        (self.root / "register.tsv").write_text("\t".join(inbox.FIELDS) + "\n")      # an empty register, not this repository's
        (self.root / "approved.json").write_text(json.dumps({"wordings": ["1", "2"], "sides": ["2"], "keys": [inbox.key_id(KEY.public_key())]}))
        os.environ["INBOX_ROOT"] = str(self.root)

    def tearDown(self):
        shutil.rmtree(self.dir)
        os.environ.pop("INBOX_ROOT", None)

    def save(self, data, name="pkg.zip"):
        f = self.dir / name
        f.write_bytes(data)
        return f

    def event(self, number, body, user="alice", action="opened", labels=("contribution",), key=False, label=None, sender=None, permission="none"):
        ev = {"action": action, "issue": {"number": number, "body": body, "user": {"login": user}, "state": "open",
                                          "labels": [{"name": l} for l in labels]}, "sender": {"login": sender or user}}
        if label:
            ev["label"] = {"name": label}
        f = self.dir / f"event{number}.json"
        f.write_text(json.dumps(ev))
        log = self.dir / "log.txt"
        log.write_text("")
        env = dict(os.environ, INBOX_DRY="1", INBOX_ALLOW_FILE="1", INBOX_LOG=str(log), GITHUB_EVENT_PATH=str(f),
                   GITHUB_REPOSITORY="owner/inbox", INBOX_DRY_PERMISSION=permission, CONTRIBUTION_KEY=PEM if key else "")
        r = subprocess.run([sys.executable, "-I", str(INBOX), "event"], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return log.read_text()

    def rows(self):
        return inbox.read_register()

    # ---- what is said of a package
    def test_check(self):
        good, pid = package()
        about, why, inner = inbox.inspect(good)
        self.assertEqual((about["id"], why, inner), (pid, [], None))
        about, why, inner = inbox.inspect(good, KEY)
        self.assertEqual(why, [])
        self.assertIn("contribution.json", zipfile.ZipFile(io.BytesIO(inner)).namelist())
        cases = {
            "checksum": package(tamper=True)[0],
            "not yes": package(answer="no")[0],
            "right to share": package(rights=False)[0],
            "wording 'draft-1'": package(wording="draft-1")[0],
            "not the maintainer's": package(key=OTHER)[0],
            "its id is not": rezip(package()[0], lambda a: a.update(id="c20200101-" + a["id"][-12:])),
            "not a zip": b"hello",
        }
        for what, data in cases.items():
            with self.subTest(what):
                self.assertTrue(any(what in w for w in inbox.inspect(data)[1]), inbox.inspect(data)[1])
        self.assertTrue(any("says 3 lines and holds 2" in w for w in inbox.inspect(package(count=3, inner_count=2)[0], KEY)[1]))
        # folio sides: only on a wording that gives them, checked inside the seal; a language and script always
        self.assertEqual(inbox.inspect(package(wording="2", sides=2)[0], KEY)[1], [])
        self.assertTrue(any("gives lines only" in w for w in inbox.inspect(package(wording="1", sides=1)[0])[1]))
        self.assertTrue(any("no language and script" in w for w in inbox.inspect(package(script="")[0])[1]))
        self.assertTrue(any("no lines and no folio sides" in w for w in inbox.inspect(package(count=0, inner_count=0)[0])[1]))
        self.assertTrue(any("not drawn on it" in w for w in inbox.inspect(package(wording="2", sides=1, drawn="shared")[0], KEY)[1]))
        self.assertTrue(any("says 2 folio sides and holds 1" in w for w in inbox.inspect(rezip(package(wording="2", sides=1)[0], lambda a: a.update(sides=2)), KEY)[1]))
        self.assertTrue(any("files a package does not hold" in w for w in inbox.inspect(package(extra={"run.sh": b"x"})[0], KEY)[1]))

    # ---- a contribution, again, and a withdrawal
    def test_contribution_and_withdrawal(self):
        data, pid = package()
        f = self.save(data, "manuscribe-contribution.zip")
        body = f"### Manuscript\n\nTest library, MS 1\n\n### Sealed package\n\n[manuscribe-contribution.zip]({f.as_uri()})\n"
        log = self.event(5, body, key=True)
        rows = self.rows()
        self.assertEqual([(r["id"], r["issue"], r["contributor"], r["script"], r["lines"], r["sides"], r["state"]) for r in rows], [(pid, "5", "alice", "sa-Deva", "2", "0", "registered")])
        self.assertIn("lines opened and checked", rows[0]["note"])
        year = datetime.date.today().year
        for want in (f"gh release create packages-{year} -R owner/inbox --draft", f"gh release upload packages-{year}", "git commit: Registered " + pid,
                     "gh release create data-", "gh issue comment 5", "--add-label registered", "gh issue close 5"):
            self.assertIn(want, log)
        # the same issue edited: nothing new, nothing said
        log = self.event(5, body, action="edited")
        self.assertNotIn("issue comment", log)
        # the same issue's own run, after a sweep answered it: nothing said again
        log = self.event(5, body)
        self.assertNotIn("issue comment", log)
        # the same file in a new issue
        log = self.event(6, body, user="bob")
        self.assertIn("gh issue close 6", log)
        self.assertEqual(len(self.rows()), 1)
        # withdrawn by another account: waits for the maintainer
        wbody = f"### Contributions to withdraw\n\n{pid}\n"
        log = self.event(7, wbody, user="mallory", labels=("withdrawal",))
        self.assertIn("--add-label needs-maintainer", log)
        self.assertEqual(self.rows()[0]["state"], "registered")
        # ... confirmed by the maintainer's label
        log = self.event(7, wbody, user="mallory", labels=("withdrawal", "needs-maintainer"), action="labeled", label="withdrawal-confirmed", sender="owner")
        self.assertEqual(self.rows()[0]["state"], "withdrawn")
        self.assertIn(f"gh release delete-asset packages-{year} {pid}.zip", log)
        self.assertIn("gh release create data-", log)
        # sent again once withdrawn: refused
        log = self.event(8, body)
        self.assertIn("--add-label needs-attention", log)
        self.assertEqual(len(self.rows()), 1)

    def test_withdrawn_by_the_sender_by_issue_number(self):
        data, pid = package()
        f = self.save(data)
        self.event(3, f"### Sealed package\n\n{f.as_uri()}\n", labels=())          # found by the form's heading
        log = self.event(4, "### Contributions to withdraw\n\n#3\n", labels=("withdrawal",))
        self.assertEqual(self.rows()[0]["state"], "withdrawn")
        self.assertIn("issue #4", self.rows()[0]["note"])
        self.assertIn("--add-label withdrawn", log)
        log = self.event(4, "### Contributions to withdraw\n\n#3\n", labels=("withdrawal",))
        self.assertNotIn("issue comment", log)

    def test_nothing_attached_and_unknown_ids(self):
        log = self.event(9, "### Sealed package\n\n_No response_\n")
        self.assertIn("--add-label needs-attention", log)
        log = self.event(10, "### Contributions to withdraw\n\nc20261124-000000000000\n", labels=("withdrawal",))
        self.assertIn("--add-label needs-attention", log)
        self.assertEqual(self.rows(), [])

    def test_refused_package_is_answered_and_not_kept(self):
        f = self.save(package(wording="draft-1")[0])
        log = self.event(11, f"### Sealed package\n\n{f.as_uri()}\n")
        self.assertIn("--add-label needs-attention", log)
        self.assertNotIn("release upload", log)
        self.assertEqual(self.rows(), [])


if __name__ == "__main__":
    unittest.main()
