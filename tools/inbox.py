#!/usr/bin/env python3
"""The inbox of Manuscribe's contributed lines, run by GitHub Actions (.github/workflows/inbox.yml) on every issue.

A contribution comes as an issue made with the "Contribute corrected lines" form, with a sealed package attached: a
zip that Manuscribe made (Manuscript tab › Contribute corrected lines…), holding

    contribution.json   in the clear: the package's id, the manuscript's name as the model cards are to give it and its
                        language and script (a tag as sa-Deva), the number of lines and of folio sides, the consent
                        record (yes, its date, the wording's version, the right to share the images confirmed), that
                        wording itself, and the seal
    sealed.bin          the lines and sides (a zip: each line's image, its corrected text, what the model proposed; each
                        folio side's image, the blocks its editor drew and their line counts), in
                        AES-256-GCM under a key of its own, that key wrapped by RSA-OAEP (SHA-256) to the maintainer's
                        public key: only the maintainer's private key opens it

A package is taken if it is whole (its checksum and id are what its contribution.json says), was sealed to a key that
approved.json lists, and its consent says yes, confirms the right to share the images, is not withdrawn, and was given
on a wording that approved.json lists ("sides": the wordings that give folio sides, not lines only), and it states
the manuscript's language and script, by which everything here is kept apart: the models of one language and script
learn from its contributions only. Where the private key is a secret of this repository (CONTRIBUTION_KEY), the
lines are opened and checked too, and then forgotten; without it they are opened only on the maintainer's computer
(devanagari-manuscript-ocr: python -m msocr.contributions sync). A package taken is kept as an asset of the draft release
packages-<year> (a draft: only the maintainer sees it), registered in register.tsv, and the issue answered and closed;
a package refused is answered with the reasons.

A withdrawal comes as an issue made with the "Withdraw contributed lines" form, naming packages (c20261124-…) or the
issues they came in (#12). The packages sent by the issue's own GitHub account are withdrawn at once: their assets
deleted, their rows kept as withdrawn. Others' only once the maintainer confirms (label withdrawal-confirmed).

Every change publishes a data release, data-<date>-<time>: dataset.json (what training may use from then on, and what
was withdrawn) and register.tsv. A model's card names the data release it was trained from; models trained before a
withdrawal stay as they are, as the consent text says.

    python tools/inbox.py event              the issue of $GITHUB_EVENT_PATH, then any other open one left unanswered
    python tools/inbox.py sweep              every open contribution or withdrawal issue left unanswered
    python tools/inbox.py labels             make the labels the issue forms apply (once, before the first issue)
    python tools/inbox.py release            publish a data release from register.tsv as it stands
    python tools/inbox.py check FILE...      what would be said of package files [--key private.pem]

Python's standard library only, but for opening the lines (the cryptography package). INBOX_DRY=1 runs without GitHub
(what would be done goes to INBOX_LOG or stdout), INBOX_ROOT another copy of this repository, for the tests.
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

__version__ = "0.12.0"            # Manuscribe and its companions always carry the same version number

FIELDS = ["id", "issue", "contributor", "manuscript", "script", "lines", "sides", "part", "wording", "consent_date", "received",
          "state", "store", "sha256", "bytes", "note"]
TAG = re.compile(r"^[a-z]{2,3}-[A-Z][a-z]{3}$")      # a language and script, as sa-Deva
ALG = "RSA-OAEP-256+A256GCM"
MAX = 26_000_000                       # GitHub takes attachments of up to 25 MB
ID = re.compile(r"\bc\d{8}-[0-9a-f]{12}\b")
LINK = re.compile(r"https://github\.com/(?:user-attachments/files/\d+/|[\w.-]+/[\w.-]+/files/\d+/)[^\s)\]>\"'<]+")
FILE_LINK = re.compile(r"file://[^\s)\]>\"'<]+")
CONTRIBUTION_FORM, WITHDRAWAL_FORM = "### Sealed package", "### Contributions to withdraw"
STATUS = {                              # the labels this sets, and the two the forms apply
    "contribution": ("1d76db", "Corrected lines sent from Manuscribe"),
    "withdrawal": ("b60205", "A request to withdraw contributed lines"),
    "registered": ("0e8a16", "The package was taken and registered"),
    "withdrawn": ("5319e7", "The lines named were withdrawn"),
    "needs-attention": ("fbca04", "Something is missing or wrong: see the bot's answer"),
    "needs-maintainer": ("d93f0b", "Waits for the maintainer"),
    "withdrawal-confirmed": ("000000", "The maintainer confirms a withdrawal of another account's lines"),
}
ANSWERED = {"registered", "withdrawn", "needs-attention", "needs-maintainer"}


def root():
    return Path(os.environ.get("INBOX_ROOT") or Path(__file__).resolve().parent.parent)


def dry():
    return os.environ.get("INBOX_DRY") == "1"


def repo():
    return os.environ.get("GITHUB_REPOSITORY", "drdhaval2785/manuscribe-contributions")


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def log(s):
    out = os.environ.get("INBOX_LOG")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(s + "\n")
    else:
        print(s)


# ---------- the register ----------

def read_register():
    f = root() / "register.tsv"
    if not f.exists():
        return []
    lines = f.read_text(encoding="utf-8").splitlines()
    head = lines[0].split("\t") if lines else FIELDS
    return [dict(zip(head, l.split("\t"))) for l in lines[1:] if l.strip()]


def write_register(rows):
    clean = lambda v: re.sub(r"[\t\r\n]+", " ", str("" if v is None else v))
    (root() / "register.tsv").write_text("\t".join(FIELDS) + "\n" + "".join("\t".join(clean(r.get(k)) for k in FIELDS) + "\n" for r in rows), encoding="utf-8")


def approved():
    return json.loads((root() / "approved.json").read_text(encoding="utf-8"))


# ---------- the package ----------

def package_id(about, sha):
    return "c" + str(about.get("made", ""))[:10].replace("-", "") + "-" + sha[:12]


def key_id(public_key):
    from cryptography.hazmat.primitives import serialization
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


def private_key():
    """the maintainer's private key where it is a secret here (CONTRIBUTION_KEY, PEM), else None"""
    pem = os.environ.get("CONTRIBUTION_KEY", "").strip()
    if not pem:
        return None
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(pem.encode(), password=None)


def open_sealed(seal, sealed, priv):
    """-> the sealed bytes opened (the lines' zip); raises where the key or the bytes are not right"""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if key_id(priv.public_key()) != seal.get("key"):
        raise ValueError("sealed to another key")
    k = priv.decrypt(base64.b64decode(seal["wrapped"]), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return AESGCM(k).decrypt(base64.b64decode(seal["iv"]), sealed, None)


def check_inner(about, inner):
    try:
        z = zipfile.ZipFile(io.BytesIO(inner))
        names = set(z.namelist())
        a = json.loads(z.read("contribution.json").decode("utf-8"))
    except Exception:
        return ["its sealed lines are not a package"]
    why = []
    if a.get("format") != "manuscribe-contribution" or a.get("version") not in (1, 2):
        why.append("its sealed lines are not a package (format, version 1 or 2)")
    lines, sides = a.get("lines") or [], a.get("sides") or []
    if len(lines) != about.get("count"):
        why.append(f"it says {about.get('count')} lines and holds {len(lines)}")
    if len(sides) != (about.get("sides") or 0):
        why.append(f"it says {about.get('sides') or 0} folio sides and holds {len(sides)}")
    missing = [str(l.get("image")) for l in lines if l.get("image") not in names]
    missing += [str(x) for sd in sides for x in (sd.get("image"), sd.get("geometry")) if x not in names]
    if missing:
        why.append("images missing: " + ", ".join(missing[:5]))
    odd = sorted(n for n in names if n != "contribution.json" and (".." in n or not re.fullmatch(r"lines/[^/]+\.(png|txt)|sides/[^/]+\.(jpg|json)", n)))
    if odd:
        why.append("files a package does not hold: " + ", ".join(odd[:5]))
    if (a.get("consent") or {}) != (about.get("consent") or {}):
        why.append("the consent inside is not the consent outside")
    if (a.get("manuscript") or {}).get("script") != (about.get("manuscript") or {}).get("script"):
        why.append("the language and script inside are not those outside")
    for sd in sides:
        try:
            g = json.loads(z.read(sd.get("geometry")).decode("utf-8"))
        except Exception:
            why.append(f"{sd.get('geometry')}: not readable")
            continue
        if g.get("drawn") != "here":            # a side's blocks must be drawn on it, not applied from another side
            why.append(f"{sd.get('folio')}: its blocks were not drawn on it (a calibration applied to the whole manuscript)")
    return why


def inspect(data, priv=None):
    """-> (about, reasons, inner): the package's clear part, the reasons it cannot be taken (none: it can), and the
    lines opened where the private key is given"""
    if len(data) > MAX:
        return None, [f"larger than {MAX // 10 ** 6} MB"], None
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = set(z.namelist())
    except zipfile.BadZipFile:
        return None, ["not a zip file"], None
    if names != {"contribution.json", "sealed.bin"}:
        return None, ["not a sealed package from Manuscribe (it holds contribution.json and sealed.bin, nothing else)"], None
    if sum(i.file_size for i in z.infolist()) > 2 * MAX:
        return None, ["it unpacks to more than a package can"], None
    try:
        about = json.loads(z.read("contribution.json").decode("utf-8"))
        assert isinstance(about, dict)
    except Exception:
        return None, ["its contribution.json is not readable"], None
    sealed = z.read("sealed.bin")
    if about.get("format") != "manuscribe-contribution" or about.get("version") != 2 or about.get("sealed") is not True:
        return about, ["not a sealed contribution from Manuscribe (format, version 2)"], None
    ok, why = approved(), []
    s = about.get("seal") or {}
    sha = hashlib.sha256(sealed).hexdigest()
    if s.get("alg") != ALG:
        why.append(f"sealed with {s.get('alg')!r}, not {ALG}")
    if s.get("sha256") != sha or s.get("bytes") != len(sealed):
        why.append("its sealed lines are not what its contribution.json says (checksum or size): the file was changed or cut short")
    if about.get("id") != package_id(about, sha):
        why.append("its id is not the one its date and checksum give")
    if s.get("key") not in ok.get("keys", []):
        why.append(f"sealed to key {s.get('key')!r}, which is not the maintainer's (Manuscribe fetches the key from the models' site)")
    c = about.get("consent") or {}
    if c.get("answer") != "yes":
        why.append(f"its consent says {c.get('answer')!r}, not yes")
    if c.get("rights") is not True:
        why.append("the right to share the images is not confirmed")
    if c.get("withdrawn"):
        why.append("its consent was withdrawn")
    if c.get("wording") not in ok.get("wordings", []):
        why.append(f"its consent was given on wording {c.get('wording')!r}, which is not one taken here (a newer Manuscribe asks again)")
    if (about.get("wording") or {}).get("version") != c.get("wording"):
        why.append("the wording it carries is not the one its consent names")
    n_sides = about.get("sides") or 0
    if not isinstance(about.get("count"), int) or not isinstance(n_sides, int) or about["count"] < 0 or n_sides < 0 or about["count"] + n_sides < 1:
        why.append("no lines and no folio sides")
    if n_sides and c.get("wording") not in ok.get("sides", []):
        why.append(f"folio sides given on wording {c.get('wording')!r}, which gives lines only (Manuscribe asks again)")
    if not TAG.match(str((about.get("manuscript") or {}).get("script", ""))):
        why.append("no language and script stated for the manuscript (a tag as sa-Deva; Manuscribe asks for it with the consent)")
    if not str((about.get("manuscript") or {}).get("name", "")).strip():
        why.append("no name for the manuscript")
    inner = None
    if priv is not None and not why:
        try:
            inner = open_sealed(s, sealed, priv)
        except Exception as e:
            why.append(f"its lines do not open with the maintainer's key ({e.__class__.__name__})")
        else:
            why += check_inner(about, inner)
    return about, why, inner


# ---------- GitHub ----------

def gh(*args, ok=False):
    """GitHub's command line (on the runners, signed in by GH_TOKEN) -> its output; with ok, None where it fails"""
    if dry():
        log("gh " + " ".join(args))
        if args[:2] == ("release", "view"):
            return None if ok else ""
        if args[0] == "api" and args[1].endswith("/permission"):
            return os.environ.get("INBOX_DRY_PERMISSION", "none")
        if args[:2] == ("issue", "list"):
            return os.environ.get("INBOX_DRY_ISSUES", "[]")
        return ""
    r = subprocess.run(["gh", *args], capture_output=True, text=True)
    if r.returncode:
        if ok:
            return None
        raise SystemExit(f"[inbox] gh {' '.join(args[:3])}: {r.stderr.strip()}")
    return r.stdout


def answer(n, text, add=(), remove=(), close=False):
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as f:
        f.write(text)
    gh("issue", "comment", str(n), "-R", repo(), "--body-file", f.name)
    if dry():
        log("  | " + text.replace("\n", "\n  | "))
    os.unlink(f.name)
    if add:                             # apart, so that a label to remove that is not there stops nothing
        gh("issue", "edit", str(n), "-R", repo(), *[x for l in add for x in ("--add-label", l)], ok=True)
    if remove:
        gh("issue", "edit", str(n), "-R", repo(), *[x for l in remove for x in ("--remove-label", l)], ok=True)
    if close:
        gh("issue", "close", str(n), "-R", repo(), "--reason", "completed", ok=True)


def labels():
    for name, (colour, about) in STATUS.items():
        gh("label", "create", name, "-R", repo(), "--color", colour, "--description", about, "--force", ok=True)


def can_withdraw_any(login):
    if login and login.lower() == repo().split("/")[0].lower():
        return True
    p = gh("api", f"repos/{repo()}/collaborators/{login}/permission", "--jq", ".permission", ok=True)
    return (p or "").strip() in ("admin", "maintain", "write")


def commit(message):
    if dry():
        log("git commit: " + message)
        return
    run = lambda *a: subprocess.run(["git", *a], cwd=root(), check=True)
    run("add", "register.tsv")
    if subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=root()).returncode == 0:
        return
    run("commit", "-q", "-m", message)
    run("push", "-q")


class _KeepToken(urllib.request.HTTPRedirectHandler):
    """the token goes to github.com only, never to the host an attachment's address leads to"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlparse(newurl).hostname != "github.com":
            new.remove_header("Authorization")
        return new


def download(url):
    if url.startswith("file://"):
        if os.environ.get("INBOX_ALLOW_FILE") != "1":
            raise ValueError("not an attachment")
        return Path(urllib.parse.unquote(urllib.parse.urlparse(url).path)).read_bytes()
    head = {"User-Agent": f"manuscribe-contributions-inbox/{__version__}"}
    tries = [(urllib.request.build_opener(), head)]
    if os.environ.get("GH_TOKEN"):
        tries.append((urllib.request.build_opener(_KeepToken), dict(head, Authorization="Bearer " + os.environ["GH_TOKEN"])))
    err = None
    for opener, h in tries:
        try:
            with opener.open(urllib.request.Request(url, headers=h), timeout=120) as r:
                data = r.read(MAX + 1)
            if len(data) > MAX:
                raise ValueError(f"larger than {MAX // 10 ** 6} MB")
            return data
        except urllib.error.HTTPError as e:
            err = e
    raise err


def attachments(body):
    links = LINK.findall(body or "")
    if os.environ.get("INBOX_ALLOW_FILE") == "1":
        links += FILE_LINK.findall(body or "")
    return list(dict.fromkeys(l.rstrip(".,;") for l in links))


def form_of(issue):
    names = {l["name"] for l in issue.get("labels") or []}
    body = issue.get("body") or ""
    if "withdrawal" in names or WITHDRAWAL_FORM in body:
        return "withdrawal"
    if "contribution" in names or CONTRIBUTION_FORM in body:
        return "contribution"
    return None


# ---------- a contribution ----------

def contribution(issue, opened=True):
    n, who = issue["number"], issue["user"]["login"]
    links = attachments(issue.get("body"))
    if not links:
        answer(n, "No package is attached yet. Edit this issue (… › Edit) and drag the file Manuscribe saved, "
                  "`manuscribe-contribution-c….zip`, into the **Sealed package** box: it is looked at again as soon as you save.",
               add=["needs-attention"])
        return False
    priv = private_key()
    rows = read_register()
    known = {r["id"]: r for r in rows}
    taken, refused, again = [], [], []
    for url in links:
        name = urllib.parse.unquote(url.rsplit("/", 1)[-1])
        try:
            data = download(url)
        except Exception as e:
            refused.append((name, [f"it could not be fetched ({e})"]))
            continue
        about, why, inner = inspect(data, priv)
        pid = (about or {}).get("id")
        if pid in known:
            r = known[pid]
            if r["state"] == "withdrawn":
                refused.append((name, [f"{pid} was withdrawn ({r['note']}); lines withdrawn are taken again only with the consent given again, as a new package"]))
            else:
                again.append(r)
            continue
        if why:
            refused.append((name, why))
            continue
        store = f"packages-{now().year}"
        if gh("release", "view", store, "-R", repo(), "--json", "tagName", ok=True) is None:
            gh("release", "create", store, "-R", repo(), "--draft", "--latest=false", "--title", f"Sealed packages, {now().year}",
               "--notes", "The sealed packages of contributed lines registered in register.tsv, as they came. A draft: never to be published. "
                          "A package withdrawn is deleted from here.")
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / f"{pid}.zip"
            f.write_bytes(data)
            gh("release", "upload", store, str(f), "-R", repo(), "--clobber")
        c, part = about["consent"], about.get("part") or [1, 1]
        row = {"id": pid, "issue": n, "contributor": who, "manuscript": about["manuscript"]["name"].strip(), "script": about["manuscript"]["script"],
               "lines": about["count"], "sides": about.get("sides") or 0,
               "part": f"{part[0]}/{part[1]}", "wording": c["wording"], "consent_date": str(c.get("date", ""))[:10],
               "received": now().isoformat(timespec="seconds"), "state": "registered", "store": store,
               "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
               "note": "lines opened and checked here" if inner is not None else "lines not opened here (the maintainer's key opens them)"}
        rows.append(row)
        known[pid] = row
        taken.append(row)
    if taken:
        write_register(rows)
        commit(f"Registered {', '.join(r['id'] for r in taken)} ({sum(int(r['lines']) for r in taken)} lines, {sum(int(r['sides'] or 0) for r in taken)} folio sides "
               f"of {taken[0]['manuscript']}, {taken[0]['script']}), issue #{n}")
    if not taken and not refused and (not opened or all(str(r["issue"]) == str(n) for r in again)):
        return True                     # an edit that brings nothing new, or an issue a sweep answered already
    say = []
    if taken:
        tag = release(f"+ {', '.join(r['id'] for r in taken)} (#{n})")
        say.append("Thank you. Registered:\n\n" + "\n".join(f"- `{r['id']}`: {r['lines']} lines" + (f" and {r['sides']} folio sides" if int(r["sides"] or 0) else "")
                                                         + f" of “{r['manuscript']}” ({r['script']}), consent of {r['consent_date']} (wording {r['wording']})" for r in taken)
                   + f"\n\nThey are kept sealed, and will be used to train the recognition models for {taken[0]['script']} only, from the next training on (data release `{tag}`). "
                     "To withdraw them later: Manuscribe's “Withdraw…” in the Manuscript tab, or a “Withdraw contributed lines” issue naming these ids.")
    if again:
        say.append("Already registered: " + ", ".join(f"`{r['id']}` (issue #{r['issue']})" for r in again) + ".")
    if refused:
        say.append("Not taken:\n\n" + "\n".join(f"- {name}: " + "; ".join(why) for name, why in refused)
                   + "\n\nEdit this issue to attach the file again, or make it again in Manuscribe; the maintainer can be asked here too.")
    done = not refused
    answer(n, "\n\n".join(say), add=["registered"] if (taken or again) and done else ["needs-attention"] if refused else [],
           remove=["needs-attention"] if done else [], close=done)
    return done


# ---------- a withdrawal ----------

def withdrawal(issue, confirmed=False):
    n, who = issue["number"], issue["user"]["login"]
    body = issue.get("body") or ""
    rows = read_register()
    by_id = {r["id"]: r for r in rows}
    ids = list(dict.fromkeys(ID.findall(body)))
    nums = set(re.findall(r"(?<![\w/&])#(\d+)\b", body))
    named = [by_id[i] for i in ids if i in by_id] + [r for r in rows if r["issue"] in nums and r["id"] not in ids]
    unknown = [i for i in ids if i not in by_id]
    if not named:
        answer(n, "No contribution registered here is named. Give the package ids Manuscribe shows (`c20261124-…`), or the number of the issue "
                  "the lines came in (`#12`), and save: this is looked at again." + (f"\n\nNot received here: {', '.join(unknown)}." if unknown else ""),
               add=["needs-attention"])
        return False
    anyone = confirmed or can_withdraw_any(who)
    mine = [r for r in named if anyone or r["contributor"].lower() == who.lower()]
    waiting = [r for r in named if r not in mine and r["state"] != "withdrawn"]
    gone, before = [], []
    day = now().date().isoformat()
    for r in mine:
        if r["state"] == "withdrawn":
            before.append(r)
            continue
        gh("release", "delete-asset", r["store"], f"{r['id']}.zip", "-R", repo(), "-y", ok=True)
        r["state"] = "withdrawn"
        r["note"] = f"withdrawn {day}, issue #{n}"
        gone.append(r)
    if not gone and not unknown and not waiting and all(f"issue #{n}" in r["note"] for r in before):
        return True                     # answered already (by a sweep)
    say = []
    if gone:
        write_register(rows)
        commit(f"Withdrawn {', '.join(r['id'] for r in gone)} ({sum(int(r['lines']) for r in gone)} lines, {sum(int(r.get('sides') or 0) for r in gone)} folio sides), issue #{n}")
        tag = release(f"− {', '.join(r['id'] for r in gone)} (#{n})")
        say.append("Withdrawn:\n\n" + "\n".join(f"- `{r['id']}`: {r['lines']} lines" + (f" and {r['sides']} folio sides" if int(r.get("sides") or 0) else "")
                                                 + f" of “{r['manuscript']}” (issue #{r['issue']})" for r in gone)
                   + f"\n\nTheir sealed packages are deleted here, and they are left out of every model trained from now on (data release `{tag}` no longer lists them). "
                     "Models already trained on them while the consent stood remain, and are not withdrawn.")
    if before:
        say.append("Already withdrawn: " + ", ".join(f"`{r['id']}` ({r['note']})" for r in before) + ".")
    if unknown:
        say.append("Not received here, so nothing to delete: " + ", ".join(f"`{i}`" for i in unknown) + ".")
    if waiting:
        say.append("Sent by another GitHub account, and so withdrawn only once the maintainer confirms: "
                   + ", ".join(f"`{r['id']}` (issue #{r['issue']})" for r in waiting) + ".")
    answer(n, "\n\n".join(say), add=["needs-maintainer"] if waiting else ["withdrawn"], remove=[] if waiting else ["needs-attention", "needs-maintainer"], close=not waiting)
    return not waiting


# ---------- the data release ----------

def release(change=""):
    """publish data-<date>-<time>: what training may use from now on -> the tag"""
    rows = read_register()
    t = now()
    tag = f"data-{t:%Y%m%d-%H%M%S}"
    for k in range(2, 20):              # two in the same second (an issue, then another the sweep found)
        if gh("release", "view", tag, "-R", repo(), "--json", "tagName", ok=True) is None:
            break
        tag = f"data-{t:%Y%m%d-%H%M%S}-{k}"
    reg = [r for r in rows if r["state"] == "registered"]
    gone = [r for r in rows if r["state"] == "withdrawn"]
    keys = ("id", "manuscript", "script", "lines", "sides", "part", "wording", "consent_date", "issue", "contributor", "store", "sha256", "bytes")
    dataset = {"release": tag, "made": t.isoformat(timespec="seconds"), "inbox": repo(), "approved": approved(),
               "contributions": [{k: r.get(k, "") for k in keys} for r in reg],
               "withdrawn": [{"id": r["id"], "manuscript": r["manuscript"], "lines": r["lines"], "note": r["note"]} for r in gone]}
    by_script = {}
    for r in reg:
        b = by_script.setdefault(r.get("script") or "no script stated", {"packages": 0, "lines": 0, "sides": 0, "mss": set()})
        b["packages"] += 1
        b["lines"] += int(r["lines"] or 0)
        b["sides"] += int(r.get("sides") or 0)
        b["mss"].add(r["manuscript"])
    notes = (f"What training may use from {t:%d %B %Y, %H:%M} UTC, by language and script (each trains its own models only):"
             + ("".join(f"\n- {k}: {b['packages']} package(s), {b['lines']} lines, {b['sides']} folio sides, of {len(b['mss'])} manuscript(s): "
                        + "; ".join(sorted(b["mss"])) for k, b in sorted(by_script.items())) if by_script else " nothing yet.")
             + (f"\n\nThis release: {change}." if change else "")
             + (f"\n\nWithdrawn, and left out from their withdrawal on: {len(gone)} package(s)." if gone else "")
             + "\n\n`dataset.json` lists the packages (sealed; the maintainer's key opens them) and `register.tsv` is the register as it stood. "
               "A model's card names the data release it was trained from.")
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "dataset.json").write_text(json.dumps(dataset, ensure_ascii=False, indent=1), encoding="utf-8")
        (Path(d) / "register.tsv").write_text((root() / "register.tsv").read_text(encoding="utf-8") if (root() / "register.tsv").exists() else "\t".join(FIELDS) + "\n", encoding="utf-8")
        (Path(d) / "notes.md").write_text(notes, encoding="utf-8")
        gh("release", "create", tag, str(Path(d) / "dataset.json"), str(Path(d) / "register.tsv"), "-R", repo(),
           "--title", f"Training data, {t:%d %B %Y, %H:%M} UTC", "--notes-file", str(Path(d) / "notes.md"), "--latest")
    return tag


# ---------- the runs ----------

def handle(issue, action="opened", label=None, sender=None):
    if issue.get("pull_request") or issue.get("state") == "closed" and action != "reopened":
        return None
    form = form_of(issue)
    if form == "contribution" and action != "labeled":
        return contribution(issue, opened=action in ("opened", "reopened"))
    if form == "withdrawal":
        if action == "labeled":
            if label != "withdrawal-confirmed" or not can_withdraw_any(sender or ""):
                return None
            return withdrawal(issue, confirmed=True)
        return withdrawal(issue)
    return None


def sweep(skip=None):
    """the open issues of either form that nothing has answered (a run the queue dropped, say)"""
    out = gh("issue", "list", "-R", repo(), "--state", "open", "--limit", "100", "--json", "number,title,body,labels,author,state", ok=True) or "[]"
    for it in json.loads(out):
        names = {l["name"] for l in it.get("labels") or []}
        if it["number"] == skip or names & ANSWERED:
            continue
        issue = dict(it, user={"login": (it.get("author") or {}).get("login", "")})
        if form_of(issue):
            print(f"[inbox] #{it['number']}: not answered yet")
            handle(issue)


def check_files(paths, key=None):
    priv = None
    if key:
        from cryptography.hazmat.primitives import serialization
        priv = serialization.load_pem_private_key(Path(key).read_bytes(), password=None)
    bad = 0
    for p in paths:
        about, why, inner = inspect(Path(p).read_bytes(), priv)
        what = f"{(about or {}).get('id')}: {(about or {}).get('count')} lines of {((about or {}).get('manuscript') or {}).get('name')!r}"
        print(f"{p}: " + ("taken, " + what + (", lines opened and checked" if inner is not None else "") if not why else "not taken: " + "; ".join(why)))
        bad += bool(why)
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("event")
    sub.add_parser("sweep")
    sub.add_parser("labels")
    sub.add_parser("release")
    c = sub.add_parser("check")
    c.add_argument("files", nargs="+")
    c.add_argument("--key")
    a = ap.parse_args()
    if a.cmd == "check":
        return check_files(a.files, a.key)
    if a.cmd == "labels":
        labels()
    elif a.cmd == "release":
        print(f"[inbox] published {release('published by hand')}")
    elif a.cmd == "sweep":
        sweep()
    else:
        ev = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        issue = ev.get("issue") or {}
        handle(issue, ev.get("action", "opened"), (ev.get("label") or {}).get("name"), (ev.get("sender") or {}).get("login"))
        sweep(skip=issue.get("number"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
