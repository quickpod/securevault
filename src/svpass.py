#!/usr/bin/env python3
r"""
svpass - the password manager that replaces Chrome's, stored inside the
         existing SecureVault container.

WHY ONE BLOB INSTEAD OF ONE VAULT ENTRY PER PASSWORD
Vault.remove() calls _compact(), which rewrites the whole container. This
vault is ~10.8 GB, so deleting a single credential that way would rewrite
10.8 GB. Instead the entire password database is ONE entry ("__passwords__")
written with Vault.write_bytes(), which appends a few KB and repoints the
index. Editing 500 credentials costs kilobytes, not gigabytes. The dead space
that accumulates is reclaimed the next time anything calls remove().

WHAT IT INHERITS FOR FREE (no new crypto is invented here)
  - master password + 6-digit PIN + TOTP, all three enforced by Vault.unlock()
  - scrypt(2^15) -> KEK, random DEK wrapped by the KEK, AES-256-GCM everywhere
  - the vault INDEX is itself encrypted, so even the name "__passwords__"
    is not visible in the container
  - SHA-256 integrity per blob, checked on every read
  - securevault._disable_network() has already neutered sockets at import time

WHAT IT DELIBERATELY DOES NOT USE
  DPAPI, the registry, the OS keychain, or any certificate store. That is the
  whole point: Chrome's store is unlocked by the Windows account, and this
  machine's account has a blank password. This store is unlocked only by
  secrets you type.

THE PHISHING TRADEOFF, STATED PLAINLY
Chrome only autofills when the page origin matches the saved origin. Copy and
paste has no such check - you are the one deciding the site is genuine. To put
that decision in front of you at the moment it matters, copy_password()
requires the caller to pass the domain it believes it is copying for, and
raises DomainMismatch if it does not match what is stored.
"""

import os, sys, json, time, uuid, math, string, secrets, threading, ctypes
from urllib.parse import urlsplit          # pure string parsing, opens nothing

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import securevault as sv
import svtotp

STORE_NAME = "__passwords__"
STORE_VERSION = 1
CLIP_CLEAR_SECONDS = 90
HISTORY_LIMIT = 10


class PassError(Exception): pass
class DomainMismatch(PassError): pass


# --------------------------------------------------------------- domain utils
# A real public-suffix list is ~10k entries and needs updating over the wire,
# which this program is not allowed to do. This covers the multi-label suffixes
# people actually hit; anything else falls back to the last two labels. It is a
# display and confirmation aid, never a security boundary on its own.
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "firm.in",
    "co.za", "org.za", "net.za", "gov.za", "ac.za",
    "com.br", "net.br", "org.br", "gov.br",
    "com.sg", "com.my", "com.hk", "com.tw", "com.cn", "com.mx", "com.ar",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "go.kr",
}


def host_of(url: str) -> str:
    """Hostname from a URL, tolerant of bare hosts like 'github.com'."""
    if not url:
        return ""
    u = url.strip()
    if "//" not in u:
        u = "https://" + u
    host = (urlsplit(u).hostname or "").lower()
    return host


def domain_of(url: str) -> str:
    """Registrable domain: 'https://login.example.co.uk/x' -> 'example.co.uk'.
    Used for matching and for the confirmation prompt, not for authentication."""
    host = host_of(url)
    if not host or host.replace(".", "").isdigit():   # bare IP: use as-is
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _MULTI_SUFFIX and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def same_site(a: str, b: str) -> bool:
    da, db = domain_of(a), domain_of(b)
    return bool(da) and da == db


# ------------------------------------------------------------------ generator
AMBIGUOUS = "Il1O0S5B8Z2|`'\"{}[]()/\\~,;:.<>"

def generate(length=24, upper=True, lower=True, digits=True, symbols=True,
             avoid_ambiguous=True) -> str:
    """CSPRNG password via `secrets`. Rejects and retries until every requested
    class is actually present - picking from a merged alphabet alone can, and
    at short lengths regularly does, emit a password with no digit in it."""
    pools = []
    if upper:   pools.append(string.ascii_uppercase)
    if lower:   pools.append(string.ascii_lowercase)
    if digits:  pools.append(string.digits)
    if symbols: pools.append("!@#$%^&*_-+=?")
    if not pools:
        raise PassError("no character classes selected")
    if avoid_ambiguous:
        pools = [("".join(c for c in p if c not in AMBIGUOUS)) or p for p in pools]
    if length < len(pools):
        raise PassError(f"length must be at least {len(pools)}")
    alphabet = "".join(pools)
    for _ in range(1000):
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in p for c in pw) for p in pools):
            return pw
    raise PassError("generator failed to satisfy the character classes")


def entropy_bits(pw: str) -> float:
    """Rough search-space entropy. Honest limitation: this measures the
    alphabet, not whether the password is 'Summer2026!' - it cannot see
    dictionary words or keyboard walks. Treat it as a floor, not a score."""
    if not pw:
        return 0.0
    pool = 0
    if any(c.islower() for c in pw): pool += 26
    if any(c.isupper() for c in pw): pool += 26
    if any(c.isdigit() for c in pw): pool += 10
    if any(not c.isalnum() for c in pw): pool += 32
    return round(len(pw) * math.log2(pool or 1), 1)


def strength_label(pw: str) -> str:
    b = entropy_bits(pw)
    if b < 40:  return "weak"
    if b < 60:  return "fair"
    if b < 80:  return "good"
    return "strong"


# ------------------------------------------------------------------ clipboard
# Win32 directly rather than tkinter: the CLI has no Tk root, and a tkinter
# clipboard dies with the interpreter, which would defeat the auto-clear.
_CF_UNICODETEXT = 13
_GMEM_MOVEABLE = 0x0002

def _clip_set(text: str) -> bool:
    if os.name != "nt":
        return False
    u32, k32 = ctypes.windll.user32, ctypes.windll.kernel32
    k32.GlobalAlloc.restype = ctypes.c_void_p
    k32.GlobalLock.restype = ctypes.c_void_p
    k32.GlobalLock.argtypes = [ctypes.c_void_p]
    k32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    u32.SetClipboardData.restype = ctypes.c_void_p
    u32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
    if not u32.OpenClipboard(None):
        return False
    try:
        u32.EmptyClipboard()
        buf = ctypes.create_unicode_buffer(text)
        size = ctypes.sizeof(buf)
        h = k32.GlobalAlloc(_GMEM_MOVEABLE, size)
        if not h:
            return False
        p = k32.GlobalLock(h)
        ctypes.memmove(p, ctypes.byref(buf), size)
        k32.GlobalUnlock(h)
        return bool(u32.SetClipboardData(_CF_UNICODETEXT, h))
    finally:
        u32.CloseClipboard()


def _clip_get() -> str:
    if os.name != "nt":
        return ""
    u32, k32 = ctypes.windll.user32, ctypes.windll.kernel32
    k32.GlobalLock.restype = ctypes.c_void_p
    k32.GlobalLock.argtypes = [ctypes.c_void_p]
    k32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    u32.GetClipboardData.restype = ctypes.c_void_p
    u32.GetClipboardData.argtypes = [ctypes.c_uint]
    if not u32.OpenClipboard(None):
        return ""
    try:
        h = u32.GetClipboardData(_CF_UNICODETEXT)
        if not h:
            return ""
        p = k32.GlobalLock(ctypes.c_void_p(h))
        try:
            return ctypes.wstring_at(p) if p else ""
        finally:
            k32.GlobalUnlock(ctypes.c_void_p(h))
    finally:
        u32.CloseClipboard()


def clip_clear_if_ours(expected: str) -> bool:
    """Only wipe the clipboard if it still holds what we put there. Clobbering
    whatever the user copied in the meantime would be its own small betrayal."""
    if _clip_get() != expected:
        return False
    return _clip_set("")


def copy_with_timeout(text: str, seconds=CLIP_CLEAR_SECONDS):
    """Copy, and arm a daemon timer to clear it. The caller must stay alive for
    `seconds` or the timer dies with the process - cli_get() blocks for exactly
    that reason, and the GUI uses its own Tk `after` timer instead."""
    if not _clip_set(text):
        raise PassError("could not open the Windows clipboard")
    t = threading.Timer(seconds, clip_clear_if_ours, args=(text,))
    t.daemon = True
    t.start()
    return t


# ---------------------------------------------------------------------- store
class PasswordStore:
    """The password DB living as a single blob inside an unlocked Vault."""

    def __init__(self, vault):
        if vault.dek is None:
            raise PassError("vault is locked")
        self.vault = vault
        self.data = None

    # ---- persistence
    def load(self):
        try:
            raw = self.vault.read_bytes(STORE_NAME)
        except sv.VaultError:
            self.data = {"version": STORE_VERSION, "entries": {}, "clients": {}}
            return self.data
        self.data = json.loads(raw.decode("utf-8"))
        if self.data.get("version") != STORE_VERSION:
            raise PassError(f"unsupported password store version {self.data.get('version')}")
        self.data.setdefault("entries", {})
        # Paired browser extensions (svauth). Added without bumping
        # STORE_VERSION on purpose: load() REJECTS a version it does not know,
        # so bumping would make every vault written before pairing existed
        # unreadable. A missing key simply means "nothing paired yet".
        self.data.setdefault("clients", {})
        return self.data

    def save(self):
        if self.data is None:
            raise PassError("nothing loaded")
        blob = json.dumps(self.data, indent=1, sort_keys=True).encode("utf-8")
        self.vault.write_bytes(STORE_NAME, blob)

    def _ensure(self):
        if self.data is None:
            self.load()
        return self.data["entries"]

    # ---- paired browser extensions (see svauth)
    def clients(self):
        """The registered extensions, as {client_id: record}. Mutate and then
        save() to persist - the records live in the same encrypted blob."""
        if self.data is None:
            self.load()
        return self.data.setdefault("clients", {})

    def forget_client(self, client_id):
        """Revoke one pairing. The next signed request from that browser fails
        with 'not paired' and it has to be paired again by hand."""
        return self.clients().pop(client_id, None) is not None

    # ---- crud
    def add(self, title, username="", password="", url="", notes="",
            totp_secret="", tags=None):
        entries = self._ensure()
        if totp_secret:
            totp_secret = _clean_totp(totp_secret)
        eid = uuid.uuid4().hex
        now = int(time.time())
        entries[eid] = {
            "title": title, "username": username, "password": password,
            "url": url, "notes": notes, "totp_secret": totp_secret,
            "tags": sorted(set(tags or [])), "created": now, "modified": now,
            "history": [],
        }
        return eid

    def update(self, eid, **fields):
        entries = self._ensure()
        if eid not in entries:
            raise PassError(f"no such entry: {eid}")
        e = entries[eid]
        if "totp_secret" in fields and fields["totp_secret"]:
            fields["totp_secret"] = _clean_totp(fields["totp_secret"])
        # keep the superseded password so a botched rotation is recoverable
        new_pw = fields.get("password")
        if new_pw is not None and new_pw != e["password"] and e["password"]:
            e.setdefault("history", []).insert(
                0, {"password": e["password"], "changed": e.get("modified", 0)})
            del e["history"][HISTORY_LIMIT:]
        for k, v in fields.items():
            if k in ("title", "username", "password", "url", "notes", "totp_secret"):
                e[k] = v
            elif k == "tags":
                e[k] = sorted(set(v or []))
        e["modified"] = int(time.time())
        return e

    def delete(self, eid):
        entries = self._ensure()
        if eid not in entries:
            raise PassError(f"no such entry: {eid}")
        del entries[eid]

    def get(self, eid):
        entries = self._ensure()
        if eid not in entries:
            raise PassError(f"no such entry: {eid}")
        return entries[eid]

    def all(self):
        return self._ensure()

    # ---- lookup
    def search(self, query):
        """Case-insensitive across title/username/url/tags. A query that looks
        like a host also matches on registrable domain, so 'mail.google.com'
        finds the entry saved as 'https://accounts.google.com/'."""
        entries = self._ensure()
        q = (query or "").strip().lower()
        if not q:
            return sorted(entries.items(), key=lambda kv: kv[1]["title"].lower())
        qdom = domain_of(q) if "." in q else ""
        out = []
        for eid, e in entries.items():
            hay = " ".join([e.get("title", ""), e.get("username", ""),
                            e.get("url", ""), " ".join(e.get("tags", []))]).lower()
            if q in hay or (qdom and same_site(qdom, e.get("url", ""))):
                out.append((eid, e))
        return sorted(out, key=lambda kv: kv[1]["title"].lower())

    def find_by_domain(self, url):
        entries = self._ensure()
        return [(eid, e) for eid, e in entries.items()
                if e.get("url") and same_site(url, e["url"])]

    def identities(self):
        """The distinct usernames/emails you use, most-frequent first. Lets the
        browser suggest which email to enter on a form even when no login is
        saved for that site yet (e.g. a fresh signup)."""
        entries = self._ensure()
        counts = {}
        for e in entries.values():
            u = (e.get("username") or "").strip()
            if u:
                counts[u] = counts.get(u, 0) + 1
        return [u for u, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))]

    def resolve(self, needle):
        """Accept a full id, a unique id prefix, or an exact/unique title."""
        entries = self._ensure()
        if needle in entries:
            return needle
        hits = [eid for eid in entries if eid.startswith(needle)]
        if len(hits) == 1:
            return hits[0]
        tl = needle.strip().lower()
        exact = [eid for eid, e in entries.items() if e["title"].lower() == tl]
        if len(exact) == 1:
            return exact[0]
        part = [eid for eid, e in entries.items() if tl in e["title"].lower()]
        if len(part) == 1:
            return part[0]
        if not (hits or exact or part):
            raise PassError(f"no entry matches {needle!r}")
        raise PassError(f"{needle!r} is ambiguous ({len(hits or exact or part)} matches)")

    # ---- the phishing gate
    def copy_password(self, eid, for_url=None, seconds=CLIP_CLEAR_SECONDS,
                      force=False):
        """Copy an entry's password, clearing the clipboard after `seconds`.

        If the entry has a URL and the caller says which site it is copying
        for, a mismatch raises DomainMismatch instead of copying. That is the
        one check standing in for the origin matching we gave up by leaving
        Chrome's autofill."""
        e = self.get(eid)
        stored = e.get("url", "")
        if stored and for_url and not force and not same_site(for_url, stored):
            raise DomainMismatch(
                f"entry is saved for {domain_of(stored)} but you asked for "
                f"{domain_of(for_url)} - refusing to copy")
        copy_with_timeout(e["password"], seconds)
        return domain_of(stored)

    def totp_now(self, eid):
        e = self.get(eid)
        if not e.get("totp_secret"):
            raise PassError("no authenticator secret on this entry")
        return svtotp.totp(e["totp_secret"]), 30 - int(time.time()) % 30

    # ---- audit
    def audit(self, weak_below=60, stale_days=365):
        """Reuse, weakness, and staleness. Reuse is the one that actually
        matters: it is how one breached site becomes all of them."""
        entries = self._ensure()
        by_pw = {}
        for eid, e in entries.items():
            if e.get("password"):
                by_pw.setdefault(e["password"], []).append(eid)
        reused = {}
        for ids in by_pw.values():
            if len(ids) > 1:
                for eid in ids:
                    reused[eid] = [i for i in ids if i != eid]
        now = time.time()
        weak, stale, no_totp = [], [], []
        for eid, e in entries.items():
            pw = e.get("password", "")
            if pw and entropy_bits(pw) < weak_below:
                weak.append(eid)
            if (now - e.get("modified", now)) > stale_days * 86400:
                stale.append(eid)
            if not e.get("totp_secret"):
                no_totp.append(eid)
        return {"reused": reused, "weak": weak, "stale": stale, "no_totp": no_totp,
                "total": len(entries)}

    # ---- bulk
    def import_records(self, records, skip_duplicates=True):
        """records: dicts with title/username/password/url/notes/totp_secret.
        A duplicate is the same username on the same registrable domain."""
        entries = self._ensure()
        existing = set()
        for e in entries.values():
            existing.add((domain_of(e.get("url", "")), e.get("username", "").lower()))
        added = skipped = 0
        for r in records:
            key = (domain_of(r.get("url", "")), (r.get("username") or "").lower())
            if skip_duplicates and key in existing and key != ("", ""):
                skipped += 1
                continue
            self.add(title=r.get("title") or domain_of(r.get("url", "")) or "(untitled)",
                     username=r.get("username", ""), password=r.get("password", ""),
                     url=r.get("url", ""), notes=r.get("notes", ""),
                     totp_secret=r.get("totp_secret", ""), tags=r.get("tags"))
            existing.add(key)
            added += 1
        return added, skipped


def _clean_totp(secret: str) -> str:
    """Accept a raw base32 secret or a pasted otpauth:// URI; validate it now
    rather than at 3am when a code is actually needed."""
    s = (secret or "").strip()
    if s.lower().startswith("otpauth://"):
        from urllib.parse import parse_qs
        q = parse_qs(urlsplit(s).query)
        s = (q.get("secret") or [""])[0]
    s = s.replace(" ", "").upper()
    if not s:
        raise PassError("empty authenticator secret")
    try:
        svtotp.totp(s)
    except Exception:
        raise PassError("not a valid base32 authenticator secret")
    return s
