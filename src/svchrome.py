#!/usr/bin/env python3
r"""
svchrome - import Chrome's saved passwords into the SecureVault store, then
           shred the export.

WHY CSV AND NOT AN IN-MEMORY DPAPI DECRYPT
The first version of this module read Chrome's SQLite DB and unwrapped each
password with the DPAPI-protected os_crypt key. That worked until Chrome's
App-Bound Encryption (v127+): on this machine (Chrome 151) ALL 1,212 saved
logins are the "v20" app-bound format, and the legacy key decrypts none of
them. Unwrapping app-bound keys offline needs SYSTEM-context code plus Chrome's
own elevation-service AES layer - fragile and version-specific. Chrome's built
-in export sidesteps it because Chrome itself does the decryption.

THE COST, STATED HONESTLY
The export is a plaintext CSV. It exists on disk from the moment Chrome writes
it until shred_file() overwrites and unlinks it - keep that window short, and
export into a folder only your user can read. shred_file() does a best-effort
multi-pass overwrite; on an SSD with wear-levelling that is not a guarantee the
old blocks are gone, so treat the export as burned, not proven-erased, and do
not export onto a network/removable drive.

Chrome CSV columns: name,url,username,password,note  (order varies by version,
so we map by header, not position).
"""

import os, sys, csv, io

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import svpass


class ChromeError(Exception): pass


# ------------------------------------------------------------------- parsing
_COLMAP = {
    "name": "title", "title": "title",
    "url": "url", "origin_url": "url", "website": "url",
    "username": "username", "username_value": "username", "login": "username",
    "password": "password", "password_value": "password",
    "note": "notes", "notes": "notes", "comment": "notes",
}

def parse_csv_text(text):
    """Map a Chrome/Chromium/Edge/Brave password CSV to import records.
    Returns (records, skipped_blank). Header-driven, so column order and the
    handful of naming variants across Chromium forks all work."""
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ChromeError("empty or headerless CSV")
    norm = {(h or "").strip().lower().lstrip("\ufeff"): h for h in reader.fieldnames}
    if "password" not in norm and "password_value" not in norm:
        raise ChromeError(
            "does not look like a password export (no 'password' column). "
            f"headers were: {reader.fieldnames}")
    records, skipped = [], 0
    for row in reader:
        rec = {"title": "", "url": "", "username": "", "password": "", "notes": ""}
        for raw_key, val in row.items():
            field = _COLMAP.get((raw_key or "").strip().lower().lstrip("\ufeff"))
            if field:
                rec[field] = (val or "").strip()
        if not rec["password"] and not rec["username"]:
            skipped += 1
            continue
        if not rec["title"]:
            rec["title"] = svpass.domain_of(rec["url"]) or rec["url"] or "(untitled)"
        rec["tags"] = ["chrome-import"]
        records.append(rec)
    return records, skipped


def preview_csv(path):
    """Counts and a de-identified sample (domain + username only, never a
    password) so the user can sanity-check the file before committing."""
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        text = f.read()
    records, skipped = parse_csv_text(text)
    sample = [{"title": r["title"], "username": r["username"],
               "domain": svpass.domain_of(r["url"])} for r in records[:5]]
    with_pw = sum(1 for r in records if r["password"])
    return {"total": len(records), "with_password": with_pw,
            "skipped_blank": skipped, "sample": sample}


# -------------------------------------------------------------------- import
def import_csv(store, path, skip_duplicates=True):
    """Parse the CSV and merge into an already-loaded PasswordStore. Does NOT
    save and does NOT delete the CSV - the caller decides when to persist and
    is responsible for shred_file()."""
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        text = f.read()
    records, _skipped = parse_csv_text(text)
    added, dup = store.import_records(records, skip_duplicates=skip_duplicates)
    return {"added": added, "duplicates": dup, "parsed": len(records)}


# --------------------------------------------------------------------- shred
def shred_file(path, passes=3):
    """Best-effort secure delete: overwrite the file's bytes several times,
    flush to disk each pass, then unlink. See the module docstring for why this
    is 'best effort' on an SSD and not a guarantee."""
    if not os.path.isfile(path):
        return False
    try:
        size = os.path.getsize(path)
        with open(path, "r+b", buffering=0) as f:
            for i in range(passes):
                f.seek(0)
                f.write((b"\x00" if i % 2 else b"\xff") * size)
                f.flush()
                os.fsync(f.fileno())
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        os.remove(path)
        return True
    except OSError:
        return False


# instructions the GUI and CLI both surface, kept in one place
EXPORT_STEPS = (
    "In Chrome:\n"
    "  1. open  chrome://password-manager/settings\n"
    "  2. Settings -> Export passwords -> confirm with your Windows login\n"
    "  3. save the CSV somewhere only you can read (e.g. C:\\Users\\User\\pw-export.csv)\n"
    "Then point this importer at that file. It is deleted (shredded) right after.\n"
    "Do NOT save the export onto a removable or network drive."
)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        import json
        print(json.dumps(preview_csv(sys.argv[1]), indent=2))
    else:
        print(EXPORT_STEPS)
