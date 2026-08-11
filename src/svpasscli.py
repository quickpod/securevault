#!/usr/bin/env python3
r"""
svpasscli - command-line front end for the SecureVault password manager.

Dispatched from securevault.main() when argv[0] is "pw". Every verb that
touches secrets goes through open_vault(), so the same password + PIN + TOTP
that guards the file vault guards the passwords - there is no second master
secret to manage.

  securevault pw list [query]        list entries (no passwords shown)
  securevault pw show <id|title>      show one entry (password redacted)
  securevault pw copy <id|title> [--url U] [--seconds N] [--force]
                                     copy password to clipboard, auto-clear
  securevault pw reveal <id|title>   print the password to stdout (console only)
  securevault pw add                 add an entry (prompts, or flags below)
  securevault pw edit <id|title>     edit fields (flags below)
  securevault pw rm  <id|title>      delete an entry
  securevault pw gen [len]           generate a password (also copies it)
  securevault pw totp <id|title>     current 6-digit code + seconds remaining
  securevault pw audit               reuse / weak / stale / no-2FA report
  securevault pw import-chrome <csv> import a Chrome export, then shred it

Field flags for add/edit: --title --user --url --notes --totp --password
  (--password with no value, or --gen, generates a strong one)
"""

import os, sys, getpass, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import svpass
import svtotp


def _console():
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        return False


def _parse_flags(args):
    """Tiny --flag value / --flag parser. Returns (flags, positionals)."""
    flags, pos, i = {}, [], 0
    known_bool = {"--gen", "--force"}
    while i < len(args):
        a = args[i]
        if a.startswith("--"):
            if a in known_bool or i + 1 >= len(args) or args[i + 1].startswith("--"):
                flags[a] = True
            else:
                flags[a] = args[i + 1]; i += 1
        else:
            pos.append(a)
        i += 1
    return flags, pos


def _fmt_entry(eid, e, reveal=False):
    lines = [f"  id       : {eid}",
             f"  title    : {e.get('title','')}",
             f"  username : {e.get('username','')}",
             f"  url      : {e.get('url','')}  (domain: {svpass.domain_of(e.get('url',''))})"]
    pw = e.get("password", "")
    if reveal:
        lines.append(f"  password : {pw}")
    else:
        lines.append(f"  password : {'*' * min(len(pw), 12) if pw else '(none)'}  "
                     f"[{svpass.strength_label(pw)}, {svpass.entropy_bits(pw):.0f} bits]")
    if e.get("totp_secret"):
        code, rem = svtotp.totp(e["totp_secret"]), 30 - int(time.time()) % 30
        lines.append(f"  totp     : {code}  ({rem}s left)")
    if e.get("tags"):
        lines.append(f"  tags     : {', '.join(e['tags'])}")
    if e.get("notes"):
        lines.append(f"  notes    : {e['notes']}")
    return "\n".join(lines)


def run(store, args):
    """args is everything after 'pw'. `store` is a loaded PasswordStore."""
    if not args:
        print(__doc__); return 0
    sub, rest = args[0], args[1:]
    flags, pos = _parse_flags(rest)

    if sub == "list":
        hits = store.search(" ".join(pos))
        if not hits:
            print("no matching entries."); return 0
        print(f"{len(hits)} entr{'y' if len(hits)==1 else 'ies'}:")
        for eid, e in hits:
            tag = " *2FA" if e.get("totp_secret") else ""
            print(f"  {eid[:8]}  {e['title'][:30]:32} {e.get('username','')[:30]:32}"
                  f"{svpass.domain_of(e.get('url','')):24}{tag}")
        return 0

    if sub == "show":
        if not pos: print("usage: pw show <id|title>"); return 1
        eid = store.resolve(pos[0]); print(_fmt_entry(eid, store.get(eid))); return 0

    if sub == "reveal":
        if not _console():
            print("reveal only works at a real console."); return 1
        if not pos: print("usage: pw reveal <id|title>"); return 1
        eid = store.resolve(pos[0]); print(_fmt_entry(eid, store.get(eid), reveal=True)); return 0

    if sub == "copy":
        if not pos: print("usage: pw copy <id|title> [--url U] [--seconds N] [--force]"); return 1
        eid = store.resolve(pos[0])
        secs = int(flags.get("--seconds", svpass.CLIP_CLEAR_SECONDS))
        try:
            dom = store.copy_password(eid, for_url=flags.get("--url"),
                                      seconds=secs, force=bool(flags.get("--force")))
        except svpass.DomainMismatch as e:
            print(f"REFUSED: {e}\n  re-run with --force if you are sure."); return 2
        where = f" for {dom}" if dom else ""
        print(f"password{where} copied - clipboard clears in {secs}s.")
        # the auto-clear timer is a daemon thread; block so it can fire
        try:
            time.sleep(secs + 1)
        except KeyboardInterrupt:
            svpass.clip_clear_if_ours(store.get(eid)["password"])
            print("\ncleared early.");
        return 0

    if sub == "gen":
        length = int(pos[0]) if pos else 24
        pw = svpass.generate(length)
        svpass.copy_with_timeout(pw)
        print(f"{pw}\n  [{svpass.strength_label(pw)}, {svpass.entropy_bits(pw):.0f} bits] "
              f"- copied, clears in {svpass.CLIP_CLEAR_SECONDS}s")
        return 0

    if sub == "totp":
        if not pos: print("usage: pw totp <id|title>"); return 1
        eid = store.resolve(pos[0])
        try:
            code, rem = store.totp_now(eid)
        except svpass.PassError as e:
            print(str(e)); return 1
        print(f"{code}  ({rem}s left)"); return 0

    if sub == "add":
        title = flags.get("--title") or (pos[0] if pos else None)
        if not title:
            if not _console(): print("pw add needs --title when not at a console"); return 1
            title = input("title: ").strip()
        pw = flags.get("--password")
        if flags.get("--gen") or pw is True:
            pw = svpass.generate(int(flags.get("--len", 24)))
            print(f"generated: {pw}")
        elif pw is None and _console():
            pw = getpass.getpass("password (blank to generate): ") or svpass.generate()
        eid = store.add(title=title, username=flags.get("--user", ""),
                        password=pw or "", url=flags.get("--url", ""),
                        notes=flags.get("--notes", ""), totp_secret=flags.get("--totp", ""))
        store.save()
        print(f"added {eid[:8]}  {title}"); return 0

    if sub == "edit":
        if not pos: print("usage: pw edit <id|title> [--field value ...]"); return 1
        eid = store.resolve(pos[0])
        upd = {}
        for flag, field in (("--title","title"),("--user","username"),("--url","url"),
                            ("--notes","notes"),("--totp","totp_secret")):
            if flag in flags: upd[field] = flags[flag]
        if flags.get("--gen") or flags.get("--password") is True:
            newpw = svpass.generate(int(flags.get("--len", 24)))
            upd["password"] = newpw; print(f"generated: {newpw}")
        elif isinstance(flags.get("--password"), str):
            upd["password"] = flags["--password"]
        if not upd: print("nothing to change - pass --field value flags."); return 1
        store.update(eid, **upd); store.save()
        print(f"updated {eid[:8]}"); return 0

    if sub == "rm":
        if not pos: print("usage: pw rm <id|title>"); return 1
        eid = store.resolve(pos[0]); e = store.get(eid)
        if _console():
            ok = input(f"delete '{e['title']}' ({e.get('username','')})? [y/N] ").strip().lower()
            if ok != "y": print("cancelled."); return 0
        store.delete(eid); store.save()
        print(f"deleted {eid[:8]}"); return 0

    if sub == "audit":
        r = store.audit()
        print(f"{r['total']} entries")
        reused_groups = {}
        for eid, others in r["reused"].items():
            key = tuple(sorted([eid] + others)); reused_groups[key] = True
        print(f"  reused passwords : {len(r['reused'])} entries in {len(reused_groups)} groups")
        print(f"  weak (<60 bits)  : {len(r['weak'])}")
        print(f"  stale (>1 year)  : {len(r['stale'])}")
        print(f"  no 2FA secret    : {r['no_totp']. __len__()}")
        if r["reused"]:
            print("\n  reuse is the priority - one breach unlocks the rest. Worst offenders:")
            shown = set()
            for eid, others in sorted(r["reused"].items(),
                                      key=lambda kv: len(kv[1]), reverse=True)[:5]:
                grp = tuple(sorted([eid] + others))
                if grp in shown: continue
                shown.add(grp)
                titles = [store.get(i)["title"] for i in grp]
                print(f"    {len(grp)}x: {', '.join(titles[:6])}")
        return 0

    if sub == "import-chrome":
        import svchrome
        if not pos:
            print(svchrome.EXPORT_STEPS); return 1
        path = pos[0]
        if not os.path.isfile(path): print(f"no such file: {path}"); return 1
        prev = svchrome.preview_csv(path)
        print(f"parsed {prev['total']} credentials ({prev['with_password']} with a password, "
              f"{prev['skipped_blank']} blank rows skipped)")
        for s in prev["sample"]:
            print(f"    {s['title'][:28]:30} {s['username'][:28]:30} {s['domain']}")
        if _console():
            ok = input(f"import into the vault and SHRED {path}? [y/N] ").strip().lower()
            if ok != "y": print("cancelled - file left untouched."); return 0
        res = svchrome.import_csv(store, path)
        store.save()
        shredded = svchrome.shred_file(path)
        print(f"imported {res['added']} ({res['duplicates']} duplicates skipped). "
              f"export {'shredded' if shredded else 'could NOT be deleted - remove it yourself'}.")
        return 0

    print(f"unknown pw command: {sub}\n"); print(__doc__); return 1
