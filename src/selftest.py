import os, sys, tempfile, shutil, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import securevault as sv
import svtotp

tmp = tempfile.mkdtemp()
dat = os.path.join(tmp, "SecureVault.dat")
PW    = sv.auth_material(b"correct horse battery staple", b"481920")
NEWPW = sv.auth_material(b"new-master-2026", b"135790")
WRONG = sv.auth_material(b"correct horse battery staple", b"000000")  # right pw, wrong PIN

SECRET = {"s": None}
def code(): return svtotp.totp(SECRET["s"])

def mk(name, data):
    p = os.path.join(tmp, name)
    with open(p, "wb") as f: f.write(data)
    return p

fails = 0
def check(cond, msg):
    global fails
    print(("PASS" if cond else "FAIL"), msg)
    if not cond: fails += 1

# create returns the TOTP enrollment secret
v = sv.Vault(dat); SECRET["s"] = v.create(PW)
check(os.path.isfile(dat) and SECRET["s"], "vault created + TOTP secret issued")

# wrong PIN rejected (never reaches data key)
try:
    sv.Vault(dat).unlock(WRONG, code()); check(False, "wrong pin should fail")
except sv.VaultError: check(True, "wrong password/PIN rejected")

# right password+PIN but wrong TOTP code rejected
try:
    sv.Vault(dat).unlock(PW, "000000"); check(False, "wrong totp should fail")
except sv.VaultError: check(True, "wrong TOTP code rejected")

# right everything unlocks
v = sv.Vault(dat).unlock(PW, code())
check(v.dek is not None, "correct password+PIN+TOTP unlocks")

# add / roundtrip
f1 = mk("secret1.txt", b"top secret alpha " * 100)
f2 = mk("pass.txt", os.urandom(5000)); data2 = open(f2, "rb").read()
v = sv.Vault(dat).unlock(PW, code()); n1 = v.add(f1); n2 = v.add(f2)
check(not os.path.exists(f1) and not os.path.exists(f2), "originals deleted after add")
v = sv.Vault(dat).unlock(PW, code())
check(open(v.get(n2, os.path.join(tmp, "o2.bin")), "rb").read() == data2, "decrypt roundtrip")

# append correctness
f3 = mk("k.pem", b"-----BEGIN KEY-----\n" + os.urandom(2000).hex().encode()); data3 = open(f3,"rb").read()
v = sv.Vault(dat).unlock(PW, code()); v.add(f3)
v = sv.Vault(dat).unlock(PW, code())
check(open(v.get(n1, os.path.join(tmp,"o1")),"rb").read()==b"top secret alpha "*100, "first file intact after 3rd add")
check(open(v.get("k.pem", os.path.join(tmp,"o3")),"rb").read()==data3, "third file intact")

# verify + tamper
v = sv.Vault(dat).unlock(PW, code()); idx, bad = v.verify(); check(not bad, "verify clean")
with open(dat, "r+b") as f:
    f.seek(os.path.getsize(dat)//2); b=f.read(1); f.seek(-1,1); f.write(bytes([b[0]^0xFF]))
v = sv.Vault(dat).unlock(PW, code()); idx, bad = v.verify(); check(len(bad)>=1, "tamper detected")

# fresh vault for remove/passwd
os.remove(dat)
v = sv.Vault(dat); SECRET["s"] = v.create(PW)
a=mk("a.txt",b"AAAA"); bb=mk("b.txt",b"BBBB"); c=mk("c.txt",b"CCCC")
v=sv.Vault(dat).unlock(PW, code()); v.add(a); v.add(bb); v.add(c)
v=sv.Vault(dat).unlock(PW, code()); v.remove("b.txt")
v=sv.Vault(dat).unlock(PW, code()); idx=v.list()
check("b.txt" not in idx and "a.txt" in idx and "c.txt" in idx, "remove works, others survive")
check(open(v.get("c.txt", os.path.join(tmp,"oc")),"rb").read()==b"CCCC", "c.txt decrypts after remove+compact")

# password change keeps same TOTP secret
v=sv.Vault(dat).unlock(PW, code()); v.change_password(NEWPW)
try:
    sv.Vault(dat).unlock(PW, code()); check(False, "old pw should fail")
except sv.VaultError: check(True, "old password rejected after change")
v=sv.Vault(dat).unlock(NEWPW, code())
check(open(v.get("a.txt", os.path.join(tmp,"oa")),"rb").read()==b"AAAA", "content survives password change (TOTP unchanged)")

# TOTP math sanity
s = svtotp.random_secret()
check(svtotp.verify(s, svtotp.totp(s)), "TOTP verifies current code")
check(not svtotp.verify(s, "000000", at=0), "TOTP rejects bad code")

# ---- folder map: the Explorer tree is derived from the "/" in stored names
import svgui, svopen, svshell
v = sv.Vault(dat).unlock(NEWPW, code())
for rel, body in (("docs/2026/tax.pdf", b"TAX"), ("docs/2026/w2.pdf", b"W2"),
                  ("docs/notes.txt", b"NOTE"), ("keys/id_rsa", b"KEY")):
    v.add(mk(rel.replace("/", "_"), body), arcname=rel)
v = sv.Vault(dat).unlock(NEWPW, code())
fmap = svgui.build_folder_map(v.list())
check(fmap[""]["dirs"] == {"docs", "keys"}, "tree: top-level folders found")
check(fmap["docs"]["dirs"] == {"docs/2026"}, "tree: intermediate folder implied by path")
check(sorted(fmap["docs/2026"]["files"]) == ["docs/2026/tax.pdf", "docs/2026/w2.pdf"],
      "tree: files land in their own folder")
check("a.txt" in fmap[""]["files"], "tree: loose files stay at the root")

# ---- open-outside-the-vault: stage, detect edits, save back, wipe
ws = svopen.Workspace(sv.Vault(dat).unlock(NEWPW, code()))
ent = ws.stage("docs/notes.txt")
check(open(ent["path"], "rb").read() == b"NOTE", "open: staged plaintext matches the stored file")
check(not ws.changed("docs/notes.txt"), "open: untouched file reports no change")
with open(ent["path"], "wb") as f: f.write(b"EDITED IN PLACE")
check(ws.changed("docs/notes.txt"), "open: edit detected")
p1, d1 = ent["path"], ent["subdir"]
ws.finish("docs/notes.txt", save_back=True)
check(not os.path.exists(p1) and not os.path.exists(d1), "open: plaintext wiped after save-back")
v = sv.Vault(dat).unlock(NEWPW, code())
check(v.read_bytes("docs/notes.txt") == b"EDITED IN PLACE", "open: edits saved back into the vault")
check(v.read_bytes("docs/2026/tax.pdf") == b"TAX", "open: neighbours intact after save-back")
check(v.dead_space() > 0, "open: superseded blob shows as reclaimable space")

ent = ws.stage("keys/id_rsa")
with open(ent["path"], "wb") as f: f.write(b"TAMPERED")
p2 = ent["path"]
ws.finish("keys/id_rsa", save_back=False)
check(not os.path.exists(p2), "open: discarded copy wiped")
v = sv.Vault(dat).unlock(NEWPW, code())
check(v.read_bytes("keys/id_rsa") == b"KEY", "open: discarding edits leaves the vault untouched")

ws2 = svopen.Workspace(sv.Vault(dat).unlock(NEWPW, code()))
ws2.stage("a.txt"); scratch = ws2.dir
ws2.wipe_all()
check(not os.path.exists(scratch), "open: wipe_all removes the whole scratch directory")
check(not ws2.list_open(), "open: nothing tracked after wipe_all")

# remove() still compacts away the dead blob left by the save-back
v = sv.Vault(dat).unlock(NEWPW, code()); v.remove("keys/id_rsa")
v = sv.Vault(dat).unlock(NEWPW, code())
check(v.dead_space() == 0, "compaction reclaims superseded blobs")
check(v.read_bytes("docs/notes.txt") == b"EDITED IN PLACE", "content survives compaction")

# ---- Explorer verbs register/unregister under HKCU with no admin rights
if os.name == "nt":
    had = svshell.is_registered()[0]
    svshell.register()
    check(svshell.is_current(), "shell: register writes verbs for this program")
    svshell.unregister()
    check(not svshell.is_registered()[0], "shell: unregister removes them")
    if had:
        svshell.register()

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{'ALL PASS' if fails==0 else str(fails)+' FAILURES'}")
sys.exit(1 if fails else 0)
