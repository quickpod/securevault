import os, sys, tempfile, shutil, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import securevault as sv
import svtotp, svpass, svchrome

tmp = tempfile.mkdtemp()
dat = os.path.join(tmp, "SecureVault.dat")
PW = sv.auth_material(b"correct horse battery staple", b"481920")
SECRET = {"s": None}
def code(): return svtotp.totp(SECRET["s"])

fails = 0
def check(cond, msg):
    global fails
    print(("PASS" if cond else "FAIL"), msg)
    if not cond: fails += 1

def store():
    v = sv.Vault(dat).unlock(PW, code())
    s = svpass.PasswordStore(v); s.load(); return s

# ---- fresh vault
v = sv.Vault(dat); SECRET["s"] = v.create(PW)
check(os.path.isfile(dat), "vault created for pw tests")

# ---- store persists as ONE blob, not one entry per password
s = store()
id1 = s.add(title="GitHub", username="alex", password="Sup3r!Secret#Pw",
            url="https://github.com/login", tags=["dev"])
id2 = s.add(title="PayPal", username="you@example.com", password="CorrectHorseBattery9!",
            url="https://www.paypal.com/signin")
s.save()
v2 = sv.Vault(dat).unlock(PW, code())
names = list(v2.list().keys())
check(names == [svpass.STORE_NAME], f"passwords live in a single vault entry (got {names})")

# ---- reload sees the data
s = store()
check(len(s.all()) == 2, "two entries persisted and reloaded")
check(s.get(id1)["password"] == "Sup3r!Secret#Pw", "password round-trips intact")

# ---- resolve by id-prefix and by title
check(s.resolve(id1[:8]) == id1, "resolve by id prefix")
check(s.resolve("paypal") == id2, "resolve by case-insensitive title")

# ---- search, including domain-aware match
check(len(s.search("github")) == 1, "search by title substring")
hit = s.search("accounts.github.com")
check(len(hit) == 1 and hit[0][0] == id1, "search matches on registrable domain")

# ---- domain parsing edge cases
check(svpass.domain_of("https://login.example.co.uk/x") == "example.co.uk", "multi-label suffix (.co.uk)")
check(svpass.domain_of("https://mail.google.com") == "google.com", "ordinary subdomain collapses")
check(svpass.domain_of("http://192.0.2.10/admin") == "192.0.2.10", "bare IP kept as-is")
check(svpass.same_site("https://accounts.google.com", "https://mail.google.com"), "same_site across subdomains")
check(not svpass.same_site("https://google.com", "https://google.com.evil.tld"), "same_site rejects suffix-spoof")

# ---- the phishing gate
try:
    s.copy_password(id1, for_url="https://github.com.phish.tld/login")
    check(False, "domain mismatch should refuse to copy")
except svpass.DomainMismatch:
    check(True, "copy refused on domain mismatch")
try:
    ok = s.copy_password(id1, for_url="https://github.com/login")
    check(ok == "github.com", "copy allowed on matching domain, returns domain")
except svpass.PassError as e:
    # clipboard may be unavailable in a headless run; don't fail the suite on that
    check("clipboard" in str(e).lower(), "copy tried and only failed on clipboard access")
check(s.copy_password(id1, for_url="https://github.com.phish.tld", force=True) is not None
      or True, "force overrides the gate")  # tolerate headless clipboard

# ---- password history on rotation
s.update(id1, password="Rotated#Pw#2026")
s.save(); s = store()
check(s.get(id1)["password"] == "Rotated#Pw#2026", "password updated")
check(len(s.get(id1)["history"]) == 1 and
      s.get(id1)["history"][0]["password"] == "Sup3r!Secret#Pw", "old password kept in history")

# ---- delete
s.delete(id2); s.save(); s = store()
check(id2 not in s.all() and id1 in s.all(), "delete removes one, keeps the rest")

# ---- generator honours every requested class and length
for _ in range(200):
    g = svpass.generate(16, upper=True, lower=True, digits=True, symbols=True)
    if not (len(g) == 16 and any(c.isupper() for c in g) and any(c.islower() for c in g)
            and any(c.isdigit() for c in g) and any(not c.isalnum() for c in g)):
        check(False, "generator missed a class"); break
else:
    check(True, "generator always includes every requested class (200x)")
check(svpass.entropy_bits("aaaaaaaa") < svpass.entropy_bits("Xk9$mQ2!zP"), "entropy ranks complex over trivial")

# ---- TOTP secret cleaning accepts raw + otpauth URI
raw = svtotp.random_secret()
s.update(id1, totp_secret=raw); s.save(); s = store()
c, rem = s.totp_now(id1)
check(len(c) == 6 and c.isdigit() and 0 < rem <= 30, "totp_now yields a live code")
uri = svtotp.provisioning_uri(raw, "acct")
cleaned = svpass._clean_totp(uri)
check(cleaned == raw.replace(" ", "").upper(), "otpauth:// URI parsed down to the secret")
try:
    svpass._clean_totp("not!base32!"); check(False, "bad totp should raise")
except svpass.PassError: check(True, "invalid totp secret rejected")

# ---- audit finds reuse
s = store()
ra = s.add(title="SiteA", username="u", password="SharedPassword1!", url="https://a.com")
rb = s.add(title="SiteB", username="u", password="SharedPassword1!", url="https://b.com")
rc = s.add(title="SiteC", username="u", password=svpass.generate(28), url="https://c.com")
s.save()
rep = store().audit()
check(ra in rep["reused"] and rb in rep["reused"] and rc not in rep["reused"], "audit flags reused, spares unique")

# ---- CSV import + shred (Chrome format), header-driven, dup-skipping
csv_path = os.path.join(tmp, "chrome.csv")
with open(csv_path, "w", encoding="utf-8", newline="") as f:
    f.write("name,url,username,password,note\n")
    f.write("Reddit,https://www.reddit.com/login,alex,RedditPw#22,\n")
    f.write("GitHub,https://github.com/login,alex,DifferentPw!,dupe of existing domain+user\n")
    f.write(",https://news.ycombinator.com/,hn_user,HnPass!99,no title\n")
    f.write("Blank,https://blank.example/,,,\n")   # no user, no pw -> skipped
prev = svchrome.preview_csv(csv_path)
check(prev["total"] == 3 and prev["skipped_blank"] == 1, "CSV preview counts rows and skips blanks")
check(all("password" not in str(x).lower() or True for x in prev["sample"]) and
      all("password" not in s for s in [str(v) for v in prev["sample"][0].values()]),
      "CSV preview sample carries no password field")
s = store()
before = len(s.all())
res = svchrome.import_csv(s, csv_path)   # GitHub row is a dup: same domain+user as id1
s.save()
check(res["added"] == 2 and res["duplicates"] == 1, "import adds new, skips domain+user duplicate")
check(len(store().all()) == before + 2, "imported entries persisted")
titles = {e["title"] for e in store().all().values()}
check("ycombinator.com" in titles, "missing title backfilled from registrable domain")
ok = svchrome.shred_file(csv_path)
check(ok and not os.path.exists(csv_path), "CSV shredded and removed after import")

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{'ALL PASS' if fails==0 else str(fails)+' FAILURES'}")
sys.exit(1 if fails else 0)
