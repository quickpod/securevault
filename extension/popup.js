// Popup: connection status (live, polled), one-time PIN pairing, and the
// paired quick actions. The PIN is generated and displayed BY THE VAULT - this
// box only accepts what the user read off the app window, which is why a
// hostile page or process cannot drive a pairing on its own.
//
// Status is polled every 2s while the popup is open, so unlocking the vault in
// the app flips the popup without closing/reopening it. Three distinct states:
//   app not running        -> "Open SecureVault" launches it via the host
//   running but locked     -> "unlock it in the app" (no launch button; a
//                             second instance would be worse than the message)
//   open + unlocked        -> pair box, or the paired quick actions

const $ = (id) => document.getElementById(id);
const send = (msg) => new Promise((res) =>
  chrome.runtime.sendMessage(msg, (r) => res(r || { ok: false })));

function show(el, on) { el.classList.toggle("hidden", !on); }

let paired = false;

async function refresh() {
  const st = await send({ op: "status" });
  const box = $("status");
  paired = !!st.paired;
  if (!st.ok) {
    const running = !!st.app_running;
    box.textContent = running
      ? "Vault is locked. Unlock it in the SecureVault app."
      : "SecureVault isn't running.";
    box.className = running ? "warn" : "bad";
    show($("launchbox"), !running);
    show($("pairbox"), false);
    show($("pairedbox"), false);
    return;
  }
  show($("launchbox"), false);
  if (st.paired) {
    box.textContent = "Connected and paired.";
    box.className = "ok";
  } else {
    box.textContent = "Connected - not paired yet.";
    box.className = "warn";
  }
  const showingPair = !$("pairbox").classList.contains("hidden");
  show($("pairbox"), !st.paired);
  show($("pairedbox"), !!st.paired);
  if (!st.paired && !showingPair) {
    $("pin").focus();                 // box just appeared: type the PIN at once
  }
  if (st.paired) { siteInfo(); bmInfo(); }
}

// ---- bookmarks sync surface
let bmShown = "";
async function bmInfo() {
  const r = await send({ op: "bm-status" });
  const box = $("bmbox");
  if (!r.ok) { show(box, false); bmShown = ""; return; }
  show(box, true);
  const when = r.saved_at ? new Date(r.saved_at * 1000).toLocaleString() : "";
  const line = r.have
    ? `Bookmarks: ${r.vault} in vault (backed up ${when}) · ${r.local} in this browser`
    : `Bookmarks: none in vault yet · ${r.local} in this browser`;
  if (line !== bmShown) { $("bmline").textContent = line; bmShown = line; }
  $("bmrestore").disabled = !r.have;
}

function bmOfferRestore(n) {
  show($("bmbox"), true);
  show($("bmconfirm"), true);
  $("bmconfirmtext").textContent =
    `This browser has no bookmarks. Restore the ${n} saved in your vault?`;
}

$("bmbackup").addEventListener("click", async () => {
  $("msg2").textContent = "backing up…";
  const r = await send({ op: "bm-backup" });
  $("msg2").textContent = r.ok ? `backed up ${r.count} bookmark(s)`
                               : (r.error || "backup failed");
  bmShown = ""; bmInfo();
});

$("bmrestore").addEventListener("click", async () => {
  const st = await send({ op: "bm-status" });
  if (!st.ok || !st.have) return;
  show($("bmconfirm"), true);
  $("bmconfirmtext").textContent =
    `Restore ${st.vault} bookmark(s) from the vault? Merge adds what's ` +
    `missing (no duplicates); Replace all clears this browser's bookmarks first.`;
});

async function bmDoRestore(mode) {
  show($("bmconfirm"), false);
  $("msg2").textContent = "restoring…";
  const r = await send({ op: "bm-restore", mode });
  $("msg2").textContent = r.ok
    ? `restored - ${r.created} bookmark(s) added`
    : (r.error || "restore failed");
  bmShown = ""; bmInfo();
}
$("bmmerge").addEventListener("click", () => bmDoRestore("merge"));
$("bmreplace").addEventListener("click", () => bmDoRestore("replace"));
$("bmcancel").addEventListener("click", () => show($("bmconfirm"), false));

let siteShown = "";
async function siteInfo() {
  const r = await send({ op: "popup-site" });
  const el = $("site");
  if (!r.ok || !r.domain) { show(el, false); siteShown = ""; return; }
  if (siteShown === r.domain + "|" + r.count) { show(el, true); return; }
  siteShown = r.domain + "|" + r.count;
  el.querySelector(".domain").textContent = r.domain;
  el.querySelector(".count").textContent =
    r.count === 0 ? "no saved logins for this site"
                  : r.count === 1 ? "1 saved login: " + (r.usernames[0] || "")
                  : r.count + " saved logins";
  show(el, true);
}

// ---- pairing: digits only, auto-focus, auto-submit on the 6th digit
$("pin").addEventListener("input", () => {
  const v = $("pin").value.replace(/\D/g, "").slice(0, 6);
  if (v !== $("pin").value) $("pin").value = v;
  if (v.length === 6) $("pairbtn").click();
});
$("pin").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("pairbtn").click();
});

let pairing = false;
$("pairbtn").addEventListener("click", async () => {
  if (pairing) return;
  pairing = true;
  const msg = $("msg");
  msg.className = "";
  msg.textContent = "pairing…";
  const r = await send({ op: "pair", pin: $("pin").value.trim() });
  pairing = false;
  if (r.ok) {
    msg.className = "good";
    msg.textContent = "Paired.";
    $("pin").value = "";
    refresh();
    if (r.offer_restore) bmOfferRestore(r.offer_restore);
  } else {
    msg.className = "err";
    // The vault's own words: "wrong PIN (2 attempts left)", "no pairing window
    // is open", "expired". Rewording them here would only lose information.
    msg.textContent = r.error || "pairing failed";
    $("pin").value = "";
    $("pin").focus();
  }
});

// ---- paired quick actions
$("fillbtn").addEventListener("click", async () => {
  const r = await send({ op: "popup-fill" });
  $("msg2").textContent = r.ok ? "" : (r.error || "no login form found on this page");
  if (r.ok) window.close();
});

$("genbtn").addEventListener("click", async () => {
  const r = await send({ op: "popup-generate", length: 24 });
  const el = $("gen");
  if (r.ok && r.password) {
    el.textContent = r.password;
    show(el, true);
    try { await navigator.clipboard.writeText(r.password); } catch (e) {}
    $("msg2").textContent = "copied to clipboard";
  } else {
    $("msg2").textContent = r.error || "could not generate";
  }
});

$("openvaultbtn").addEventListener("click", async () => {
  await send({ op: "open-app" });
  window.close();
});

$("launchbtn").addEventListener("click", async () => {
  const r = await send({ op: "open-app" });
  $("status").textContent = r.ok ? "Starting SecureVault…"
                                 : (r.error || "could not start SecureVault");
});

$("unpairbtn").addEventListener("click", async () => {
  // local only: forget our own key and id. The vault keeps its record until
  // the user revokes it there, which is the half that actually stops access.
  await send({ op: "unpair" });
  siteShown = "";
  refresh();
});

refresh();
const poll = setInterval(refresh, 2000);
window.addEventListener("unload", () => clearInterval(poll));
