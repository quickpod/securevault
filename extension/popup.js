// Popup: shows whether the app is serving, and carries the one-time PIN
// pairing. The PIN is generated and displayed BY THE VAULT - this box only
// accepts what the user read off the app window, which is why a hostile page
// or process cannot drive a pairing on its own.

const $ = (id) => document.getElementById(id);
const send = (msg) => new Promise((res) =>
  chrome.runtime.sendMessage(msg, (r) => res(r || { ok: false })));

function show(el, on) { el.classList.toggle("hidden", !on); }

async function refresh() {
  const st = await send({ op: "status" });
  const box = $("status");
  if (!st.ok) {
    box.textContent = "Not connected. Open and unlock the SecureVault app.";
    box.className = "bad";
    // Pairing needs the app running, so offer neither panel while it is down.
    show($("pairbox"), false);
    show($("pairedbox"), false);
    return;
  }
  if (st.paired) {
    box.textContent = "Connected and paired.";
    box.className = "ok";
  } else {
    box.textContent = "Connected, but this browser is not paired yet.";
    box.className = "warn";
  }
  show($("pairbox"), !st.paired);
  show($("pairedbox"), !!st.paired);
}

$("pairbtn").addEventListener("click", async () => {
  const msg = $("msg");
  msg.className = "";
  msg.textContent = "pairing…";
  const r = await send({ op: "pair", pin: $("pin").value.trim() });
  if (r.ok) {
    msg.className = "good";
    msg.textContent = "Paired.";
    $("pin").value = "";
    refresh();
  } else {
    msg.className = "err";
    // The vault's own words: "wrong PIN (2 attempts left)", "no pairing window
    // is open", "expired". Rewording them here would only lose information.
    msg.textContent = r.error || "pairing failed";
  }
});

$("pin").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("pairbtn").click();
});

$("unpairbtn").addEventListener("click", async () => {
  await send({ op: "unpair" });
  refresh();
});

refresh();
