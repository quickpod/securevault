// SecureVault Autofill - background service worker (MV3).
//
// The ONLY component that talks to the native host. Content scripts message
// this worker; it relays to `com.securevault.autofill` (svhost.py -> named pipe
// -> the unlocked SecureVault app) and relays the reply back.
//
// REGISTRATION (see src/svauth.py for the vault half)
// Reaching the vault is not permission to read from it. This extension holds an
// ECDSA P-256 keypair whose PRIVATE HALF IS NON-EXTRACTABLE: it is generated
// inside the browser with extractable=false and kept as a CryptoKey handle in
// IndexedDB, so no code here - not this worker, not a content script, not a
// compromised page - can read the key material out. It can only ask the browser
// to sign with it.
//
// Pairing happens once: the user clicks "Pair a browser" in the SecureVault app,
// reads a 6-digit PIN off the app window, and types it into our popup. We send
// {pin, pubkey}; the vault records the public key and returns a client_id.
//
// After that, every request that touches a credential is a two-step exchange:
//   1. ask the vault for a challenge (32 random bytes, single use, 30s)
//   2. sign  client_id|op|nonce|origin  and send the signature with the request
// The vault refuses anything unsigned. Binding op and origin into the signed
// bytes means a captured signature cannot be replayed against another site or
// turned into a different operation.
//
// No passwords are stored here or in chrome.storage - they live only in the
// vault and pass through memory for the moment it takes to fill.

const HOST = "com.securevault.autofill";

// Ops that need a signature. Kept in sync with svauth.PRIVILEGED_OPS; the vault
// enforces it regardless, this list just decides when we bother to sign.
const PRIVILEGED = ["query", "identities", "save", "update", "generate"];

// ---------------------------------------------------------------- key storage
const DB_NAME = "securevault-auth";
const DB_STORE = "keys";
const KEY_ID = "client-keypair";

let dbPromise = null;

function openDb() {
  // One connection per worker lifetime. Opening a fresh one per call leaks
  // connections and, worse, a pending open blocks any future upgrade.
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      const rq = indexedDB.open(DB_NAME, 1);
      rq.onupgradeneeded = () => {
        if (!rq.result.objectStoreNames.contains(DB_STORE)) {
          rq.result.createObjectStore(DB_STORE);
        }
      };
      rq.onsuccess = () => resolve(rq.result);
      rq.onerror = () => { dbPromise = null; reject(rq.error); };
    });
  }
  return dbPromise;
}

function idbTx(mode, fn) {
  return openDb().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, mode);
    const rq = fn(tx.objectStore(DB_STORE));
    let result;
    rq.onsuccess = () => { result = rq.result; };
    // Resolve on the TRANSACTION, not the request. A request succeeds before
    // the transaction commits, so resolving there could report a stored
    // keypair that a worker shutdown then loses - leaving the vault holding a
    // registration this extension can no longer sign for, with no symptom
    // except autofill quietly failing until the user re-pairs.
    tx.oncomplete = () => resolve(result);
    tx.onabort = tx.onerror = () => reject(tx.error || rq.error);
  }));
}

// MV3 service workers are killed and restarted constantly, so nothing may be
// assumed to survive in memory; this cache is only an optimisation within one
// worker lifetime and IndexedDB is the real home.
let keyPairCache = null;

async function loadKeyPair() {
  if (keyPairCache) return keyPairCache;
  try {
    const stored = await idbTx("readonly", (s) => s.get(KEY_ID));
    if (stored && stored.privateKey) {
      keyPairCache = stored;
      return stored;
    }
  } catch (e) { /* fall through to generate */ }
  return null;
}

async function ensureKeyPair() {
  const existing = await loadKeyPair();
  if (existing) return existing;
  // extractable = false. Note this applies to the PRIVATE key only: WebCrypto
  // always marks a generated public key extractable, which is what lets us
  // export the SPKI below while the private half stays unreadable forever.
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  await idbTx("readwrite", (s) => s.put(pair, KEY_ID));
  keyPairCache = pair;
  return pair;
}

async function clearKeyPair() {
  keyPairCache = null;
  try { await idbTx("readwrite", (s) => s.delete(KEY_ID)); } catch (e) {}
}

// ------------------------------------------------------------------- encoding
function b64(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

// ---------------------------------------------------------------- client id
// Not a secret - it names which registration to check, and is useless without
// the private key - so chrome.storage.local is the right home for it.
async function getClientId() {
  const got = await chrome.storage.local.get("client_id");
  return got.client_id || "";
}

async function setClientId(id) {
  if (id) await chrome.storage.local.set({ client_id: id });
  else await chrome.storage.local.remove("client_id");
}

function browserLabel() {
  const ua = navigator.userAgent || "";
  const name = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : "Browser";
  const plat = /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : "";
  return plat ? `${name} on ${plat}` : name;
}

// ------------------------------------------------------------------ transport
function nativeCall(request) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(HOST, request, (reply) => {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: chrome.runtime.lastError.message ||
                    "SecureVault app is not running" });
        } else {
          resolve(reply || { ok: false, error: "no reply from host" });
        }
      });
    } catch (e) {
      resolve({ ok: false, error: String(e) });
    }
  });
}

// A revoked or forgotten pairing must not leave us retrying forever with a
// client_id the vault has never heard of: drop it so the popup offers pairing.
async function handleUnpaired(reply) {
  if (reply && reply.code === "unpaired") await setClientId("");
  return reply;
}

/** Challenge -> sign -> send. Any failure short-circuits without ever putting
 *  the request on the wire unsigned. */
async function signedCall(op, fields) {
  const clientId = await getClientId();
  if (!clientId) return { ok: false, code: "unpaired", error: "not paired with SecureVault" };
  const pair = await loadKeyPair();
  if (!pair) return { ok: false, code: "unpaired", error: "pairing key is missing" };

  const chal = await nativeCall({ op: "challenge", client_id: clientId });
  if (!chal.ok) return handleUnpaired(chal);

  const origin = fields.origin || "";
  const payload = new TextEncoder().encode(
    [clientId, op, chal.nonce, origin].join("|"));
  let sig;
  try {
    sig = b64(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, pair.privateKey, payload));
  } catch (e) {
    return { ok: false, error: "could not sign the request: " + String(e) };
  }
  return handleUnpaired(await nativeCall(
    Object.assign({ op, client_id: clientId, nonce: chal.nonce, sig }, fields)));
}

/** One-time pairing with the PIN shown in the SecureVault app window. */
async function pair(pin) {
  if (!/^\d{6}$/.test(String(pin || ""))) {
    return { ok: false, error: "enter the 6-digit PIN shown in SecureVault" };
  }
  let pair_;
  try {
    pair_ = await ensureKeyPair();
  } catch (e) {
    return { ok: false, error: "could not create a key: " + String(e) };
  }
  const spki = b64(await crypto.subtle.exportKey("spki", pair_.publicKey));
  const reply = await nativeCall({ op: "register", pin: String(pin),
                                   pubkey: spki, label: browserLabel() });
  if (reply.ok && reply.client_id) await setClientId(reply.client_id);
  return reply;
}

async function status() {
  const ping = await nativeCall({ op: "ping" });
  const clientId = await getClientId();
  const hasKey = !!(await loadKeyPair());
  return { ok: !!ping.ok, error: ping.error || "",
           serving: !!ping.serving, paired: !!(clientId && hasKey) };
}

// -------------------------------------------------------------------- routing
// Messages from content scripts and from the popup. `origin` is derived HERE
// from the sender, never trusted from the page, so a page cannot ask for
// another site's credentials - and since origin is inside the signed payload,
// it cannot be rewritten in flight either.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const op = msg && msg.op;

  if (op === "status") { status().then(sendResponse); return true; }
  if (op === "pair") { pair(msg.pin).then(sendResponse); return true; }
  if (op === "unpair") {
    // local only: forget our own key and id. The vault keeps its record until
    // the user revokes it there, which is the half that actually stops access.
    Promise.all([setClientId(""), clearKeyPair()])
      .then(() => sendResponse({ ok: true }));
    return true;
  }
  if (op === "ping") { nativeCall({ op: "ping" }).then(sendResponse); return true; }

  if (!PRIVILEGED.includes(op)) {
    sendResponse({ ok: false, error: "bad op" });
    return false;
  }

  const origin = sender && sender.origin ? sender.origin :
                 (sender && sender.url ? new URL(sender.url).origin : "");
  const fields = { origin };
  if (op === "generate") fields.length = msg.length || 24;
  if (op === "save" || op === "update") {
    fields.username = msg.username || "";
    fields.password = msg.password || "";
    fields.url = origin;
  }
  signedCall(op, fields).then(sendResponse);
  return true;   // async response
});
