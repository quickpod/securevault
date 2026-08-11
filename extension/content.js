// SecureVault Autofill - content script.
//
// Detects login and signup fields, offers matching credentials from the vault
// as USERNAME/PASSWORD PAIRS, suggests a generated password on signup, and on
// submit asks the vault to save (new) or update (changed) the credential. The
// save/update CONFIRMATION happens in the SecureVault app window, not here.
//
// Pairing rule: a stored login is an (email/username, password) pair. When the
// login field already holds an email/username - typed, chosen from our menu, or
// carried over on a two-step "enter email, then password" page - the menu is
// narrowed to the pair(s) for THAT identity, so you are never offered another
// account's password. With no identity present yet, every pair for the site is
// offered and picking one fills both halves together.

(function () {
  "use strict";
  if (window.__securevaultLoaded) return;
  window.__securevaultLoaded = true;

  const call = (msg) => new Promise((res) => {
    try { chrome.runtime.sendMessage(msg, (r) => res(r || { ok: false })); }
    catch (e) { res({ ok: false, error: String(e) }); }
  });

  const isPw = (el) => el && el.tagName === "INPUT" && el.type === "password";
  const isTextLike = (el) => el && el.tagName === "INPUT" &&
    ["text", "email", "tel", ""].includes((el.type || "").toLowerCase());

  function scopeOf(field) { return field.form || document; }
  function inputsIn(field) { return Array.from(scopeOf(field).querySelectorAll("input")); }

  // Does this input look like it names an account? Used for READING an identity
  // even when it is hidden/readonly (common on two-step and "confirm it's you"
  // password pages, where the email is shown but not editable).
  function looksLikeUserField(el) {
    if (!el || el.tagName !== "INPUT") return false;
    const t = (el.type || "").toLowerCase();
    if (t === "password" || t === "hidden" && !el.value) return false;
    const hay = [(el.getAttribute("autocomplete") || ""), el.name || "",
                 el.id || "", el.getAttribute("aria-label") || "",
                 el.placeholder || ""].join(" ").toLowerCase();
    if (/user|email|login|account|e-mail|phone/.test(hay)) return true;
    if (t === "email") return true;
    return false;
  }

  // The password field associated with an arbitrary anchor field.
  function pwFieldFor(anchor) {
    if (isPw(anchor)) return anchor;
    const ins = inputsIn(anchor), i = ins.indexOf(anchor);
    for (let k = i + 1; k < ins.length; k++) if (isPw(ins[k])) return ins[k];
    for (const el of ins) if (isPw(el)) return el;
    return null;
  }

  // The EDITABLE, visible username field we should fill (may differ from the
  // one we read the identity from, which can be readonly/hidden).
  function fillableUserField(pwField) {
    const ins = inputsIn(pwField), idx = ins.indexOf(pwField);
    const editable = (el) => el && !el.disabled && !el.readOnly &&
      (el.offsetParent !== null || el.type === "hidden") && isTextLike(el);
    for (let k = idx - 1; k >= 0; k--) if (editable(ins[k])) return ins[k];
    for (const el of ins) if (editable(el)) return el;
    return null;
  }

  // The identity currently present, from any account-naming input with a value
  // (editable or not). This is what we filter pairs by.
  function enteredIdentity(pwField) {
    const ins = inputsIn(pwField);
    for (const el of ins) {
      if (looksLikeUserField(el) && el.value && el.value.trim())
        return el.value.trim();
    }
    // fall back to the nearest preceding text field with a value
    const idx = ins.indexOf(pwField);
    for (let k = idx - 1; k >= 0; k--) {
      if (isTextLike(ins[k]) && ins[k].value && ins[k].value.trim())
        return ins[k].value.trim();
    }
    return "";
  }

  // Narrow logins to the entered identity: exact match wins; else prefix match
  // (so a half-typed email still filters); else, only if nothing matched, show
  // all so the user is not left with an empty menu.
  function narrow(logins, identity) {
    if (!identity) return logins;
    const id = identity.toLowerCase();
    const exact = logins.filter((l) => (l.username || "").toLowerCase() === id);
    if (exact.length) return exact;
    const pref = logins.filter((l) => (l.username || "").toLowerCase().startsWith(id));
    return pref.length ? pref : logins;
  }

  function setValue(el, val) {
    const proto = Object.getPrototypeOf(el);
    const setter = Object.getOwnPropertyDescriptor(proto, "value");
    if (setter && setter.set) setter.set.call(el, val); else el.value = val;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function fillPair(pwField, login) {
    const uField = fillableUserField(pwField);
    if (uField && login.username) setValue(uField, login.username);
    if (login.password) setValue(pwField, login.password);
  }

  // ---- floating menu
  let menuEl = null;
  function closeMenu() { if (menuEl) { menuEl.remove(); menuEl = null; } }
  function showMenu(anchor, items) {
    closeMenu();
    if (!items.length) return;
    const r = anchor.getBoundingClientRect();
    menuEl = document.createElement("div");
    menuEl.style.cssText = [
      "position:absolute", "z-index:2147483647",
      `left:${window.scrollX + r.left}px`, `top:${window.scrollY + r.bottom + 2}px`,
      `min-width:${Math.max(r.width, 240)}px`, "background:#fff", "color:#111",
      "border:1px solid #888", "border-radius:6px", "box-shadow:0 4px 14px rgba(0,0,0,.25)",
      "font:13px system-ui,Segoe UI,sans-serif", "overflow:hidden", "max-height:320px", "overflow-y:auto"
    ].join(";");
    for (const it of items) {
      const row = document.createElement("div");
      row.style.cssText = "padding:8px 10px;cursor:pointer;white-space:nowrap;display:flex;gap:8px;align-items:center";
      if (it.sub) {
        const main = document.createElement("span"); main.textContent = it.label; main.style.fontWeight = "600";
        const sub = document.createElement("span"); sub.textContent = it.sub; sub.style.color = "#666"; sub.style.fontSize = "12px";
        row.append(main, sub);
      } else {
        row.textContent = it.label;
      }
      row.addEventListener("mouseenter", () => row.style.background = "#eef");
      row.addEventListener("mouseleave", () => row.style.background = "#fff");
      row.addEventListener("mousedown", (e) => { e.preventDefault(); closeMenu(); it.action(); });
      menuEl.appendChild(row);
    }
    document.body.appendChild(menuEl);
  }
  document.addEventListener("click", (e) => { if (menuEl && !menuEl.contains(e.target)) closeMenu(); }, true);
  window.addEventListener("scroll", closeMenu, true);

  // ---- build and show the offer for whatever field was focused
  let lastAnchor = null;
  async function offer(anchor) {
    lastAnchor = anchor;
    const pwField = pwFieldFor(anchor);
    const anchorIsUser = !isPw(anchor);
    if (!pwField && !anchorIsUser) return;   // nothing we can help with here
    const r = await call({ op: "query" });
    if (!r || !r.ok) {
      if (r && r.error) showMenu(anchor, [{ label: "SecureVault: " + r.error, action: () => {} }]);
      return;
    }
    const refField = pwField || anchor;       // for scope + identity reading
    const identity = enteredIdentity(refField);
    const matches = narrow(r.logins || [], identity);
    const items = matches.map((l) => ({
      label: l.username || "(no username)",
      sub: pwField ? ("•••••••• — " + (l.title || "")) : (l.title || ""),
      action: () => { if (pwField) fillPair(pwField, l); else setValue(anchor, l.username || ""); }
    }));

    // When a USERNAME/EMAIL field is focused, also offer the identities you use
    // elsewhere, so you can fill an email even on a site with no saved login
    // (e.g. a new signup). These fill only the username field, not a password.
    if (anchorIsUser) {
      const idr = await call({ op: "identities" });
      if (idr && idr.ok) {
        const shown = new Set(matches.map((m) => (m.username || "").toLowerCase()));
        const typed = (anchor.value || "").trim().toLowerCase();
        const known = [...(idr.emails || []), ...(idr.usernames || [])];
        for (const who of known) {
          const lw = who.toLowerCase();
          if (shown.has(lw)) continue;                 // already offered as a pair
          if (typed && !lw.startsWith(typed)) continue; // narrow as they type
          shown.add(lw);
          items.push({ label: who, sub: "use this " + (who.includes("@") ? "email" : "username"),
                       action: () => setValue(anchor, who) });
        }
      }
    }

    if (pwField && looksLikeSignup(pwField)) {
      items.unshift({
        label: "Suggest a strong password", sub: "generate",
        action: async () => {
          const g = await call({ op: "generate", length: 24 });
          if (g && g.ok) scopeOf(pwField).querySelectorAll('input[type=password]')
            .forEach((p) => setValue(p, g.password));
        }
      });
    }
    showMenu(anchor, items);
  }

  function looksLikeSignup(pwField) {
    const a = (pwField.getAttribute("autocomplete") || "").toLowerCase();
    if (a.includes("new-password")) return true;
    return scopeOf(pwField).querySelectorAll('input[type=password]').length >= 2;
  }

  document.addEventListener("focusin", (e) => {
    const el = e.target;
    if (isPw(el) || looksLikeUserField(el)) offer(el);
  }, true);

  // ---- auto-fill when the site has EXACTLY ONE saved login
  // No click needed for the common case. Skips signup/new-password forms and
  // never overwrites a value you've already typed. Multi-account sites still
  // use the focus menu so you choose which pair.
  let autoFilled = false;
  const visible = (el) => el && el.offsetParent !== null;

  async function autoFillSingle() {
    if (autoFilled) return;
    const pws = Array.from(document.querySelectorAll('input[type=password]')).filter(visible);
    if (pws.length !== 1) return;          // a login form has one password field
    const pw = pws[0];
    if (looksLikeSignup(pw)) return;       // don't put a saved password in a signup field
    const r = await call({ op: "query" });
    if (!r || !r.ok) return;
    const logins = r.logins || [];
    if (logins.length !== 1) return;       // only auto-fill the unambiguous case
    const login = logins[0];
    const uField = fillableUserField(pw);
    if (uField && !uField.value && login.username) setValue(uField, login.username);
    if (!pw.value) setValue(pw, login.password);
    autoFilled = true;
  }

  autoFillSingle();
  // watch for late-rendered / SPA login forms, then stop after a while
  const _obs = new MutationObserver(() => { autoFillSingle(); });
  try { _obs.observe(document.documentElement, { childList: true, subtree: true }); } catch (e) {}
  setTimeout(() => { try { _obs.disconnect(); } catch (e) {} }, 15000);

  // as the user types their email, re-narrow the open menu in place
  document.addEventListener("input", (e) => {
    if (menuEl && lastAnchor && looksLikeUserField(e.target)) offer(lastAnchor);
  }, true);

  // ---- on submit, report the credential so the app can offer save/update
  function captureFrom(form) {
    const pw = form.querySelector('input[type=password]');
    if (!pw || !pw.value) return null;
    return { username: (enteredIdentity(pw) || ""), password: pw.value };
  }
  document.addEventListener("submit", (e) => {
    const cap = captureFrom(e.target);
    if (cap) call({ op: "save", username: cap.username, password: cap.password });
  }, true);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && isPw(e.target) && e.target.value) {
      call({ op: "save", username: enteredIdentity(e.target), password: e.target.value });
    }
  }, true);
})();
