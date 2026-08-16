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
//
// UI rules (this file's overlays):
//   * everything lives in SHADOW DOM hosts appended to <html>, never injected
//     into the page's own tree, so site CSS/layout is untouched;
//   * light/dark follows prefers-color-scheme;
//   * the menu is keyboard-first: arrows move, Enter picks, Escape closes;
//   * a small vault badge sits inside detected password fields - the standard
//     way back into the menu after it was dismissed;
//   * nothing secret is rendered: passwords stay masked bullets.

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

  // ---------------------------------------------------------------- theming
  function palette() {
    const dark = window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: dark)").matches;
    return dark ? {
      bg: "#1d2029", text: "#e8eaf1", muted: "#9aa1b2", border: "#333846",
      hover: "#2a3152", accent: "#7c90ff", shadow: "0 6px 18px rgba(0,0,0,.55)",
    } : {
      bg: "#ffffff", text: "#1c1e26", muted: "#5c6270", border: "#d8dbe4",
      hover: "#e3e8ff", accent: "#4f6bff", shadow: "0 6px 18px rgba(20,24,40,.22)",
    };
  }

  // A tiny inline padlock mark so both overlays are recognisably SecureVault
  // without needing web-accessible resources.
  function lockSvg(colour, size) {
    return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" ` +
      `xmlns="http://www.w3.org/2000/svg" aria-hidden="true">` +
      `<rect x="4.5" y="10" width="15" height="10" rx="2.5" stroke="${colour}" stroke-width="2"/>` +
      `<path d="M8 10V7a4 4 0 0 1 8 0v3" stroke="${colour}" stroke-width="2"/>` +
      `<circle cx="12" cy="15" r="1.6" fill="${colour}"/></svg>`;
  }

  // ---- floating menu (shadow-DOM host; keyboard-first; SPA-proof)
  //
  // Field defect (owner's laptop, quickopen.ai login - a React app): the menu
  // appeared for a second and vanished. Three causes, three rules:
  //   1. NEVER close on scroll - REPOSITION. Frameworks and autofocus scripts
  //      fire capture-phase scroll events on render; closing there kills the
  //      menu the instant it opens. Close only when the anchor truly went away.
  //   2. Survive re-renders: React REPLACES the input node, so the anchor
  //      reference goes stale. A watchdog re-resolves the anchor from
  //      document.activeElement instead of holding a dead node, and the
  //      outside-click handler never treats a login input as "outside".
  //   3. Update IN PLACE: re-offers for the same anchor reuse the host and
  //      just swap the rows - no remove/rebuild flicker - and an async
  //      sequence guard stops a slow older offer() from clobbering a newer one.
  let menuHost = null;
  let menuList = null;       // the row container inside the shadow root
  let menuAnchor = null;     // the field the menu belongs to
  let menuItems = [];        // [{action}] in render order
  let menuActive = -1;
  let menuRows = [];
  let menuWatch = null;      // re-anchor watchdog while open

  function closeMenu() {
    if (menuHost) { menuHost.remove(); menuHost = null; }
    if (menuWatch) { clearInterval(menuWatch); menuWatch = null; }
    menuList = null; menuAnchor = null;
    menuItems = []; menuRows = []; menuActive = -1;
  }

  function highlight(idx) {
    const p = palette();
    menuRows.forEach((row, i) => {
      row.style.background = i === idx ? p.hover : "transparent";
    });
    menuActive = idx;
    if (idx >= 0 && menuRows[idx]) menuRows[idx].scrollIntoView({ block: "nearest" });
  }

  function anchorAlive() {
    return menuAnchor && menuAnchor.isConnected &&
           menuAnchor.offsetParent !== null;
  }

  function reanchorOrClose() {
    if (anchorAlive()) { positionMenu(); return; }
    // React replaced the node: adopt the currently-focused login input
    const ae = document.activeElement;
    if (ae && ae.tagName === "INPUT" && (isPw(ae) || looksLikeUserField(ae))) {
      menuAnchor = ae;
      lastAnchor = ae;
      positionMenu();
      return;
    }
    closeMenu();
  }

  function positionMenu() {
    if (!menuHost || !anchorAlive()) return;
    const r = menuAnchor.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) { closeMenu(); return; }
    const width = Math.min(360, Math.max(r.width, 260));
    const estH = Math.min(320, 34 + menuItems.length * 36);
    let left = window.scrollX + r.left;
    const maxLeft = window.scrollX + document.documentElement.clientWidth - width - 6;
    left = Math.max(window.scrollX + 6, Math.min(left, maxLeft));
    let top = window.scrollY + r.bottom + 2;
    if (r.bottom + estH > window.innerHeight && r.top - estH > 0) {
      top = window.scrollY + r.top - estH - 2;
    }
    menuHost.style.left = left + "px";
    menuHost.style.top = top + "px";
    menuHost.style.width = width + "px";
  }

  function showMenu(anchor, items) {
    if (!items.length) { closeMenu(); return; }
    const p = palette();
    const sameAnchor = menuHost && (anchor === menuAnchor || !anchor.isConnected);
    if (!sameAnchor) {
      closeMenu();
      menuHost = document.createElement("div");
      menuHost.style.cssText = "position:absolute;z-index:2147483647";
      const root = menuHost.attachShadow({ mode: "closed" });
      root.innerHTML = `<style>
        .menu { background:${p.bg}; color:${p.text}; border:1px solid ${p.border};
                border-radius:8px; box-shadow:${p.shadow};
                font:13px system-ui,"Segoe UI",sans-serif; overflow:hidden;
                max-height:320px; display:flex; flex-direction:column; }
        .head { display:flex; align-items:center; gap:6px; padding:6px 10px;
                font-size:11px; font-weight:600; color:${p.muted};
                border-bottom:1px solid ${p.border}; flex:none; }
        .list { overflow-y:auto; }
        .row { padding:8px 10px; cursor:pointer; display:flex; gap:8px;
               align-items:baseline; min-width:0; }
        .row .main { font-weight:600; white-space:nowrap; overflow:hidden;
                     text-overflow:ellipsis; max-width:60%; flex:none; }
        .row .sub { color:${p.muted}; font-size:12px; white-space:nowrap;
                    overflow:hidden; text-overflow:ellipsis; min-width:0; }
        .row .only { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
      </style>`;
      const menu = document.createElement("div");
      menu.className = "menu";
      const head = document.createElement("div");
      head.className = "head";
      head.innerHTML = lockSvg(p.accent, 12) + "<span>SecureVault</span>";
      menu.appendChild(head);
      menuList = document.createElement("div");
      menuList.className = "list";
      menu.appendChild(menuList);
      root.appendChild(menu);
      document.documentElement.appendChild(menuHost);
      menuAnchor = anchor;
      menuWatch = setInterval(reanchorOrClose, 400);
    }
    // (re)fill the rows in place
    menuList.textContent = "";
    menuItems = items;
    menuRows = [];
    menuActive = -1;
    items.forEach((it, i) => {
      const row = document.createElement("div");
      row.className = "row";
      if (it.sub) {
        const main = document.createElement("span");
        main.className = "main"; main.textContent = it.label; main.title = it.label;
        const sub = document.createElement("span");
        sub.className = "sub"; sub.textContent = it.sub; sub.title = it.sub;
        row.append(main, sub);
      } else {
        const only = document.createElement("span");
        only.className = "only"; only.textContent = it.label; only.title = it.label;
        row.append(only);
      }
      row.addEventListener("mouseenter", () => highlight(i));
      row.addEventListener("mouseleave", () => highlight(-1));
      row.addEventListener("mousedown", (e) => { e.preventDefault(); closeMenu(); it.action(); });
      menuList.appendChild(row);
      menuRows.push(row);
    });
    positionMenu();
  }

  document.addEventListener("click", (e) => {
    if (!menuHost) return;
    if (e.composedPath().includes(menuHost)) return;      // inside the menu
    const t = e.target;
    // clicking a login input (the anchor, or its re-rendered replacement) is
    // not "outside" - focusin will re-offer for it
    if (t && t.tagName === "INPUT" && (isPw(t) || looksLikeUserField(t))) return;
    closeMenu();
  }, true);
  // scroll REPOSITIONS (rule 1); resize too
  window.addEventListener("scroll", () => positionMenu(), true);
  window.addEventListener("resize", () => positionMenu(), true);

  // Keyboard: arrows move, Enter picks, Escape closes. Capture phase so the
  // page doesn't see the keys we consume while our menu is open.
  document.addEventListener("keydown", (e) => {
    if (!menuHost) return;
    if (e.key === "Escape") { closeMenu(); e.preventDefault(); e.stopPropagation(); return; }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      const n = menuItems.length;
      const next = e.key === "ArrowDown"
        ? (menuActive + 1) % n
        : (menuActive - 1 + n) % n;
      highlight(next);
      e.preventDefault(); e.stopPropagation();
      return;
    }
    if (e.key === "Enter" && menuActive >= 0) {
      const it = menuItems[menuActive];
      closeMenu(); it.action();
      e.preventDefault(); e.stopPropagation();
    }
  }, true);

  // ---- in-field badge: the way back into the menu after dismissing it.
  // A shadow-DOM overlay positioned over the field's right edge - nothing is
  // injected into the field or its form, so site layout cannot break.
  const badges = new Map();   // field -> host element

  function badgeFor(field) {
    if (badges.has(field)) return badges.get(field);
    const host = document.createElement("div");
    const size = 18;
    host.style.cssText =
      "position:absolute;z-index:2147483646;width:18px;height:18px;" +
      "cursor:pointer;display:none";
    const root = host.attachShadow({ mode: "closed" });
    const p = palette();
    root.innerHTML =
      `<div style="width:18px;height:18px;opacity:.75" title="SecureVault: show saved logins">` +
      lockSvg(p.accent, size) + `</div>`;
    host.addEventListener("mousedown", (e) => {
      e.preventDefault(); e.stopPropagation();
      field.focus();
      offer(field);
    });
    document.documentElement.appendChild(host);
    badges.set(field, host);
    return host;
  }

  function positionBadges() {
    for (const [field, host] of badges) {
      if (!field.isConnected || field.offsetParent === null) {
        host.style.display = "none";
        if (!field.isConnected) { host.remove(); badges.delete(field); }
        continue;
      }
      const r = field.getBoundingClientRect();
      if (r.width < 60 || r.height < 16) { host.style.display = "none"; continue; }
      host.style.display = "block";
      host.style.left = (window.scrollX + r.right - 24) + "px";
      host.style.top = (window.scrollY + r.top + (r.height - 18) / 2) + "px";
    }
  }

  function ensureBadges() {
    document.querySelectorAll('input[type=password]').forEach((pw) => {
      if (pw.offsetParent !== null) badgeFor(pw);
    });
    positionBadges();
  }

  window.addEventListener("resize", positionBadges, true);
  window.addEventListener("scroll", positionBadges, true);
  setInterval(positionBadges, 1500);       // SPAs move things without events

  // ---- build and show the offer for whatever field was focused
  let lastAnchor = null;
  let offerSeq = 0;          // async guard: only the NEWEST offer may render
  async function offer(anchor) {
    lastAnchor = anchor;
    const seq = ++offerSeq;
    const pwField = pwFieldFor(anchor);
    const anchorIsUser = !isPw(anchor);
    if (!pwField && !anchorIsUser) return false; // nothing we can help with here
    const r = await call({ op: "query" });
    if (seq !== offerSeq) return false;          // a newer offer superseded us
    if (!r || !r.ok) {
      if (r && r.error) showMenu(anchor, [{ label: "SecureVault: " + r.error, action: () => {} }]);
      return false;
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
      if (seq !== offerSeq) return false;
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
    if (seq !== offerSeq) return false;
    showMenu(anchor, items);
    return items.length > 0;
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

  // "Fill on this page" from the popup: open the menu on the login form.
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg || msg.op !== "sv-fill") return false;
    const pws = Array.from(document.querySelectorAll('input[type=password]'))
      .filter((el) => el.offsetParent !== null);
    const target = pws[0] ||
      Array.from(document.querySelectorAll("input")).find(looksLikeUserField);
    if (!target) { sendResponse({ ok: false, error: "no login form on this page" }); return false; }
    target.focus();
    offer(target).then((shown) =>
      sendResponse(shown ? { ok: true } : { ok: false, error: "no saved logins for this site" }));
    return true;
  });

  // ---- auto-fill when the site has EXACTLY ONE saved login
  // No click needed for the common case. Skips signup/new-password forms and
  // never overwrites a value you've already typed. Multi-account sites still
  // use the focus menu so you choose which pair.
  let autoFilled = false;
  const visible = (el) => el && el.offsetParent !== null;

  async function autoFillSingle() {
    ensureBadges();
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

  // as the user types their email, re-narrow the open menu IN PLACE -
  // debounced, so a keystroke burst is one update, not a flicker per key
  let inputDeb = null;
  document.addEventListener("input", (e) => {
    if (!menuHost || !lastAnchor || !looksLikeUserField(e.target)) return;
    if (inputDeb) clearTimeout(inputDeb);
    const target = e.target;
    inputDeb = setTimeout(() => {
      inputDeb = null;
      // the anchor may have been re-rendered out from under us (React)
      offer(lastAnchor && lastAnchor.isConnected ? lastAnchor : target);
    }, 150);
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
    if (e.key === "Enter" && isPw(e.target) && e.target.value && !menuHost) {
      call({ op: "save", username: enteredIdentity(e.target), password: e.target.value });
    }
  }, true);
})();
