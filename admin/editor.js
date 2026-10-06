/*
 * Alok Foundation — on-page editor for a static GitHub Pages site.
 *
 * There is no server: logging in unlocks a GitHub access key (admin/key.json, encrypted with the
 * admin username + password), and "Publish" commits the edited index.html (plus any new photos)
 * straight to the repository. GitHub Pages then rebuilds the live site in a minute or two.
 */
(function () {
  "use strict";
  const SESSION_KEY = "af-admin-token";
  const API = "https://api.github.com";
  /** Where the encrypted key lives. Read straight from GitHub so a new setup works instantly (no waiting for Pages). */
  const KEY_SOURCE = { owner: "alok-foundation", repos: ["alok-foundation.github.io", "alok-foundation-desktop"], branch: "main", path: "admin/key.json" };

  // ------------------------------------------------------------------ helpers
  const h = (tag, attrs = {}, ...children) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat()) if (c !== null && c !== undefined && c !== "") el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return el;
  };

  let toastTimer;
  function toast(message, kind = "ok", ms) {
    let el = document.getElementById("ae-toast");
    if (!el) document.body.append((el = h("div", { id: "ae-toast", role: "status" })));
    el.textContent = message;
    el.className = `show ${kind}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (el.className = ""), ms || (kind === "error" ? 7000 : 3500));
  }

  function dialog(title, body, actions, { dismissable = true } = {}) {
    const close = () => { backdrop.remove(); document.removeEventListener("keydown", onKey); };
    const backdrop = h("div", { class: "ae-backdrop", onclick: (e) => dismissable && e.target === backdrop && close() });
    const box = h("div", { class: "ae-dialog", role: "dialog", "aria-modal": "true", "aria-label": title },
      h("div", { class: "ae-dialog-head" }, h("h2", {}, title), dismissable ? h("button", { type: "button", class: "ae-x", "aria-label": "Close", onclick: close }, "✕") : ""),
      body,
      h("div", { class: "ae-dialog-actions" }, actions(close)));
    const onKey = (e) => { if (e.key === "Escape" && dismissable) close(); };
    document.addEventListener("keydown", onKey);
    backdrop.append(box);
    document.body.append(backdrop);
    setTimeout(() => box.querySelector("input, button.ae-btn-primary")?.focus(), 30);
    return close;
  }

  const b64 = {
    fromBytes(bytes) { let s = ""; const a = new Uint8Array(bytes); for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode(...a.subarray(i, i + 0x8000)); return btoa(s); },
    toBytes(str) { return Uint8Array.from(atob(str), (c) => c.charCodeAt(0)); },
  };

  // ----------------------------------------------------------- unlocking the key
  async function deriveKey(username, password, salt, iterations) {
    const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(`${username.trim().toLowerCase()}\n${password}`), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  }

  async function unlock(username, password) {
    // Newest key from GitHub first; fall back to the copy published with the site (e.g. if GitHub's API is busy).
    let box = null;
    const { owner, repos, branch, path } = KEY_SOURCE;
    for (const repo of repos) {
      if (box) break;
      try {
        const res = await fetch(`${API}/repos/${owner}/${repo}/contents/${path}?ref=${branch}&t=${Date.now()}`, { headers: { Accept: "application/vnd.github.raw" }, cache: "no-store" });
        if (res.ok) box = await res.json();
      } catch { /* offline or rate-limited — try the next place */ }
    }
    if (!box) {
      const res = await fetch(`admin/key.json?v=${Date.now()}`, { cache: "no-store" });
      if (!res.ok) throw new Error("The admin login isn't set up yet (run admin/setup.html).");
      box = await res.json();
    }
    const key = await deriveKey(username, password, b64.toBytes(box.salt), box.iterations);
    let plain;
    try {
      plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.toBytes(box.iv) }, key, b64.toBytes(box.data));
    } catch {
      throw new Error("Wrong username or password.");
    }
    const session = JSON.parse(new TextDecoder().decode(plain)); // { token, owner, repo, branch }
    const check = await fetch(`${API}/repos/${session.owner}/${session.repo}`, { headers: ghHeaders(session.token) });
    if (check.status === 401) throw new Error("The saved GitHub key has expired or was removed. Please set up the admin login again (admin/setup.html).");
    if (!check.ok) throw new Error("Couldn't reach GitHub. Please check your internet and try again.");
    // If the repository was renamed (e.g. to alok-foundation.github.io), GitHub tells us its current name.
    const info = await check.json();
    if (info.name) { session.repo = info.name; session.owner = info.owner?.login || session.owner; }
    return session;
  }

  // ----------------------------------------------------------------- GitHub API
  const ghHeaders = (token, extra = {}) => ({ Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", ...extra });
  async function gh(session, path, { method = "GET", body, accept } = {}) {
    const res = await fetch(`${API}/repos/${session.owner}/${session.repo}${path}`, {
      method,
      headers: ghHeaders(session.token, { ...(accept ? { Accept: accept } : {}), ...(body ? { "Content-Type": "application/json" } : {}) }),
      body: body ? JSON.stringify(body) : undefined,
      cache: "no-store",
    });
    if (res.status === 401) { sessionStorage.removeItem(SESSION_KEY); throw new Error("The GitHub key is no longer valid. Please log in again."); }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      const err = new Error(data.message || `GitHub error ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return accept === "application/vnd.github.raw" ? res.text() : res.json();
  }

  // --------------------------------------------------------------------- login
  function showLogin() {
    const err = h("p", { class: "ae-error", role: "alert", hidden: true });
    const form = h("form", { class: "ae-form", novalidate: true },
      h("label", { class: "ae-field" }, h("span", {}, "Username"), h("input", { name: "username", autocomplete: "off", autocapitalize: "none", spellcheck: "false" })),
      h("label", { class: "ae-field" }, h("span", {}, "Password"),
        h("span", { class: "ae-pass" },
          h("input", { name: "password", type: "password", autocomplete: "off", spellcheck: "false" }),
          h("button", { type: "button", class: "ae-eye", "aria-label": "Show password", onclick: (e) => { const i = form.password; i.type = i.type === "password" ? "text" : "password"; e.currentTarget.textContent = i.type === "password" ? "👁" : "🙈"; } }, "👁"))),
      err);
    let busy = false;
    const submit = async (close, btn) => {
      if (busy) return;
      const username = form.username.value.trim();
      const password = form.password.value;
      if (!username || !password) { err.textContent = "Please enter your username and password."; err.hidden = false; return; }
      busy = true; btn.disabled = true; btn.textContent = "Checking…"; err.hidden = true;
      try {
        const session = await unlock(username, password);
        sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
        close();
        startEditing(session);
      } catch (e) {
        err.textContent = e.message; err.hidden = false;
        btn.disabled = false; btn.textContent = "Log in";
      } finally {
        busy = false;
      }
    };
    dialog("Admin login", h("div", {}, h("p", { class: "ae-help" }, "Log in to edit texts, photos, buttons and contact details."), form), (close) => {
      const btn = h("button", { type: "submit", class: "ae-btn ae-btn-primary", onclick: () => submit(close, btn) }, "Log in");
      form.addEventListener("submit", (e) => { e.preventDefault(); submit(close, btn); });
      return [h("button", { type: "button", class: "ae-btn ae-btn-ghost", onclick: () => { close(); history.replaceState(null, "", location.pathname); } }, "Cancel"), btn];
    });
  }

  /** "Admin login" can be clicked again at any time (e.g. after closing the box). */
  window.__afOpenLogin = () => {
    if (document.body.classList.contains("ae-editing")) return toast("You're already logged in — edit away, then press Publish.");
    if (document.querySelector(".ae-backdrop")) return; // the login box is already open
    const saved = sessionStorage.getItem(SESSION_KEY);
    if (saved) { try { return startEditing(JSON.parse(saved)); } catch { sessionStorage.removeItem(SESSION_KEY); } }
    showLogin();
  };

  // ------------------------------------------------------------- photo helpers
  /** Shrinks a photo in the browser (JPEG, max side) so the website stays fast. */
  async function compress(file, maxSide = 1600) {
    if (!file.type.startsWith("image/")) throw new Error("Please choose a photo (JPG or PNG).");
    let bitmap;
    try { bitmap = await createImageBitmap(file); } catch { throw new Error("This photo format isn't supported. Please choose a JPG or PNG."); }
    const scale = Math.min(1, maxSide / Math.max(bitmap.width, bitmap.height));
    const canvas = h("canvas", { width: Math.round(bitmap.width * scale), height: Math.round(bitmap.height * scale) });
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#fff"; // transparent PNGs get white, not black
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    return new Promise((resolve, reject) => canvas.toBlob((b) => (b ? resolve(b) : reject(new Error("Could not process the photo."))), "image/jpeg", 0.82));
  }
  function pickFiles({ multiple = false } = {}) {
    return new Promise((resolve) => {
      const input = h("input", { type: "file", accept: "image/*", multiple });
      input.addEventListener("change", () => resolve([...input.files]));
      input.click();
    });
  }
  const newPhotoPath = () => `images/uploads/${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}.jpg`;

  // ============================================================== editing mode
  function startEditing(session) {
    if (document.body.classList.contains("ae-editing")) return;
    document.body.classList.add("ae-editing");

    /** Everything changed since the last publish. Nothing leaves this browser until "Publish". */
    const pending = { texts: {}, links: {}, images: {}, contact: null, gallery: null, photos: new Map() };
    const count = () => Object.keys(pending.texts).length + Object.keys(pending.links).length + Object.keys(pending.images).length + (pending.contact ? 1 : 0) + (pending.gallery ? 1 : 0);
    const changed = () => {
      const n = count();
      publishBtn.disabled = n === 0;
      publishBtn.textContent = n ? `🚀 Publish ${n} change${n === 1 ? "" : "s"}` : "No changes yet";
      discardBtn.hidden = n === 0;
    };
    window.addEventListener("beforeunload", (e) => { if (count()) { e.preventDefault(); e.returnValue = ""; } });

    /** Keeps a new photo in memory (preview via a blob: URL) until it is published to images/uploads/. */
    async function addPhoto(file, maxSide) {
      const blob = await compress(file, maxSide);
      const path = newPhotoPath();
      const url = URL.createObjectURL(blob);
      pending.photos.set(path, { blob, url });
      return { path, url };
    }

    // ---------------------------------------------------------------- photos
    const LABELS = {
      logo: "Logo", hero1: "Top photo 1", hero2: "Top photo 2", hero3: "Top photo 3", hero4: "Top photo 4", hero5: "Top photo 5",
      aboutWho: "Who We Are photo", aboutBelief: "Our Belief photo", aboutValues: "Core Values photo", aboutTeam: "Our Team photo", vision: "Vision photo",
    };
    const layer = h("div", { id: "ae-layer" });
    document.body.append(layer);
    const photoButtons = [];
    document.querySelectorAll("img[data-img]").forEach((img) => {
      const slot = img.getAttribute("data-img");
      const btn = h("button", { type: "button", class: "ae-photo-btn", title: `Change ${LABELS[slot] || "photo"}` }, "📷 Change photo");
      btn.addEventListener("click", async (e) => {
        e.preventDefault(); e.stopPropagation();
        const [file] = await pickFiles();
        if (!file) return;
        try {
          const { path, url } = await addPhoto(file, slot === "logo" ? 600 : 1600);
          pending.images[slot] = path;
          document.querySelectorAll(`img[data-img="${slot}"]`).forEach((el) => (el.src = url));
          toast(`${LABELS[slot] || "Photo"} changed — press Publish to make it live.`);
          changed();
        } catch (err) { toast(err.message, "error"); }
      });
      const group = h("div", { class: "ae-photo-group" }, btn);
      layer.append(group);
      photoButtons.push({ img, group });
    });
    (function place() {
      for (const { img, group } of photoButtons) {
        const r = img.getBoundingClientRect();
        const visible = r.width > 30 && r.height > 30 && r.bottom > 0 && r.top < innerHeight;
        group.style.display = visible ? "flex" : "none";
        if (!visible) continue;
        group.classList.toggle("ae-small", r.width < 120);
        group.style.left = `${Math.round(r.left + 8)}px`;
        group.style.top = `${Math.round(r.top + 8)}px`;
      }
      requestAnimationFrame(place);
    })();

    // ----------------------------------------------------------------- texts
    const supportsPlain = (() => { const d = document.createElement("div"); d.contentEditable = "plaintext-only"; return d.contentEditable === "plaintext-only"; })();
    document.querySelectorAll("[data-edit]").forEach((el) => {
      const key = el.getAttribute("data-edit");
      el.contentEditable = supportsPlain ? "plaintext-only" : "true";
      el.classList.add("ae-editable");
      el.title = "Tap to edit this text";
      let before = "";
      el.addEventListener("focus", () => (before = el.innerText));
      el.addEventListener("keydown", (e) => {
        if (e.key === "Enter") { e.preventDefault(); el.blur(); }
        if (e.key === "Escape") { el.innerText = before; el.blur(); }
      });
      el.addEventListener("paste", (e) => { e.preventDefault(); document.execCommand("insertText", false, (e.clipboardData || window.clipboardData).getData("text/plain")); });
      el.addEventListener("blur", () => {
        const value = el.innerText.replace(/\s+/g, " ").trim();
        if (value === before.replace(/\s+/g, " ").trim()) return;
        if (!value) { el.innerText = before; toast("Text can't be empty — change undone.", "error"); return; }
        el.innerText = value;
        pending.texts[key] = value;
        changed();
      });
    });

    // --------------------------------------------------------------- buttons
    const isLink = (v) => /^https?:\/\/\S+$/i.test(v) || /^(mailto|tel):\S+$/i.test(v) || /^#[A-Za-z][\w-]*$/.test(v);
    function linkDialog(el) {
      const key = el.getAttribute("data-link");
      const form = h("form", { class: "ae-form", novalidate: true },
        h("label", { class: "ae-field" }, h("span", {}, "Button text"), h("input", { name: "label", value: el.textContent.trim(), maxlength: "60" })),
        h("label", { class: "ae-field" }, h("span", {}, "Link"), h("input", { name: "url", value: el.getAttribute("href"), type: "url", placeholder: "https://forms.gle/…" }),
          h("small", {}, "Paste any link — a Google Form (https://forms.gle/…), WhatsApp (https://wa.me/91…), or #contacts to jump to a section of this page.")));
      form.addEventListener("submit", (e) => e.preventDefault());
      dialog("Edit button", form, (close) => [
        h("button", { type: "button", class: "ae-btn ae-btn-ghost", onclick: close }, "Cancel"),
        h("button", {
          type: "button", class: "ae-btn ae-btn-primary",
          onclick: () => {
            const label = form.label.value.trim();
            let url = form.url.value.trim();
            if (url && !/^(https?:|mailto:|tel:|#)/i.test(url)) url = `https://${url}`; // "forms.gle/…" pasted without https://
            if (!label) return toast("Please enter the button text.", "error");
            if (!isLink(url)) return toast("Please enter a full link, e.g. https://forms.gle/…", "error");
            pending.links[key] = { label, url };
            el.textContent = label;
            el.setAttribute("href", url);
            changed();
            close();
          },
        }, "Done"),
      ]);
    }
    document.querySelectorAll("[data-link]").forEach((el) => {
      el.classList.add("ae-link-editable");
      el.title = "Tap to change this button's text and link";
      el.addEventListener("click", (e) => { e.preventDefault(); linkDialog(el); });
    });

    // --------------------------------------------------------- contact & map
    const digits = (v) => String(v || "").replace(/[^\d+]/g, "");
    const mapsEmbed = (a) => `https://maps.google.com/maps?q=${encodeURIComponent(a)}&z=15&output=embed`;
    const currentContact = () => {
      const wa = document.querySelector("[data-show=whatsapp]");
      const map = document.querySelector("[data-map]");
      return {
        phone: document.querySelector("[data-text=phone]")?.textContent.trim() || "",
        email: document.querySelector("[data-text=email]")?.textContent.trim() || "",
        whatsapp: wa && !wa.hidden ? (document.querySelector("[data-href=whatsapp]")?.getAttribute("href") || "").replace("https://wa.me/", "+") : "",
        address: decodeURIComponent((map?.getAttribute("src") || "").match(/[?&]q=([^&]+)/)?.[1] || "").replace(/\+/g, " "),
      };
    };
    /** Applies contact details to any document — the live page (preview) or the copy being published. */
    function applyContact(doc, c) {
      doc.querySelectorAll("[data-text=phone]").forEach((el) => (el.textContent = c.phone));
      doc.querySelectorAll("[data-text=email]").forEach((el) => (el.textContent = c.email));
      doc.querySelectorAll("[data-href=tel]").forEach((el) => el.setAttribute("href", `tel:${digits(c.phone)}`));
      doc.querySelectorAll("[data-href=mailto]").forEach((el) => el.setAttribute("href", `mailto:${c.email}`));
      doc.querySelectorAll("[data-href=whatsapp]").forEach((el) => el.setAttribute("href", `https://wa.me/${digits(c.whatsapp).replace(/^\+/, "")}`));
      doc.querySelectorAll("[data-show=whatsapp]").forEach((el) => (el.hidden = !c.whatsapp));
      doc.querySelectorAll("[data-map]").forEach((el) => { el.setAttribute("src", mapsEmbed(c.address)); el.setAttribute("title", `Map: ${c.address}`); });
      doc.querySelectorAll("[data-text=address]").forEach((el) => (el.textContent = c.address));
    }
    function contactDialog() {
      const c = pending.contact || currentContact();
      const field = (key, label, hint, type = "text") =>
        h("label", { class: "ae-field" }, h("span", {}, label), h("input", { name: key, type, value: c[key] || "", autocomplete: "off" }), hint ? h("small", {}, hint) : "");
      const form = h("form", { class: "ae-form", novalidate: true },
        field("phone", "Phone number", "Shown on the website and used for the call button.", "tel"),
        field("email", "Email", "", "email"),
        field("whatsapp", "WhatsApp number", "Leave empty to hide the WhatsApp link.", "tel"),
        field("address", "Address (also used for the map)", "Shown in the Contact section; the map points here."));
      const preview = h("iframe", { class: "ae-map-preview", title: "Map preview", loading: "lazy", src: mapsEmbed(c.address || "New Delhi") });
      form.address.addEventListener("change", () => (preview.src = mapsEmbed(form.address.value)));
      dialog("Edit contact & map", h("div", {}, form, preview), (close) => [
        h("button", { type: "button", class: "ae-btn ae-btn-ghost", onclick: close }, "Cancel"),
        h("button", {
          type: "button", class: "ae-btn ae-btn-primary",
          onclick: () => {
            const next = { phone: form.phone.value.trim(), email: form.email.value.trim(), whatsapp: form.whatsapp.value.trim(), address: form.address.value.trim() };
            if (digits(next.phone).replace("+", "").length < 7) return toast("Please enter a valid phone number.", "error");
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(next.email)) return toast("Please enter a valid email address.", "error");
            if (next.whatsapp && digits(next.whatsapp).replace("+", "").length < 7) return toast("Please enter a valid WhatsApp number (or leave it empty).", "error");
            if (!next.address) return toast("Please enter the map location.", "error");
            pending.contact = next;
            applyContact(document, next);
            changed();
            close();
          },
        }, "Done"),
      ]);
    }

    // --------------------------------------------------------------- gallery
    const galleryNow = () => [...document.querySelectorAll("[data-gallery] img:not([aria-hidden])")].map((img) => ({ path: img.getAttribute("src") }));
    function renderGallery(doc, items, srcOf) {
      const track = doc.querySelector("[data-gallery]");
      track.replaceChildren();
      for (const copy of [false, true]) {
        items.forEach((item, i) => {
          const img = doc.createElement("img");
          img.setAttribute("src", srcOf(item));
          img.setAttribute("alt", copy ? "" : `Photo ${i + 1} from Alok Foundation`);
          if (copy) img.setAttribute("aria-hidden", "true");
          img.setAttribute("loading", "lazy");
          track.append(img);
        });
      }
    }
    function galleryDialog() {
      let list = (pending.gallery || galleryNow()).map((x) => ({ ...x }));
      const grid = h("div", { class: "ae-gallery" });
      const render = () => grid.replaceChildren(
        ...list.map((item, i) => h("figure", { class: "ae-thumb" },
          h("img", { src: item.url || item.path, alt: `Gallery photo ${i + 1}` }),
          h("figcaption", {},
            h("button", { type: "button", "aria-label": "Move left", disabled: i === 0, onclick: () => { [list[i - 1], list[i]] = [list[i], list[i - 1]]; render(); } }, "←"),
            h("button", { type: "button", "aria-label": "Move right", disabled: i === list.length - 1, onclick: () => { [list[i + 1], list[i]] = [list[i], list[i + 1]]; render(); } }, "→"),
            h("button", { type: "button", class: "ae-del", "aria-label": "Remove", disabled: list.length === 1, onclick: () => { list.splice(i, 1); render(); } }, "✕")))),
        h("button", {
          type: "button", class: "ae-add",
          onclick: async (e) => {
            const btn = e.currentTarget;
            const files = await pickFiles({ multiple: true });
            if (!files.length) return;
            btn.disabled = true;
            try {
              for (const [n, file] of files.entries()) {
                btn.textContent = `Preparing ${n + 1} of ${files.length}…`;
                const { path, url } = await addPhoto(file, 1400);
                list.push({ path, url });
              }
            } catch (err) { toast(err.message, "error"); }
            render();
          },
        }, "＋ Add photos"));
      render();
      dialog("Gallery photos", h("div", {}, h("p", { class: "ae-help" }, "These photos scroll across the Gallery section. Add, remove or reorder them."), grid), (close) => [
        h("button", { type: "button", class: "ae-btn ae-btn-ghost", onclick: close }, "Cancel"),
        h("button", {
          type: "button", class: "ae-btn ae-btn-primary",
          onclick: () => {
            pending.gallery = list;
            renderGallery(document, list, (x) => x.url || x.path);
            window.__afGallery?.(); // rebuild the endless loop with the new photos
            changed();
            close();
          },
        }, "Done"),
      ]);
    }

    // --------------------------------------------------------------- publish
    /** Applies every pending change to a clean copy of index.html from GitHub, then commits it with the new photos. */
    async function publish() {
      if (!count()) return;
      const n = count();
      publishBtn.disabled = true;
      publishBtn.textContent = "Publishing…";
      try {
        for (let attempt = 1; ; attempt++) {
          try {
            await commitChanges(n);
            break;
          } catch (err) {
            // Someone else published at the same moment: retry once on top of their version.
            if (err.status === 422 && attempt === 1) continue;
            throw err;
          }
        }
        pendingReset();
        toast("Published ✓ GitHub is updating the live website — usually 1–2 minutes.", "ok", 9000);
        watchLive();
      } catch (err) {
        toast(`Couldn't publish: ${err.message}`, "error");
        changed();
      }
    }

    let liveVersion = null;
    async function commitChanges(n) {
      const branch = session.branch || "main";
      const ref = await gh(session, `/git/ref/heads/${encodeURIComponent(branch)}`);
      const base = await gh(session, `/git/commits/${ref.object.sha}`);
      const source = await gh(session, `/contents/index.html?ref=${encodeURIComponent(branch)}`, { accept: "application/vnd.github.raw" });

      const doc = new DOMParser().parseFromString(source, "text/html");
      for (const [key, value] of Object.entries(pending.texts)) doc.querySelectorAll(`[data-edit="${key}"]`).forEach((el) => (el.textContent = value));
      for (const [key, { label, url }] of Object.entries(pending.links)) {
        doc.querySelectorAll(`[data-link="${key}"]`).forEach((el) => {
          el.textContent = label;
          el.setAttribute("href", url);
          if (/^https?:/i.test(url)) { el.setAttribute("target", "_blank"); el.setAttribute("rel", "noopener"); }
          else { el.removeAttribute("target"); el.removeAttribute("rel"); }
        });
      }
      for (const [slot, path] of Object.entries(pending.images)) {
        doc.querySelectorAll(`[data-img="${slot}"]`).forEach((el) => el.setAttribute("src", path));
        if (slot === "logo") doc.querySelectorAll("[data-img-href=logo]").forEach((el) => el.setAttribute("href", path));
      }
      if (pending.contact) applyContact(doc, pending.contact);
      if (pending.gallery) renderGallery(doc, pending.gallery, (x) => x.path);
      const version = new Date().toISOString();
      doc.querySelector('meta[name="site-version"]')?.setAttribute("content", version);
      const html = `<!DOCTYPE html>\n${doc.documentElement.outerHTML}\n`;

      // New photos that are actually used, plus old uploads nothing refers to any more (removed to keep the repo small).
      const used = new Set([...doc.querySelectorAll("img[src], link[href]")].map((el) => el.getAttribute("src") || el.getAttribute("href")));
      const tree = [];
      for (const [path, { blob }] of pending.photos) {
        if (!used.has(path)) continue;
        const { sha } = await gh(session, "/git/blobs", { method: "POST", body: { content: b64.fromBytes(await blob.arrayBuffer()), encoding: "base64" } });
        tree.push({ path, mode: "100644", type: "blob", sha });
      }
      const { tree: existing } = await gh(session, `/git/trees/${base.tree.sha}?recursive=1`);
      for (const item of existing) {
        if (item.type === "blob" && item.path.startsWith("images/uploads/") && !used.has(item.path)) tree.push({ path: item.path, mode: "100644", type: "blob", sha: null });
      }
      const page = await gh(session, "/git/blobs", { method: "POST", body: { content: html, encoding: "utf-8" } });
      tree.push({ path: "index.html", mode: "100644", type: "blob", sha: page.sha });

      const newTree = await gh(session, "/git/trees", { method: "POST", body: { base_tree: base.tree.sha, tree } });
      const commit = await gh(session, "/git/commits", { method: "POST", body: { message: `Website edit: ${n} change${n === 1 ? "" : "s"} (admin editor)`, tree: newTree.sha, parents: [ref.object.sha] } });
      await gh(session, `/git/refs/heads/${encodeURIComponent(branch)}`, { method: "PATCH", body: { sha: commit.sha, force: false } });
      liveVersion = version;
      return commit.sha;
    }

    function pendingReset() {
      pending.texts = {}; pending.links = {}; pending.images = {}; pending.contact = null; pending.gallery = null;
      pending.photos = new Map(); // blob: previews stay visible on this page; the published files take over after a reload
      changed();
    }

    /** Polls the public page until GitHub Pages serves the version we just published. */
    async function watchLive() {
      const expected = liveVersion;
      status.textContent = "⏳ Updating the live website…";
      const started = Date.now();
      while (Date.now() - started < 10 * 60_000) {
        await new Promise((r) => setTimeout(r, 10_000));
        if (liveVersion !== expected) return; // a newer publish took over
        try {
          const text = await (await fetch(`${location.pathname}?check=${Date.now()}`, { cache: "no-store" })).text();
          if (text.includes(`content="${expected}"`)) {
            status.textContent = "✅ Live";
            toast("Your changes are now live on the website ✓", "ok", 8000);
            return;
          }
        } catch { /* offline for a moment — keep waiting */ }
      }
      status.textContent = "⏳ Still updating — check again in a few minutes";
    }

    // ------------------------------------------------------------- admin bar
    const status = h("span", { class: "ae-status" });
    const publishBtn = h("button", { type: "button", class: "ae-publish", onclick: publish, disabled: true }, "No changes yet");
    const discardBtn = h("button", { type: "button", class: "ae-ghost", hidden: true, onclick: () => { pendingReset(); location.reload(); } }, "Discard");
    const logout = () => { pendingReset(); sessionStorage.removeItem(SESSION_KEY); location.replace(location.pathname); };
    const bar = h("div", { id: "ae-bar" },
      h("span", { class: "ae-bar-title" }, "✏️ Editing mode ", status),
      h("div", { class: "ae-bar-actions" },
        h("button", { type: "button", onclick: contactDialog }, "📞 Contact & map"),
        h("button", { type: "button", onclick: galleryDialog }, "🖼️ Gallery"),
        discardBtn,
        publishBtn,
        h("button", { type: "button", class: "ae-ghost", onclick: logout }, "Log out")));
    document.body.append(bar);

    document.querySelector(".footer-grid")?.before(h("div", { class: "container ae-inline-wrap" }, h("button", { type: "button", class: "ae-inline-btn", onclick: contactDialog }, "✏️ Edit contact & map")));
    document.querySelector("#gallery .section-title")?.after(h("div", { class: "ae-inline-wrap ae-center" }, h("button", { type: "button", class: "ae-inline-btn", onclick: galleryDialog }, "✏️ Edit gallery photos")));

    toast("Editing mode: tap any text, photo or button to change it, then press Publish.", "ok", 6000);
  }

  // --------------------------------------------------------------------- start
  window.__afOpenLogin();
})();
