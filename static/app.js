// SecureVault browser-side helpers (no inline scripts, so the strict CSP stays intact)
document.addEventListener("DOMContentLoaded", () => {

  // ---- Copy buttons ----
  document.querySelectorAll("[data-copy]").forEach(btn => {
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(btn.dataset.copy);
        const old = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(() => (btn.textContent = old), 1200);
      } catch (e) { /* clipboard blocked: ignore */ }
    });
  });

  // ---- Confirm dialogs ----
  document.querySelectorAll("form[data-confirm]").forEach(f => {
    f.addEventListener("submit", e => { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });

  // ---- Busy state on long uploads ----
  document.querySelectorAll("form[data-busy]").forEach(f => {
    f.addEventListener("submit", () => {
      const b = f.querySelector("button[type=submit]");
      if (b) { b.disabled = true; b.textContent = f.dataset.busy; }
    });
  });

  // ---- Show chosen file name ----
  document.querySelectorAll("input[type=file][data-filename]").forEach(inp => {
    inp.addEventListener("change", () => {
      const drop = inp.closest(".drop");
      const label = drop && drop.querySelector("[data-filename-label]");
      const f = inp.files[0];
      if (drop) drop.classList.toggle("has-file", !!f);
      if (label && f) label.textContent = `${f.name} · ${(f.size / 1048576).toFixed(2)} MB`;
    });
  });

  // ---- SHA-256 in the browser (Web Crypto) ----
  // The server hashes the file independently; if both match, the upload
  // was not altered between the browser and the server.
  const toHex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  document.querySelectorAll("input[type=file][data-hash]").forEach(inp => {
    inp.addEventListener("change", async () => {
      const form = inp.form;
      const hidden = form.querySelector("[data-client-hash]");
      const out = form.querySelector("[data-client-hash-label]");
      const btn = form.querySelector("button[type=submit]");
      hidden.value = "";
      const f = inp.files[0];
      if (!f || !(window.crypto && crypto.subtle)) return;
      if (f.size > 500 * 1048576) return;
      out.hidden = false;
      out.textContent = "Computing SHA-256 in your browser…";
      btn.disabled = true;
      try {
        const digest = toHex(await crypto.subtle.digest("SHA-256", await f.arrayBuffer()));
        hidden.value = digest;
        out.textContent = "Browser SHA-256: " + digest;
      } catch (e) {
        out.textContent = "Browser hashing unavailable; the server will still hash the file.";
      } finally {
        btn.disabled = false;
      }
    });
  });

  // ---- Tabs ----
  const tabs = document.querySelectorAll("[data-tab]");
  tabs.forEach(t => t.addEventListener("click", () => {
    tabs.forEach(x => x.classList.toggle("on", x === t));
    document.querySelectorAll("[data-tabpanel]").forEach(p => (p.hidden = p.dataset.tabpanel !== t.dataset.tab));
  }));
  const tabBar = document.querySelector("[data-active-tab]");
  if (tabBar) {
    const start = tabBar.querySelector(`[data-tab="${tabBar.dataset.activeTab}"]`);
    if (start) start.click();
  }

  // ---- MFA: switch between TOTP and recovery code ----
  document.querySelectorAll("[data-switch]").forEach(a => a.addEventListener("click", e => {
    e.preventDefault();
    document.querySelectorAll("[data-panel]").forEach(p => (p.hidden = p.dataset.panel !== a.dataset.switch));
    const input = document.querySelector(`[data-panel="${a.dataset.switch}"] input[name=code]`);
    if (input) input.focus();
  }));

  // ---- MFA: 30-second window countdown ----
  const bar = document.querySelector("[data-ticker]");
  const lbl = document.querySelector("[data-ticker-label]");
  if (bar) {
    const tick = () => {
      const left = 30 - (Math.floor(Date.now() / 1000) % 30);
      bar.style.width = (left / 30 * 100) + "%";
      bar.classList.toggle("low", left <= 5);
      lbl.textContent = `Current code valid for ${left}s`;
    };
    tick();
    setInterval(tick, 1000);
  }

  // ---- Password strength ----
  const pw = document.querySelector("[data-strength]");
  if (pw) {
    const meter = document.querySelector("[data-meter]");
    const rules = {
      len: v => v.length >= 10,
      case: v => /[a-z]/.test(v) && /[A-Z]/.test(v),
      digit: v => /\d/.test(v),
      sym: v => /[^A-Za-z0-9]/.test(v),
    };
    pw.addEventListener("input", () => {
      let score = 0;
      for (const [k, fn] of Object.entries(rules)) {
        const ok = fn(pw.value);
        score += ok;
        document.querySelector(`[data-rule="${k}"]`).classList.toggle("ok", ok);
      }
      meter.className = score ? "s" + score : "";
    });
  }
});
