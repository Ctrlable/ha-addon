// Ctrlable Store — appliance panel. Vanilla custom element; talks to the
// ctrlable_store websocket API. HA assigns `.hass`. List + search + detail views.
class CtrlableStorePanel extends HTMLElement {
  set hass(hass) { this._hass = hass; if (!this._init) { this._init = true; this._q = ""; this._render(); this._load(); } }

  async _ws(msg) { return this._hass.connection.sendMessagePromise(msg); }

  _render() {
    this.attachShadow({ mode: "open" });
    this.shadowRoot.innerHTML = `
      <style>
        :host{display:block;font-family:Inter,system-ui,sans-serif;background:#0F1216;color:#E7ECF3;min-height:100%}
        .wrap{max-width:920px;margin:0 auto;padding:24px}
        h1{font-size:20px;margin:0 0 4px}.sub{color:#8A94A6;font-size:13px}
        .top{display:flex;align-items:center;gap:12px;margin:14px 0 18px}
        .search{flex:1;background:#161B22;border:1px solid #232a33;border-radius:10px;padding:10px 14px;color:#E7ECF3;font-size:14px}
        .search::placeholder{color:#5d6675}
        .card{background:#161B22;border:1px solid #232a33;border-radius:12px;padding:16px;margin-bottom:12px;display:flex;align-items:center;gap:16px;cursor:pointer;transition:border-color .15s}
        .card:hover{border-color:#3a4757}
        .ico{width:40px;height:40px;border-radius:10px;background:#0F1216;object-fit:contain;flex:none;padding:3px;box-sizing:border-box}
        .meta{flex:1}.name{font-weight:600}.ver{color:#8A94A6;font-size:13px;margin-top:2px}
        .badge{font-size:11px;padding:2px 8px;border-radius:999px;background:#23304a;color:#9cc1ff;margin-left:8px}
        .badge.brk{background:#3a2330;color:#ff9cb0}.badge.ok{background:#1e3a2a;color:#7ee0a3}.badge.lic{background:#3a3320;color:#ffcf6b}
        .chev{color:#5d6675;font-size:18px}
        button{background:#4C8DFF;color:#fff;border:0;border-radius:8px;padding:9px 18px;font-weight:600;cursor:pointer;font-size:14px}
        button.sec{background:#232a33;color:#E7ECF3}button:disabled{opacity:.5;cursor:default}
        .ok{color:#5fd08a}.warn{color:#ffcf6b}.err{color:#ff7a7a}
        .bar{background:#161B22;border:1px solid #232a33;border-radius:10px;padding:12px 16px;margin-bottom:16px;display:none}
        .back{color:#9cc1ff;cursor:pointer;font-size:13px;display:inline-block;margin-bottom:14px}
        .detail{background:#161B22;border:1px solid #232a33;border-radius:12px;padding:24px}
        .dh{display:flex;align-items:center;gap:12px;margin-bottom:6px}.dt{font-size:22px;font-weight:700}
        .grid{display:grid;grid-template-columns:140px 1fr;gap:8px 16px;margin:18px 0;font-size:14px}
        .k{color:#8A94A6}.v{color:#E7ECF3;word-break:break-all}
        .cl{background:#0F1216;border:1px solid #232a33;border-radius:8px;padding:12px;color:#c8d0db;font-size:13px;white-space:pre-wrap;margin-top:6px}
        .desc{margin:18px 0;color:#c8d0db;font-size:14px;line-height:1.55;border-top:1px solid #232a33;padding-top:16px}
        .desc ha-markdown a{color:#9cc1ff}.desc img{max-width:100%}
      </style>
      <div class="wrap">
        <h1>Ctrlable Store</h1>
        <div class="sub">Licensed components for this appliance.</div>
        <div class="bar" id="bar"></div>
        <div id="view"></div>
      </div>`;
    this.shadowRoot.getElementById("bar").addEventListener("click", (e) => {
      if (e.target.dataset.act === "restart") this._restart();
    });
  }

  async _load() {
    const view = this.shadowRoot.getElementById("view");
    view.innerHTML = `<div class="sub">Loading…</div>`;
    try { this._res = await this._ws({ type: "ctrlable_store/catalog" }); }
    catch (e) { view.innerHTML = `<div class="err">Failed to load catalog: ${e.message || e}</div>`; return; }
    if (!this._res.configured) {
      view.innerHTML = `<div class="warn">This appliance isn't enrolled yet (no device token). Install/enroll the Ctrlable agent first.</div>`;
      return;
    }
    if (!this._res.provisioned) {
      view.innerHTML = `<div class="warn">This appliance is enrolled but not yet <b>assigned to a client and location</b>. The Ctrlable Store activates once it's assigned in the portal.</div>`;
      return;
    }
    this._renderList();
  }

  _renderList() {
    const view = this.shadowRoot.getElementById("view");
    const all = this._res.products || [];
    const q = this._q.trim().toLowerCase();
    const items = q ? all.filter((p) => (p.name || p.product).toLowerCase().includes(q) || p.product.toLowerCase().includes(q)) : all;
    view.innerHTML = `
      <div class="top">
        <input class="search" id="search" placeholder="Search components…" value="${this._q}">
      </div>
      <div id="list"></div>`;
    const list = this.shadowRoot.getElementById("list");
    if (!all.length) { list.innerHTML = `<div class="sub">No licensed products for this instance.</div>`; }
    else if (!items.length) { list.innerHTML = `<div class="sub">No matches for “${this._q}”.</div>`; }
    else { list.innerHTML = items.map((p, i) => this._card(p, all.indexOf(p))).join(""); }

    const s = this.shadowRoot.getElementById("search");
    s.addEventListener("input", () => { this._q = s.value; this._renderList(); });
    s.focus(); s.setSelectionRange(s.value.length, s.value.length);
    list.querySelectorAll("[data-idx]").forEach((el) =>
      el.addEventListener("click", () => this._renderDetail(all[+el.dataset.idx])));
  }

  _card(p, idx) {
    const inst = !p.installed ? `<span class="badge">not installed</span>`
      : p.update_available ? `<span class="badge">update</span>` : `<span class="badge ok">installed</span>`;
    const status = inst + (p.licensed ? "" : `<span class="badge lic">unlicensed</span>`);
    const brk = p.breaking ? `<span class="badge brk">breaking</span>` : "";
    const cur = p.installed ? ` · installed ${p.installed_version}` : "";
    const ico = p.icon_url ? `<img class="ico" src="${p.icon_url}" onerror="this.style.visibility='hidden'">` : `<div class="ico"></div>`;
    return `<div class="card" data-idx="${idx}">
      ${ico}
      <div class="meta"><div class="name">${p.name || p.product}${status}${brk}</div>
        <div class="ver">v${p.version}${cur}</div></div>
      <div class="chev">›</div></div>`;
  }

  _renderDetail(p) {
    const view = this.shadowRoot.getElementById("view");
    const action = !p.installed ? "Install" : (p.update_available ? `Update to ${p.version}` : "Up to date");
    const dis = (p.installed && !p.update_available) ? "disabled" : "";
    const brk = p.breaking ? `<span class="badge brk">breaking</span>` : "";
    const mb = (p.size_bytes / 1048576).toFixed(1);
    view.innerHTML = `
      <span class="back" id="back">‹ Back</span>
      <div class="detail">
        <div class="dh">${p.icon_url ? `<img class="ico" src="${p.icon_url}" onerror="this.style.visibility='hidden'">` : ""}<span class="dt">${p.name || p.product}</span>${brk}</div>
        <div class="sub" style="margin-bottom:6px">${p.product}</div>
        <div class="sub">Latest v${p.version}${p.installed ? ` · installed v${p.installed_version}` : " · not installed"}</div>
        <div id="desc" class="desc"></div>
        <div class="grid">
          <div class="k">Licensed</div><div class="v">${p.licensed ? "Yes" : "No — contact Ctrlable to license this product"}</div>
          <div class="k">Latest version</div><div class="v">${p.version}</div>
          <div class="k">Installed</div><div class="v">${p.installed ? p.installed_version : "—"}</div>
          <div class="k">Channel</div><div class="v">${p.channel || "stable"}</div>
          <div class="k">Download size</div><div class="v">${mb} MB</div>
          <div class="k">Breaking</div><div class="v">${p.breaking ? "Yes — re-licensing/migration may be required" : "No"}</div>
          <div class="k">SHA-256</div><div class="v">${p.sha256 || "—"}</div>
        </div>
        ${p.changelog ? `<div class="k">Changelog</div><div class="cl">${p.changelog}</div>` : ""}
        <div style="margin-top:22px"><button id="act" ${dis}>${action}</button>
        ${!p.licensed ? `<div class="sub" style="margin-top:10px">⚠ Not licensed on this instance — it will install, but the component requires a license (applied in its own panel) to run.</div>` : ""}</div>
      </div>`;
    this.shadowRoot.getElementById("back").addEventListener("click", () => this._renderList());
    const act = this.shadowRoot.getElementById("act");
    if (!dis) act.addEventListener("click", () => this._install(p, act));
    // Render the README/description with HA's markdown renderer (safe).
    const desc = this.shadowRoot.getElementById("desc");
    if (p.description) {
      const md = document.createElement("ha-markdown");
      md.breaks = true;
      md.content = p.description;
      desc.appendChild(md);
    } else {
      desc.innerHTML = `<div class="sub">No description provided.</div>`;
    }
  }

  async _install(p, btn) {
    btn.disabled = true; btn.textContent = "Installing…";
    try {
      const r = await this._ws({ type: "ctrlable_store/install", product: p.product });
      btn.textContent = `Installed ${r.version}`;
      if (r.restart_required) this._showRestart(`${p.product} ${r.version} installed — restart to apply.`);
    } catch (e) {
      btn.disabled = false; btn.textContent = "Retry";
      this._showRestart(`Install failed: ${e.message || e}`, false);
    }
  }

  _showRestart(text, restart = true) {
    const bar = this.shadowRoot.getElementById("bar");
    bar.style.display = "block";
    bar.innerHTML = `<span class="${restart ? "ok" : "err"}">${text}</span>` +
      (restart ? ` <button class="sec" data-act="restart" style="margin-left:12px">Restart now</button>` : "");
  }

  async _restart() {
    const bar = this.shadowRoot.getElementById("bar");
    bar.innerHTML = `<span class="warn">Restarting Home Assistant…</span>`;
    try { await this._ws({ type: "ctrlable_store/restart" }); } catch (e) {}
  }
}
customElements.define("ctrlable-store-panel", CtrlableStorePanel);
