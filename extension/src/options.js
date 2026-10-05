// Options page logic.
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const DEFAULTS = {
    githubToken: "",
    annotateLists: true,
    listBudget: 10,
    extraCAs: [],
  };

  function status(msg) {
    $("status").textContent = msg;
    setTimeout(() => {
      if ($("status").textContent === msg) $("status").textContent = "";
    }, 2500);
  }

  // Show the shipped pin so it can be eyeballed against the cluster's own
  // export without trusting anything this page fetched.
  function renderShippedCA() {
    const lines = globalThis.Beamsig.ca.PINNED_CAS.map(
      (c) => `${c.cluster}\n${c.fingerprint}`
    );
    $("shipped-ca").textContent = lines.join("\n\n");
  }

  // Accept Teleport export / authorized_keys / allowed_signers shaped lines.
  // We keep the whole line and let verify.loadPinnedCAs pull the blob out, so
  // the parsing stays in exactly one place.
  function parseExtraCAs(text) {
    const out = [];
    for (const raw of text.split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      if (!/\bAAAA\S+/.test(line)) {
        throw new Error(`no base64 key found in: ${line.slice(0, 48)}…`);
      }
      const m = /clustername=([^&\s]+)/.exec(line);
      out.push({ cluster: m ? m[1] : "user-added", line });
    }
    return out;
  }

  async function load() {
    renderShippedCA();
    const s = await chrome.storage.local.get(DEFAULTS);
    $("githubToken").value = s.githubToken || "";
    $("annotateLists").checked = !!s.annotateLists;
    $("listBudget").value = Number.isFinite(s.listBudget) ? s.listBudget : 10;
    $("extraCAs").value = (s.extraCAs || []).map((c) => c.line).join("\n");
  }

  async function save() {
    let extraCAs;
    try {
      extraCAs = parseExtraCAs($("extraCAs").value);
    } catch (e) {
      status(e.message);
      return;
    }
    const budget = Math.max(0, Math.min(100, Number($("listBudget").value) || 0));
    await chrome.storage.local.set({
      githubToken: $("githubToken").value.trim(),
      annotateLists: $("annotateLists").checked,
      listBudget: budget,
      extraCAs,
    });
    $("listBudget").value = budget;
    status("Saved. Reload any open GitHub tab.");
  }

  async function clearCache() {
    const all = await chrome.storage.local.get(null);
    const keys = Object.keys(all).filter((k) => k.startsWith("sig:"));
    if (keys.length) await chrome.storage.local.remove(keys);
    status(`Cleared ${keys.length} cached signature${keys.length === 1 ? "" : "s"}.`);
  }

  $("save").addEventListener("click", save);
  $("clearCache").addEventListener("click", clearCache);
  load();
})();
