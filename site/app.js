// Progressive enhancement only: the page is complete without this script.
(() => {
  "use strict";
  document.documentElement.classList.add("js");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // The lamp: a hard-edged circle that follows the pointer over the plate.
  const scene = document.querySelector(".scene");
  const plate = document.querySelector(".plate");
  if (scene && plate && !reduced) {
    scene.addEventListener("pointermove", (e) => {
      const r = plate.getBoundingClientRect();
      if (e.clientY > r.bottom) return;
      scene.style.setProperty("--lx", ((e.clientX - r.left) / r.width * 100).toFixed(1) + "%");
      scene.style.setProperty("--ly", ((e.clientY - r.top) / r.height * 100).toFixed(1) + "%");
    });
  }

  // Relative ages.
  const ago = (iso) => {
    const s = (Date.now() - Date.parse(iso)) / 1000;
    if (!isFinite(s)) return null;
    if (s < 90) return "just now";
    if (s < 5400) return Math.round(s / 60) + " min ago";
    if (s < 172800) return Math.round(s / 3600) + "h ago";
    return Math.round(s / 86400) + " days ago";
  };
  const paintAges = () => document.querySelectorAll("[data-ago]").forEach((el) => {
    const a = ago(el.dataset.ago);
    if (a) el.textContent = a;
  });

  // Monitor health. The publisher checks in every 15 minutes, so a check
  // older than 45 minutes means it is late and older than 2 hours means it
  // has stopped. A page rendered with health "down" (monitor not reading
  // logs) already says so and is left alone.
  const generated = document.querySelector('meta[name="ct2-generated"]')?.content;
  const health = document.querySelector('meta[name="ct2-health"]')?.content;
  const paintStatus = () => {
    if (!generated || health === "down") return;
    const mins = (Date.now() - Date.parse(generated)) / 6e4;
    const age = mins < 120 ? `${Math.round(mins)} min` : `${Math.round(mins / 60)}h`;
    let word = "[OK]", cls = "ok", text = null;
    if (mins > 120) { word = "[ERR]"; cls = "err"; text = `No check-in for ${age}. The monitor or publisher may be down.`; }
    else if (mins > 45) { word = "[WARN]"; cls = "warn"; text = `Last check-in ${age} ago, later than the usual 15 minutes.`; }
    document.querySelectorAll("[data-status-marker]").forEach((el) => {
      el.textContent = word; el.className = "m " + cls;
    });
    document.querySelectorAll("[data-status-sq]").forEach((el) => { el.className = "sq " + cls; });
    if (text) document.querySelectorAll("[data-status-text]").forEach((el) => { el.textContent = text; });
  };
  paintAges(); paintStatus();
  setInterval(() => { paintAges(); paintStatus(); }, 60000);

  // Reload when newer data has been published.
  const check = async () => {
    try {
      const res = await fetch("data.json?t=" + Date.now(), { cache: "no-store" });
      if (!res.ok) return;
      const d = await res.json();
      if (generated && d.generated_at && Date.parse(d.generated_at) > Date.parse(generated)) location.reload();
    } catch (_) { /* offline: try again later */ }
  };
  setInterval(check, 120000);

  // Table filter.
  const q = document.getElementById("q"), v = document.getElementById("v"), shown = document.getElementById("shown");
  const rows = [...document.querySelectorAll("#all-table tbody tr[data-v]")];
  const filter = () => {
    const needle = (q?.value || "").trim().toLowerCase(), want = v?.value || "";
    let n = 0;
    for (const r of rows) {
      const ok = (!want || r.dataset.v === want) && (!needle || r.dataset.q.toLowerCase().includes(needle));
      r.hidden = !ok; if (ok) n++;
    }
    if (shown) shown.textContent = `${n} of ${rows.length} shown`;
  };
  q?.addEventListener("input", filter);
  v?.addEventListener("change", filter);
  filter();
})();
