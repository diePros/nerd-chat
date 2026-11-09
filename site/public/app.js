// Progressive enhancement only. The page is complete without this file.
(() => {
  "use strict";
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // 1. Handshake tokens resolve from noise once, on load.
  if (!reduced) {
    const glyphs = "0123456789abcdefABCDEF+_*#";
    document.querySelectorAll(".tok").forEach((el, i) => {
      const final = el.dataset.final || el.textContent || "";
      const start = performance.now() + i * 140;
      const dur = 650;
      const tick = (now) => {
        const t = Math.min(1, Math.max(0, (now - start) / dur));
        let out = "";
        for (let k = 0; k < final.length; k++) {
          out += t === 1 || t >= (k + 1) / (final.length + 1) ? final[k] : glyphs[Math.floor(Math.random() * glyphs.length)];
        }
        el.textContent = t < 1 ? out : final;
        if (t < 1) requestAnimationFrame(tick);
      };
      el.textContent = final.replace(/./g, "·");
      requestAnimationFrame(tick);
    });
  }

  // 2. Relay path: a message crosses, losing one Tor layer per relay on each side.
  const relay = document.getElementById("relay");
  if (relay && !reduced) {
    const route = relay.querySelector("#route");
    const packet = relay.querySelector("#packet");
    const rings = [...packet.querySelectorAll(".ring")];
    const nodes = [...relay.querySelectorAll(".n")];
    const arrive = relay.querySelector(".arrive");
    const total = route.getTotalLength();

    // distance along the route of each node, from the node coordinates
    const pts = nodes.map((n) => [Number(n.getAttribute("cx")), Number(n.getAttribute("cy"))]);
    const stops = [0];
    for (let i = 1; i < pts.length; i++) {
      stops.push(stops[i - 1] + Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]));
    }
    const norm = stops.map((s) => s / stops[stops.length - 1]);
    const RDV = 4; // index of the rendezvous node

    const CYCLE = 10000, MOVE = 0.78;
    let running = false, t0 = 0;

    const frame = (now) => {
      if (!running) return;
      const t = ((now - t0) % CYCLE) / CYCLE;
      const m = Math.min(1, t / MOVE);
      const p = route.getPointAtLength(m * total);
      packet.setAttribute("transform", `translate(${p.x.toFixed(1)} ${p.y.toFixed(1)})`);

      // layers: three, peeled by each relay up to the rendezvous point, rewrapped for the far side
      let peeled = 0;
      if (m < norm[RDV]) {
        for (let i = 1; i < RDV; i++) if (m >= norm[i]) peeled++;
      } else {
        for (let i = RDV + 1; i < nodes.length - 1; i++) if (m >= norm[i]) peeled++;
      }
      rings.forEach((r, i) => r.setAttribute("opacity", i < 3 - peeled ? "1" : "0"));

      nodes.forEach((n, i) => n.classList.toggle("lit", m >= norm[i] && t < MOVE + 0.1));
      packet.setAttribute("opacity", t < 0.02 ? String(t / 0.02) : t > MOVE ? String(Math.max(0, 1 - (t - MOVE) / 0.04)) : "1");

      const a = t > MOVE ? (t - MOVE) / 0.14 : 0; // arrival pulse at the contact
      arrive.setAttribute("r", String(11 + a * 40));
      arrive.setAttribute("opacity", a > 0 && a < 1 ? String(0.8 * (1 - a)) : "0");

      requestAnimationFrame(frame);
    };

    const io = new IntersectionObserver((entries) => {
      const visible = entries.some((e) => e.isIntersecting);
      if (visible && !running) {
        running = true;
        t0 = performance.now();
        requestAnimationFrame(frame);
      } else if (!visible) {
        running = false;
      }
    }, { threshold: 0.2 });
    io.observe(relay);
  }

  // 3. GitHub pulse, from this site's own /api/github (never from GitHub directly).
  const $ = (id) => document.getElementById(id);
  const fmtDate = (iso) => {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString("en", { year: "numeric", month: "short", day: "numeric" });
  };
  const fmtSize = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB");
  const safe = (u) => (typeof u === "string" && u.startsWith("https://github.com/") ? u : "#");

  function link(text, href) {
    const a = document.createElement("a");
    a.textContent = text;
    a.href = safe(href);
    a.rel = "noopener";
    return a;
  }
  function item(left, right, cls) {
    const li = document.createElement("li");
    li.append(left);
    const s = document.createElement("span");
    s.className = cls;
    s.textContent = right;
    li.append(s);
    return li;
  }

  function spark(history) {
    const svg = $("p-spark");
    if (!svg || history.length < 2) return;
    const pts = history.slice(-90);
    const vals = pts.map((p) => p.s);
    const lo = Math.min(...vals), hi = Math.max(...vals);
    const span = hi - lo || 1;
    const coords = pts.map((p, i) => {
      const x = (i / (pts.length - 1)) * 160;
      const y = 36 - ((p.s - lo) / span) * 32;
      return x.toFixed(1) + "," + y.toFixed(1);
    });
    const line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
    line.setAttribute("points", coords.join(" "));
    svg.replaceChildren(line);
    svg.setAttribute("aria-label", `Star history, ${pts.length} days, ${lo} to ${hi}`);
    svg.hidden = false;
  }

  async function pulse() {
    const note = $("p-note");
    try {
      const res = await fetch("/api/github", { headers: { Accept: "application/json" } });
      if (!res.ok) throw new Error(String(res.status));
      const d = await res.json();
      if (typeof d.stars !== "number") throw new Error("shape");
      $("p-stars").textContent = d.stars.toLocaleString("en");
      spark(Array.isArray(d.history) ? d.history : []);

      const rels = Array.isArray(d.releases) ? d.releases : [];
      const latest = rels.find((r) => !r.prerelease) || rels[0];
      if (latest) {
        $("p-latest-cap").textContent = latest.prerelease ? "Latest pre-release" : "Latest release";
        $("p-tag").replaceChildren(link(latest.tag, latest.url));
        $("p-when").textContent = fmtDate(latest.date);
        $("p-assets").replaceChildren(...(latest.assets || []).map((a) => item(link(a.name, a.url), fmtSize(a.size), "sz")));
        const dl = $("cta-download");
        if (dl && latest.url) dl.href = safe(latest.url);
      } else {
        $("p-tag").textContent = "No release yet";
        $("p-when").textContent = "";
      }
      $("p-list").replaceChildren(...rels.map((r) => item(link(r.name || r.tag, r.url), fmtDate(r.date), "dt")));

      if (res.headers.get("X-Pulse-Stale") === "1" && d.fetchedAt) {
        note.className = "note stale";
        note.textContent = "GitHub did not answer. Showing the last numbers seen on " + fmtDate(d.fetchedAt) + ".";
      } else {
        note.textContent = "From GitHub, " + d.repo + ". Updated " + fmtDate(d.fetchedAt) + ".";
      }
    } catch {
      note.className = "note stale";
      note.replaceChildren("Release data unavailable right now. ", link("See releases on GitHub", "https://github.com/diePros/nerd-chat/releases"), ".");
    }
  }
  pulse();
})();
