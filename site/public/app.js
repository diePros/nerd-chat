// Progressive enhancement only. The page is complete without this file.
(() => {
  "use strict";
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // 1. Hero: each protocol token resolves from noise once, on load.
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
          out += t >= (k + 1) / (final.length + 1) + 0.0001 || t === 1
            ? final[k]
            : glyphs[Math.floor(Math.random() * glyphs.length)];
        }
        el.textContent = t < 1 ? out : final;
        if (t < 1) requestAnimationFrame(tick);
      };
      el.textContent = final.replace(/./g, "·");
      requestAnimationFrame(tick);
    });
  }

  // 2. Route: the packet crosses once when the figure scrolls into view.
  const route = document.querySelector(".route");
  if (route && !reduced && "IntersectionObserver" in window) {
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        route.classList.add("go");
        io.disconnect();
      }
    }, { threshold: 0.6 });
    io.observe(route);
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
    const ns = "http://www.w3.org/2000/svg";
    const line = document.createElementNS(ns, "polyline");
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
        const tag = $("p-tag");
        tag.replaceChildren(link(latest.tag, latest.url));
        $("p-when").textContent = fmtDate(latest.date);
        const assets = $("p-assets");
        assets.replaceChildren(...(latest.assets || []).map((a) => {
          const li = document.createElement("li");
          li.append(link(a.name, a.url));
          const s = document.createElement("span");
          s.className = "sz";
          s.textContent = fmtSize(a.size);
          li.append(s);
          return li;
        }));
        const dl = $("cta-download");
        if (dl && latest.url) dl.href = safe(latest.url);
      } else {
        $("p-tag").textContent = "No release yet";
        $("p-when").textContent = "";
      }
      $("p-list").replaceChildren(...rels.map((r) => {
        const li = document.createElement("li");
        li.append(link(r.name || r.tag, r.url));
        const s = document.createElement("span");
        s.className = "dt";
        s.textContent = fmtDate(r.date);
        li.append(s);
        return li;
      }));

      const stale = res.headers.get("X-Pulse-Stale") === "1";
      if (stale && d.fetchedAt) {
        note.className = "note stale";
        note.textContent = "GitHub did not answer. Showing the last numbers seen on " + fmtDate(d.fetchedAt) + ".";
      } else {
        note.textContent = "From GitHub, " + d.repo + ". Updated " + fmtDate(d.fetchedAt) + ".";
      }
    } catch {
      note.className = "note stale";
      note.replaceChildren(
        "Release data unavailable right now. ",
        link("See releases on GitHub", "https://github.com/diePros/nerd-chat/releases"),
        ".",
      );
    }
  }
  pulse();
})();
