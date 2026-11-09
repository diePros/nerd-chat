// Serves /api/github (stars + releases, cached) and the daily star sampler.
// Everything else is static assets (see wrangler.jsonc: run_worker_first).

const CACHE_TTL = 600; // seconds a fresh GitHub answer is reused
const HISTORY_KEY = "stars-history";
const HISTORY_MAX = 365;

interface Sample {
  d: string; // YYYY-MM-DD
  s: number; // stars
}

interface Asset {
  name: string;
  size: number;
  url: string;
}

interface Release {
  tag: string;
  name: string;
  date: string;
  url: string;
  prerelease: boolean;
  assets: Asset[];
}

interface Pulse {
  repo: string;
  stars: number;
  fetchedAt: string;
  releases: Release[];
  history: Sample[];
}

const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": "default-src 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Resource-Policy": "same-origin",
};

function json(body: unknown, status: number, cacheControl: string): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": cacheControl, ...SECURITY_HEADERS },
  });
}

// What GitHub said when it refused us (its own message, never our token), for the Worker log.
async function refusal(res: Response, path: string): Promise<string> {
  let message = "";
  try {
    const body = (await res.json()) as { message?: unknown };
    message = typeof body.message === "string" ? body.message.slice(0, 200) : "";
  } catch {
    /* not JSON */
  }
  const left = res.headers.get("x-ratelimit-remaining");
  const sso = res.headers.get("x-github-sso") ? " (SSO required)" : "";
  return `github ${path || "/"} -> ${res.status}${sso}${left !== null ? ` (rate limit left: ${left})` : ""}${message ? `: ${message}` : ""}`;
}

async function gh(env: Env, path: string): Promise<unknown> {
  const call = (withToken: boolean) => {
    const headers: Record<string, string> = {
      Accept: "application/vnd.github+json",
      "User-Agent": "sine-loco-site",
      "X-GitHub-Api-Version": "2022-11-28",
    };
    if (withToken && env.GITHUB_TOKEN) headers.Authorization = `Bearer ${env.GITHUB_TOKEN.trim()}`;
    return fetch(`https://api.github.com/repos/${env.REPO}${path}`, { headers });
  };
  let res = await call(true);
  if (env.GITHUB_TOKEN && (res.status === 401 || res.status === 403)) {
    // A bad, expired or unapproved token must not take the panel down: say why, then try without it.
    console.error(JSON.stringify({ msg: "github refused the token, retrying without it", detail: await refusal(res, path) }));
    res = await call(false);
  }
  if (!res.ok) throw new Error(await refusal(res, path));
  return res.json();
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}
function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}
// Only https://github.com/... links are passed on to the page.
function ghUrl(v: unknown): string {
  const s = str(v);
  return s.startsWith("https://github.com/") ? s : "";
}

async function readHistory(env: Env): Promise<Sample[]> {
  const raw = await env.STATS.get<Sample[]>(HISTORY_KEY, "json");
  return Array.isArray(raw) ? raw : [];
}

async function fetchPulse(env: Env): Promise<Pulse> {
  const [repo, rels, history] = await Promise.all([
    gh(env, "") as Promise<Record<string, unknown>>,
    gh(env, "/releases?per_page=5") as Promise<Array<Record<string, unknown>>>,
    readHistory(env),
  ]);
  const releases: Release[] = rels
    .filter((r) => !r.draft)
    .map((r) => ({
      tag: str(r.tag_name),
      name: str(r.name) || str(r.tag_name),
      date: str(r.published_at),
      url: ghUrl(r.html_url),
      prerelease: r.prerelease === true,
      assets: (Array.isArray(r.assets) ? (r.assets as Array<Record<string, unknown>>) : []).map((a) => ({
        name: str(a.name),
        size: num(a.size),
        url: ghUrl(a.browser_download_url),
      })),
    }));
  return {
    repo: env.REPO,
    stars: num(repo.stargazers_count),
    fetchedAt: new Date().toISOString(),
    releases,
    history,
  };
}

async function handleGithub(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return json({ error: "method not allowed" }, 405, "no-store");
  }
  const cache = await caches.open("pulse");
  const key = new Request(new URL("/api/github", request.url).toString());
  const hit = await cache.match(key);
  if (hit) return hit;
  try {
    const pulse = await fetchPulse(env);
    const res = json(pulse, 200, `public, max-age=${CACHE_TTL}`);
    ctx.waitUntil(cache.put(key, res.clone()));
    // Remember the last good answer so a GitHub outage can still show it, marked with its age.
    ctx.waitUntil(env.STATS.put("last-good", JSON.stringify(pulse)));
    return res;
  } catch (err) {
    console.error(JSON.stringify({ msg: "github fetch failed", error: String(err) }));
    const last = await env.STATS.get("last-good");
    if (last) {
      return new Response(last, {
        status: 200,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "public, max-age=60",
          "X-Pulse-Stale": "1",
          ...SECURITY_HEADERS,
        },
      });
    }
    return json({ error: "unavailable" }, 503, "public, max-age=30");
  }
}

async function sampleStars(env: Env): Promise<void> {
  const repo = (await gh(env, "")) as Record<string, unknown>;
  const today = new Date().toISOString().slice(0, 10);
  const history = (await readHistory(env)).filter((p) => p.d !== today);
  history.push({ d: today, s: num(repo.stargazers_count) });
  await env.STATS.put(HISTORY_KEY, JSON.stringify(history.slice(-HISTORY_MAX)));
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;
    if (url.hostname === "www.sineloco.dev") {
      return Response.redirect(`https://sineloco.dev${pathname}${url.search}`, 301);
    }
    if (pathname === "/api/github") return handleGithub(request, env, ctx);
    if (pathname.startsWith("/api/")) return json({ error: "not found" }, 404, "no-store");
    return env.ASSETS.fetch(request);
  },

  async scheduled(_controller, env, ctx): Promise<void> {
    ctx.waitUntil(
      sampleStars(env).catch((err) =>
        console.error(JSON.stringify({ msg: "star sample failed", error: String(err) })),
      ),
    );
  },
} satisfies ExportedHandler<Env>;
