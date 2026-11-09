# Sine Loco website

Static page plus one small Worker, for Cloudflare Workers.

- `public/` is the page (HTML, CSS, one script, self-hosted fonts, `_headers` with a strict CSP).
- `src/worker.ts` serves `/api/github` (stars and releases, cached 10 min) and a daily cron that records star counts in KV for the sparkline. Everything else is static assets.

## Run and deploy

    npm install
    npm run dev        # http://localhost:8787
    npm run check      # wrangler types + tsc
    npm run deploy     # first deploy creates the STATS KV namespace

## Before going live

- `REPO` in `wrangler.jsonc` and the GitHub links in `public/index.html` and `public/app.js` point at `diePros/nerd-chat`. Change them after the repository rename (GitHub redirects the API, but the links should be final).
- Optional: `npx wrangler secret put GITHUB_TOKEN` (read-only, public data) to avoid the unauthenticated rate limit.
- The site is configured for `sineloco.dev` (`routes` in `wrangler.jsonc`, custom domain). The first `npm run deploy` creates the DNS record and certificate; the zone must be in the same Cloudflare account as the Worker.
- Every row in the facts table cites a source file. Re-check them when the code changes.
