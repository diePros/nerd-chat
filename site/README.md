# Sine Loco website

Static page plus one small Worker, for Cloudflare Workers.

- `public/` is the page (HTML, CSS, one script, self-hosted fonts, `_headers` with a strict CSP).
- `src/worker.ts` serves `/api/github` (stars and releases, cached 10 min) and a daily cron that records star counts in KV for the sparkline. Everything else is static assets.

## Run and deploy

    npm install
    npm run dev        # http://localhost:8787
    npm run check      # wrangler types + tsc
    npm run deploy     # first deploy creates the STATS KV namespace

## Automatic deployment

- **Cloudflare (sineloco.dev):** `.github/workflows/site-deploy.yml` checks every change under `site/` and, on a push
  to `main`, runs `wrangler deploy`. One-time setup: create an API token (Cloudflare dashboard → My Profile → API Tokens →
  template **Edit Cloudflare Workers**, limited to this account and the `sineloco.dev` zone), then store it with
  `gh secret set CLOUDFLARE_API_TOKEN` (paste the value when asked; never put it in a file or a chat). The account ID is
  not secret and lives in `wrangler.jsonc`. Without the token the checks still run and the deploy step is skipped.
- **Onion server:** updates itself from signed commits; see `onion/README.md`.

## Before going live

- `REPO` in `wrangler.jsonc` and the GitHub links in `public/index.html` and `public/app.js` point at `diePros/nerd-chat`. Change them after the repository rename (GitHub redirects the API, but the links should be final).
- Optional: `npx wrangler secret put GITHUB_TOKEN` (read-only, public data) to avoid the unauthenticated rate limit.
- The site is configured for `sineloco.dev` (`routes` in `wrangler.jsonc`, custom domain). The first `npm run deploy` creates the DNS record and certificate; the zone must be in the same Cloudflare account as the Worker.
- Every row in the facts table cites a source file. Re-check them when the code changes.
- A Tor onion mirror with a direct download page (for your own server) is in `onion/`; see `onion/README.md`.
