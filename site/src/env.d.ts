// Optional secret (wrangler secret put GITHUB_TOKEN): a read-only token for public data.
// Not in wrangler.jsonc, so `wrangler types` does not know it.
interface Env {
  GITHUB_TOKEN?: string;
}
