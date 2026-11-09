# Onion mirror for sineloco.dev

Serves the same website as a Tor onion service from your own server, plus a direct download page
with checksums. New releases appear by themselves: you never edit the site for an update.

## How it works

    GitHub release  --(every 15 min)-->  sync-releases.sh  -->  /srv/sineloco/dl/<tag>/...
                                              |                 /srv/sineloco/data/github.json
                                              |                 /srv/sineloco/data/downloads/index.html
    Tor (onion service) --> nginx (127.0.0.1:8080) --> the site + /api/github + /dl/ + /downloads/

- A release is published only after **every file matches `SHA256SUMS`** (and GitHub's own digest, when
  it reports one). If anything is wrong, that release is refused and the previous one keeps being served.
- If the release has `SHA256SUMS.asc` and you installed the signer's public key, the signature is
  checked too. With `SIGNER_FPR` set, only that exact key is accepted.
- The home page's stars and releases panel reads `/api/github`, which nginx serves from the file the sync
  job writes (same JSON shape as the clearnet Worker). `/downloads/` is plain HTML, so it also works in
  Tor Browser's Safest mode, where scripts are off.
- The last 3 releases are kept; older ones are deleted. `/dl/latest/` always points at the newest
  non-pre-release.

## Server: plain Debian LXC, no Docker

1. In Proxmox, create an **unprivileged Debian 12 LXC** (1 vCPU, 512 MB RAM, 4 GB disk is plenty).
2. Put it **behind the VPN** (see below), then get this repository's `site/` folder into it
   (`git clone`, or `scp -r site root@<container>:`).
3. `cd site/onion && sudo ./install.sh`
   It installs `tor` and `nginx`, builds the onion variant of the site, starts the onion service,
   starts the sync timer, and prints the onion address.
4. Back up `/var/lib/tor/sineloco/`. The secret key in there **is** the address.

Standard (location-hiding) onion service instead of single-hop: `SINGLE_HOP=0 sudo ./install.sh`.

## VPN in front, and why it needs a kill switch

The installer sets up a **single-hop onion service** (`HiddenServiceSingleHopMode`): faster, but Tor
relays then connect straight to this server and see its public IP. With a VPN in front they see the
VPN's address instead of your home IP. That only holds if traffic can **never** leave outside the VPN:

- Best: make the VPN the container's only route (a VPN gateway/router VM, or a firewall rule on the
  Proxmox bridge that drops everything not going through the VPN). Do it outside the container, so a
  container problem cannot undo it.
- After install, the script prints the public IP seen from the container. It must be the VPN's.
- Test the kill switch: take the VPN down and confirm the container has no connectivity.
- Single-hop mode is incompatible with running Tor as a client on the same instance. That is fine here.

## Day to day

| Task | Command |
|---|---|
| Sync now | `sudo systemctl start sineloco-mirror-sync` |
| See what happened | `journalctl -u sineloco-mirror-sync -e` |
| Next run | `systemctl list-timers sineloco-mirror-sync.timer` |
| Update the website itself | `git pull`, then `sudo ROOT=/srv/sineloco /usr/local/lib/sineloco-mirror/deploy-site.sh site/public` |
| Settings | `/etc/sineloco-mirror.conf` (repo name, how many releases to keep, optional token) |
| Verify releases with a signature | save the signer's public key as `/etc/sineloco-mirror/signing.asc` |
| Onion address | `cat /var/lib/tor/sineloco/hostname` |

After the repository rename, change `REPO` in `/etc/sineloco-mirror.conf` and the
`https://github.com/diePros/nerd-chat/...` links in `public/index.html` and `onion/deploy-site.sh`.

## Tell visitors about it

Once it works, add this line inside the `/*` block of `public/_headers` and redeploy the Worker.
Tor Browser then offers "onion available" on the clearnet site:

    Onion-Location: http://YOURADDRESS.onion/

## What the checksums do and do not prove

Checksums served from the same place as the file only catch corruption. A copy of `SHA256SUMS` from a
second place (GitHub), a signature, or a reproducible rebuild is what actually protects against a
tampered download. The page says so next to the hashes.

## Tested and not tested

Tested here: the sync script against a fake GitHub (good release, tampered file refused, signatures
valid / unknown / wrong key / wrong pinned fingerprint), the site build, the generated downloads page,
and the Tor config (`tor --verify-config`). **Not tested here:** `install.sh` on a real Debian machine,
the systemd units, and the nginx config (no nginx on the dev machine). Run `nginx -t` and the first
sync on the server and read the output before sharing the address.
