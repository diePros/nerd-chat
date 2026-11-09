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

## Server: a small Debian LXC, no Docker

**Recommended resources** (unprivileged Debian 12 container):

| | Recommended | Why |
|---|---|---|
| CPU | 1 vCPU, no limit | Tor's main loop is single-threaded, so one fast core matters more than many. A second core only helps under a flood of requests. |
| RAM | 1 GB (512 MB is the floor) | Tor needs roughly 100 to 250 MB for one onion service, nginx about 10 MB. The rest is headroom for updates and the sync job. |
| Swap | 512 MB | Safety net only. |
| Disk | 8 GB | The system is about 1.5 GB. Each release is a few MB to tens of MB, 3 are kept, and any single file is capped at 100 MB (`MAX_ASSET_MB`). |
| Network | one bridge, VPN as the only way out | Real speed is limited by your VPN and upload, not the container. |
| Options | start at boot, no nesting, no extra features | Nothing here needs Docker, FUSE or a privileged container. |

## Set it up (with WireGuard)

Run these on the **Proxmox host**. Replace `210` with a free container ID, `vmbr0` with your bridge, and the
template name with what `pveam available | grep debian-12` shows.

    # 0. once: WireGuard is a kernel module and loads on the host, not in the container
    modprobe wireguard && echo wireguard >> /etc/modules

    # 1. the container
    pct create 210 local:vztmpl/<debian-12 template> --hostname sineloco-onion \
        --unprivileged 1 --cores 1 --memory 1024 --swap 512 --rootfs local-lvm:8 \
        --net0 name=eth0,bridge=vmbr0,ip=dhcp --onboot 1
    pct start 210

    # 2. your VPN config (a full-tunnel WireGuard .conf from your provider) goes in as wg0.conf
    pct exec 210 -- install -d -m 700 /etc/wireguard
    pct push 210 ./myvpn.conf /etc/wireguard/wg0.conf --perms 600

    # 3. this repository's site/ folder, then install
    tar czf site.tgz site && pct push 210 site.tgz /root/site.tgz
    pct exec 210 -- bash -c 'cd /root && tar xzf site.tgz && cd site/onion && ./install.sh'

The installer ends by printing the onion address. Back up `/var/lib/tor/sineloco/`: the secret key in there
**is** the address.

`SINGLE_HOP=0 ./install.sh` gives a standard (location-hiding) onion service instead of single-hop.

## The VPN and the kill switch

Single-hop mode is faster, but Tor relays then connect straight to this server and see its public IP.
The installer makes sure that IP is your VPN's, and fails closed:

- Your WireGuard config is installed as `/etc/wireguard/wg0.conf` and started with `wg-quick@wg0`
  (it must route everything: `AllowedIPs` includes `0.0.0.0/0`). A hostname in `Endpoint` is replaced by
  its IP address, because the firewall has to name it; rerun the installer if your VPN changes that address.
- A firewall (`/etc/nftables.conf`, table `killswitch`) drops everything that is not inside the tunnel,
  except the tunnel's own packets to your VPN endpoint and local DHCP. If the VPN drops, the container
  has no internet; it does not fall back to your home IP.
- Tor, nginx and the sync job are tied to the tunnel (`BindsTo=wg-quick@wg0`): they stop if it stops.
- Tor is only started after three checks pass: a handshake with the VPN, a public IP that differs from the
  one before, and a leak test (a request forced out of the normal network port must fail).
- `sudo sineloco-vpn-check` repeats all of that whenever you want.
- Manage the container with `pct enter 210` from the host. SSH works too if you install `openssh-server`, but only from your local network (private address ranges); nothing from the internet can reach it.
- While the installer loads the firewall it keeps a 3-minute safety timer: if it has not confirmed success by then, it removes the live rules so a broken run cannot lock you out. The saved rules still load at boot.
- The container has no home-network access of its own other than the VPN endpoint and DHCP; apt updates
  also go through the VPN.

If the tunnel does not come up inside an unprivileged container, check on the host that `lsmod | grep wireguard`
shows the module, and read `journalctl -u wg-quick@wg0` in the container. Some providers' configs need
`PostUp` lines that an unprivileged container may refuse; a minimal config (Interface + one Peer) always works.

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
and the Tor config (`tor --verify-config`). The firewall rules and endpoint pinning were generated and
read back for sample configs. **Not tested here:** `install.sh` and `vpn-setup.sh --install` on a real
Debian machine (the nft rules were not loaded, WireGuard was not started), the systemd units, and the nginx
config (neither nginx nor nft is on the dev machine). On the server, read the installer's output, run
`nginx -t` and `sudo sineloco-vpn-check`, and do the "take the VPN down" test before sharing the address.
