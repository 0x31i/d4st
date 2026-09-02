# Running d4st on a Windows VM (WSL2 + Docker)

For a Windows Server 2025 box that reaches the target's dev environment over a VPN. The whole
scanner stack runs in one Linux container — you don't install any of the tools on Windows,
and Defender has nothing native to flag.

## 1. Install WSL2 (one time)

```powershell
wsl --install -d Ubuntu
wsl --update
```
Reboot if prompted, then set an Ubuntu username/password when the shell opens.

## 2. Turn on mirrored networking (so the container can reach the dev env via the VPN)

This is the important one. By default WSL2 has its own NIC and will **not** inherit the
Windows VPN routes. Mirrored mode makes WSL2 (and Docker inside it) share the host's
interfaces, including the VPN.

Create `C:\Users\<you>\.wslconfig`:
```ini
[wsl2]
networkingMode=mirrored
dnsTunneling=true
firewall=true
```
Then in PowerShell: `wsl --shutdown` (it restarts on next launch).

## 3. Install Docker Engine inside WSL2 (not Docker Desktop)

In the Ubuntu shell:
```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"       # then close+reopen the shell
sudo service docker start             # (or: enable systemd in /etc/wsl.conf)
```

## 4. Get d4st + pull the prebuilt image

The scanner image is published to GitHub Container Registry, so you **pull** it — no local
build. (You still clone the repo: it carries the compose file and the source that gets
bind-mounted for live updates.)

```bash
git clone https://github.com/0x31i/d4st.git
cd d4st
docker compose pull          # pulls ghcr.io/0x31i/d4st:core (ZAP + nuclei + katana + sqlmap + dalfox + commix + Playwright)
docker compose up -d
docker compose exec d4st d4st selftest    # MUST be green before scanning
```

If the package is private you'll first authenticate once:
`echo <github-PAT-with-read:packages> | docker login ghcr.io -u <your-gh-user> --password-stdin`
(If it's public, `docker compose pull` just works with no login.)

## 5. Verify VPN reachability BEFORE scanning

Connect the Windows VPN client, then from inside the container:
```bash
docker compose exec d4st bash -lc 'curl -sS -o /dev/null -w "%{http_code}\n" https://<dev-env-url>/'
```
A 200/302/401 means the container can reach it through the VPN. If it hangs or fails, the
mirrored-networking step didn't take — recheck `.wslconfig` + `wsl --shutdown`.

## 6. Run a scan

```bash
# capture an authenticated session (headed the first time to log in / do MFA):
docker compose exec d4st d4st auth capture -p app -b https://<dev-env-url> -o sessions/app.json --headed
# blind authenticated engagement:
docker compose exec d4st d4st engagement -t https://<dev-env-url> -s sessions/app.json -o results/app.json
```
Watch it in the console at `http://localhost:8810`, then produce the client report:
```bash
docker compose exec d4st d4st report app --from-db --client "<Client>" -o results/app-report.pdf
```

## Updating the tool (the easy loop)

Almost every fix is d4st Python code (adapter flags, parsing, report). The source is
bind-mounted live, so:
```bash
git pull && docker compose restart d4st
```
No rebuild, ~10 seconds. Only when the **tools** change (a new dependency or scanner binary)
do you pull a fresh image — Docker re-fetches just the changed layer:
```bash
git pull && docker compose pull && docker compose up -d
```

## If something misbehaves (remote diagnosis)

1. `docker compose exec d4st d4st selftest` — pinpoints a broken tool→parser path.
2. Screenshot the console **Engines** tab (each scanner's ran/skipped/note/count) + **Timeline**.
3. Paste both back — the fix is almost always a code change you pull with the loop above.

## Defender

Nothing native runs on Windows, but if Defender ever scans the WSL2 disk and flags a tool,
add an exclusion for the WSL distro's vhdx (Windows Security → Virus & threat protection →
Exclusions → `\\wsl$\Ubuntu` or the `ext4.vhdx` path).
