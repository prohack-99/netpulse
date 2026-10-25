# NetPulse

A live network monitor for a single machine or VM.

**Zeek -> JSON logs -> Go bridge -> SSE -> browser dashboard.**

<p align="center"><img src="image/netpulse.png" alt="NetPulse dashboard" width="900"></p>

The traffic chart reads kernel interface counters. Everything else comes from
real Zeek logs. Nothing is simulated or guessed.

## What you get

| Tab | Shows |
|-----|-------|
| Main | live up/down chart, protocol share, all flows |
| TCP / UDP / ICMP / ICMPv6 | flows per protocol |
| DNS | queries, answers, response codes, round-trip time |
| TLS | SNI, version, ALPN, cipher, handshake state, **JA3 and JA4** fingerprints |
| ARP | ARP conversations with MAC addresses |
| Other | IGMP, GRE, ESP, OSPF, VRRP, PIM, SCTP and other IP protocols |
| Statistics | top endpoints, services, domains, flows by protocol |
| Diagnostics | collector state, row rates, buffer and eviction counters |

Tested on a Kali Linux VM (VirtualBox, NAT adapter, Zeek 8.x in Docker).

## Requirements

- **Linux** (Debian, Ubuntu or Kali). Zeek runs with host networking, which
  Docker supports on Linux only. macOS and Windows are not supported.
- **Docker**
- **Go 1.21 or newer**, to build the bridge
- **Git**
- `hping3` (optional), to test the Other tab

## Installation

### 1. Install the tools

```bash
sudo apt update
sudo apt install -y git golang-go docker.io
sudo systemctl enable --now docker
```

Check the versions:

```bash
git --version
sudo docker --version
go version
```

If `go version` prints something older than 1.21 (common on older Ubuntu),
install a newer Go from https://go.dev/dl/ :

```bash
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go*.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version
```

> **Note:** Download the matching Go archive from the official Go website before
> running the `tar` command. The archive filename must match the command.

### 2. Let your user run Docker (optional)

You can use `sudo` before Docker commands, as shown in this guide. If you prefer
running Docker without `sudo`, add your user to the `docker` group:

```bash
sudo usermod -aG docker "$USER"
```

Log out and back in for the change to apply. Membership in the `docker` group
grants root-level privileges, so only do this for a trusted user.

### 3. Find your network interface

```bash
ip route show default
```

Example output:

```text
default via 192.168.1.1 dev wlan0
```

The name after `dev` (in this example, `wlan0`) is the interface. Your system
may use a different name, such as `eth0` or `ens33`. Use the actual interface
name in the Zeek command below.

## Quick start

Clone the repository and enter its directory:

```bash
git clone https://github.com/prohack-99/netpulse.git
cd netpulse
mkdir -p logs
```

### 1. Build the Zeek image

```bash
sudo docker build -t netpulse-zeek:latest .
```

The first build may take several minutes, especially while the JA4 plugin is
being compiled.

### 2. Start Zeek

Set `IFACE` to the network interface that you identified in the previous step.
This command automatically selects the interface used by the default route:

```bash
IFACE="$(ip -o route show default | awk '{print $5; exit}')"
echo "Using interface: $IFACE"
```

Check that the variable contains the expected interface name. Then start the
collector:

```bash
sudo docker rm -f netpulse-zeek 2>/dev/null || true

sudo docker run -d --name netpulse-zeek \
  --network host \
  --cap-add NET_ADMIN \
  --restart unless-stopped \
  -w /logs \
  -v "$PWD/zeek:/s:ro" \
  -v "$PWD/logs:/logs" \
  netpulse-zeek:latest \
  zeek -C -i "$IFACE" /s/netpulse.zeek local
```

The `docker rm` line removes an older container with the same name, if one
exists, so the start command can be repeated. It does not delete the `logs/`
directory.

Check that Zeek is running and writing logs:

```bash
sudo docker ps --filter name=netpulse-zeek
sudo docker logs --tail 40 netpulse-zeek
ls -lah logs
```

After network traffic is observed, files such as `conn.log` and `dns.log`
should appear in `logs/`. To inspect recent entries:

```bash
sudo tail -n 3 logs/conn.log
sudo tail -n 3 logs/dns.log
```

### 3. Build and start the Go bridge

Open a terminal in the repository directory and run:

```bash
go build -o netpulse main.go
./netpulse -logs ./logs -html ./index.html
```

Keep this terminal open while using the dashboard.

Open **http://127.0.0.1:5001** in your browser and browse a few websites to
generate traffic.

Press `Ctrl+C` to stop the Go bridge. To stop and remove the Zeek container:

```bash
sudo docker rm -f netpulse-zeek
```

With Docker Compose installed, `docker compose up -d --build` is intended to
replace the two Docker commands (set `NETPULSE_IFACE` for another interface).
The Compose path has not been verified as part of the steps above; use the
manual commands if you want to follow the tested workflow.

The bridge reads **new** log lines only. It never replays old history, so start
the bridge after Zeek has written its first logs.

## How it works

1. Zeek watches the interface and writes JSON logs (`conn`, `dns`, `ssl`,
   `arp`, `icmp_live`, `other_ip`).
2. The Go bridge tails those files, merges them into flows, and keeps all state
   in memory.
3. The browser receives a snapshot every second over Server-Sent Events.

Files:

| Path | Purpose |
|------|---------|
| `main.go` | the bridge: log tailing, aggregation, HTTP API |
| `index.html` | the whole dashboard in one file |
| `zeek/netpulse.zeek` | Zeek config: JSON logs, ICMP, ARP and other-IP-protocol logs |
| `Dockerfile` | Zeek image with the JA3 and JA4 packages |

## Bridge options

| Flag | Default | Meaning |
|------|---------|---------|
| `-logs` | `.` | folder with Zeek logs |
| `-addr` | `127.0.0.1:5001` | listen address |
| `-html` | `index.html` | dashboard file |
| `-localnets` | see `-h` | extra CIDRs counted as local |
| `-expire` | `300` | seconds before an idle flow disappears |

API: `/api/stream` (SSE), `/api/flows`, `/api/flows/<tcp|udp|icmp|icmpv6|other>`,
`/api/dns`, `/api/tls`, `/api/arp`, `/api/stats`, `/api/status`.

## Security

The dashboard has **no login**. By default it listens on `127.0.0.1` only.
Use `-addr :5001` only on a network you trust.

Zeek logs contain IP addresses, MAC addresses and visited domains. Never publish
your `logs/` folder or share its contents without checking for private network
information.

## Troubleshooting

- **Docker permission denied:** run Docker commands with `sudo`, for example
  `sudo docker ps`. Alternatively, see the optional Docker group step above.
- **Container does not start:** check `sudo docker ps -a` and
  `sudo docker logs --tail 40 netpulse-zeek`. If a container with the same name
  already exists, remove it with `sudo docker rm -f netpulse-zeek` and retry.
- **"collector offline":** Zeek is not writing logs. Check the container logs
  and verify that `logs/` contains recent files.
- **No log files or no new rows:** verify the interface with
  `ip route show default`. Make sure the `-i` value in the Zeek command is an
  interface that exists on your machine and carries the traffic you want to
  monitor. Generate some traffic, then inspect `logs/conn.log` and
  `logs/dns.log`.
- **SNI, JA3 or JA4 empty:** Zeek must run with `-C` (ignore bad checksums on
  VMs). Check whether recent TLS records exist in `logs/ssl.log` and whether
  those records contain the expected fingerprint fields. Not every connection
  exposes every field.
- **Other tab empty:** this can be normal on many networks. To test it, install
  `hping3` and, only on a network you own or are authorized to test, run
  `sudo hping3 --rawip -H 2 -c 3 <gateway-ip>`. Replace `<gateway-ip>` with your
  gateway address. Flows disappear after 5 minutes.
- **Page not reachable:** use `http://127.0.0.1:5001`, not `0.0.0.0`. Make sure
  the Go bridge is still running and that port `5001` is available.
- **Statistics or a tab stays blank:** press `F12`, open the browser Console,
  and inspect the error message.

## Known limits

- Other-protocol detection is IPv4 only.
- JA3 and JA4 need a TLS ClientHello that Zeek actually saw. Connections that
  started before Zeek show no SNI or fingerprints.
- State is in memory. Restarting the bridge clears history.
- The dashboard has no authentication and is intended to be used locally by
  default.

## License and credits

MIT, see `LICENSE`.

- [Zeek](https://zeek.org)
- JA3 (Salesforce) and JA4 (FoxIO) Zeek packages have their own licenses.
  Check them before you redistribute.
