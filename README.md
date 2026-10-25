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

- Linux with Docker
- Go 1.21 or newer, to build the bridge
- `hping3` (optional), to test the Other tab

## Quick start

```bash
mkdir -p logs

# 1. Zeek collector with JA3 and JA4
docker build -t netpulse-zeek:latest .
docker run -d --name netpulse-zeek \
  --network host --cap-add NET_ADMIN --restart unless-stopped \
  -w /logs -v "$PWD/zeek:/s:ro" -v "$PWD/logs:/logs" \
  netpulse-zeek:latest zeek -C -i eth0 /s/netpulse.zeek local

# 2. Go bridge (start it after Zeek wrote its first logs)
go build -o netpulse main.go
./netpulse -logs ./logs -html ./index.html
```

Open http://127.0.0.1:5001

To capture another interface, replace `eth0` in the `docker run` command.
With Docker Compose installed, `docker compose up -d --build` does step 1
(set `NETPULSE_IFACE` for another interface). The compose file is untested.

The bridge reads **new** log lines only. It never replays old history.

## How it works

1. Zeek watches the interface and writes JSON logs (`conn`, `dns`, `ssl`,
   `arp`, `icmp_live`, `other_ip`).
2. The Go bridge tails those files, merges them into flows, and keeps all
   state in memory.
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
Zeek logs contain IP addresses, MAC addresses and visited domains.
Never publish your `logs/` folder.

## Troubleshooting

- **"collector offline"**: Zeek is not writing logs.
  Run `docker ps` and `docker logs --tail 20 netpulse-zeek`.
- **SNI, JA3 or JA4 empty**: Zeek must run with `-C` (ignore bad checksums on
  VMs). Check `tail -n1 logs/ssl.log` for `ja3` and `ja4`.
- **Other tab empty**: normal on most networks. Test it with
  `sudo hping3 --rawip -H 2 -c 3 <gateway-ip>`. Flows disappear after 5 minutes.
- **Page not reachable**: use `http://127.0.0.1:5001`, not `0.0.0.0`.
- **Statistics or a tab stays blank**: press F12, open the Console tab,
  and report the red error line.

## Known limits

- Other-protocol detection is IPv4 only.
- JA3 and JA4 need a TLS ClientHello that Zeek actually saw. Connections that
  started before Zeek show no SNI or fingerprints.
- State is in memory. Restarting the bridge clears history.

## License and credits

MIT, see `LICENSE`.

- [Zeek](https://zeek.org)
- JA3 (Salesforce) and JA4 (FoxIO) Zeek packages have their own licenses.
  Check them before you redistribute.
