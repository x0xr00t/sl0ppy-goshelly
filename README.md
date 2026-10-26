# goshell

**A lightweight, standard-library-only system and network assessment toolkit**  
**Author:** Patrick Hoogeveen (`x0xr00t`)  
**Team:** Team Sl0ppyRoot  
**Current source version:** `0.6.0`

> **Important — rebuild the binary after updating the source.**
>
> The compiled `goshell` executable does **not** update when `goshell.go` (or any Go source file) changes. After replacing or editing the source, rebuild the executable using the instructions below, then run `./goshell version` and `./goshell doctor` to check the rebuilt copy. An older binary may still contain old behavior or bugs.

`goshell` combines local system inventory, authorized network checks, DNS and HTTP inspection, file hashing, AES-GCM file encryption, archive utilities, and basic host-security audits in one Go executable. It uses the Go standard library and does not require third-party Go modules.

Use it only on systems and networks you own or have explicit permission to assess.

## Features

- **System inventory:** host details, local users, processes, services, network sockets, and routes.
- **Network assessment:** TCP port scanning, CIDR discovery using common-port probes, and service-banner collection.
- **DNS:** forward record lookups and reverse DNS lookups.
- **HTTP inspection:** response/status and page metadata inspection; bounded HTTP(S) downloads.
- **File utilities:** MD5 and SHA-256 hashes, AES-256-GCM encryption/decryption, and ZIP creation/extraction.
- **Host audit helpers:** privilege-escalation configuration checks, scheduled-task/cron review, firewall inspection, and sensitive/config-file path discovery.
- **Self-test:** `doctor` checks selected networking, cryptography, time, and parser behavior.
- **Operational safeguards:** context cancellation on interrupt/termination, bounded scan concurrency, capped retry backoff with jitter, and JSON output for the TCP scanner.
- **Portable build:** Go 1.22+ and standard-library dependencies only.

## What is intentionally disabled

In this hardened build, remote-shell, bind-shell, proxy/SOCKS, relay, and exfiltration commands are **not registered and cannot be invoked through the command interface**. Their presence as unregistered implementation functions in source code does not mean they are supported features. This project does not include keylogging, credential/Wi-Fi dumping, or AV-evasion droppers.

## Requirements

- Go **1.22 or newer** to compile from source.
- A supported Go target platform. Some inventory results depend on OS utilities being installed (for example, `ss`, `ip`, `systemctl`, or `getent` on Linux).
- Appropriate permissions for the checks being performed. Run without elevated privileges unless a specific, authorized audit requires them.

## Build and rebuild

### Build from the repository

If the source is named `main.go` and the repository contains a `go.mod` file:

```bash
go version
go build -trimpath -ldflags="-s -w" -o goshell .
```

If you are using the delivered single source file named `goshell_hardened.go`, build it directly from the directory containing that file:

```bash
go version
go build -trimpath -ldflags="-s -w" -o goshell goshell_hardened.go
```

The command creates a new `goshell` executable in the current directory. If you have an older binary, replace it with the newly built executable only after the build succeeds. On Linux, you can then run:

```bash
chmod +x ./goshell
./goshell version
./goshell doctor
```

### Run tests and static checks

When the source and test file are both available:

```bash
go test goshell_hardened.go goshell_hardened_test.go
go vet goshell_hardened.go goshell_hardened_test.go
go build -trimpath -ldflags="-s -w" -o goshell goshell_hardened.go
./goshell doctor
```

The tests cover selected functionality; they are **not** a guarantee that every module behaves identically on every operating system or network. Re-run tests and perform controlled integration checks after making changes.

## Quick start

```bash
# Show available commands
./goshell help

# Print the compiled version
./goshell version

# Run built-in self-tests
./goshell doctor

# Gather system information
./goshell sysinfo

# List processes, services, sockets, and routes
./goshell procs
./goshell services
./goshell netstat
./goshell route
```

## Command reference

Use `./goshell help` for the command list shipped in your binary. Flags can vary by command; use the command's help/usage output when available.

| Command | Purpose | Example |
|---|---|---|
| `sysinfo` | Host, OS, runtime, user, environment, and interface information | `./goshell sysinfo` |
| `users` | List local accounts using platform facilities | `./goshell users` |
| `procs` | List running processes | `./goshell procs` |
| `services` | List services | `./goshell services` |
| `netstat` | Show sockets and connections | `./goshell netstat` |
| `route` | Show routing table | `./goshell route` |
| `scan` | Scan TCP ports on one host | `./goshell scan -h 192.0.2.10 -p 22,80,443` |
| `sweep` | Discover hosts in an authorized CIDR using common TCP ports | `./goshell sweep -c 192.0.2.0/24 -p 22,80,443` |
| `banner` | Read service banners from selected ports | `./goshell banner -h 192.0.2.10 -p 22,80` |
| `dnslookup` | Query DNS records | `./goshell dnslookup example.com txt` |
| `revdns` | Reverse DNS lookup | `./goshell revdns 8.8.8.8 1.1.1.1` |
| `httphead` | Inspect HTTP response and page metadata | `./goshell httphead https://example.com` |
| `download` | Download a file over HTTP(S) | `./goshell download -u https://example.com/file.bin -o file.bin` |
| `http` | Serve a directory over HTTP | `./goshell http -dir ./public -p 8000` |
| `hash` | Calculate MD5 and SHA-256 for files | `./goshell hash ./file.bin` |
| `aes` | Encrypt or decrypt a file using AES-256-GCM | `./goshell aes -f ./notes.txt -p 'use-a-long-unique-passphrase'` |
| `zip` | Create or extract a ZIP archive | `./goshell zip -a backup.zip -dir ./data` |
| `doctor` | Run selected built-in self-tests | `./goshell doctor` |
| `privesc` | Audit selected privilege-escalation conditions | `./goshell privesc` |
| `tasks` | Review scheduled tasks / cron configuration | `./goshell tasks` |
| `fw` | Inspect firewall configuration | `./goshell fw` |
| `hunt` | Find paths matching sensitive/config-file patterns | `./goshell hunt -r /home` |

The examples use documentation IP addresses or public example domains where possible. Replace them only with targets you are authorized to assess.

## Scanner examples

### TCP scan

```bash
./goshell scan -h 192.0.2.10 -p 1-1024 -t 800ms -c 128
```

- `-h`: target hostname or IP address.
- `-p`: port range or comma-separated port list.
- `-t`: per-probe timeout.
- `-c`: concurrency; accepted range is 1–4096.
- `-net`: `tcp`, `tcp4`, or `tcp6`.
- `-json`: emit machine-readable JSON on standard output.

Example JSON output:

```bash
./goshell scan -h 192.0.2.10 -p 22,80,443 -json
```

Only ports that accept a TCP connection are reported as open. A closed or filtered result does not prove that a service is absent; firewall rules, routing, rate limits, and timeouts can affect results.

### CIDR discovery

```bash
./goshell sweep -c 192.0.2.0/24 -p 22,80,443,445 -t 700ms
```

This checks a limited set of TCP ports rather than performing ICMP discovery. Hosts that do not accept any configured probe may not be reported even if they are online. Keep the target range small and explicitly authorized.

## File encryption

Encrypt a file:

```bash
./goshell aes -f ./report.txt -p 'a-long-unique-passphrase'
```

By default, the encrypted output is written to `report.txt.enc`.

Decrypt it:

```bash
./goshell aes -f ./report.txt.enc -p 'a-long-unique-passphrase' -d
```

Use a strong, unique passphrase and keep a separate backup of important data. A lost passphrase cannot be recovered by this tool. Avoid putting sensitive passphrases in shell history; use an appropriate secret-handling method for your environment. The command-line passphrase option may be visible to local process-inspection tools while the command runs.

## ZIP archives

Create an archive:

```bash
./goshell zip -a backup.zip -dir ./data
```

Extract an archive:

```bash
mkdir -p ./restore
./goshell zip -a backup.zip -dir ./restore -x
```

The extractor checks for archive paths that escape the destination directory, but you should still treat untrusted archives cautiously and extract them into a new, restricted directory. Review the destination before extraction and do not run extracted files automatically.

## Configuration

The program accepts an optional JSON configuration file through the global `-config` flag or the `GOSHELL_CONFIG` environment variable:

```bash
./goshell -config ./config.json sysinfo
```

If no configuration is provided, built-in defaults are used. Check the `Config` struct in the source for the exact supported fields for the version you built; do not assume fields from another release are supported.

## Output, errors, and exit status

- Normal command output is written to standard output; diagnostics and errors may be written to standard error.
- The TCP scanner supports JSON output with `-json` for automation.
- Invalid commands and command failures return a non-zero process exit status.
- Long-running operations listen for interrupt/termination signals and attempt to cancel work cleanly.
- Results are observations, not a guarantee of vulnerability or compromise. Validate important findings with independent evidence.

## Security and responsible use

- Obtain written authorization and define the scope before scanning.
- Use conservative timeouts and concurrency on production networks.
- Avoid scanning third-party infrastructure, shared hosting, or cloud address ranges without explicit authorization.
- Review collected output before storing or sharing it; inventory may contain usernames, paths, network addresses, and other operationally sensitive details.
- Run with least privilege and protect reports, archives, and encryption keys.
- Do not treat a `WARN`, missing result, or unsuccessful probe as proof of compromise or proof of safety.

## Known limitations

- This is a compact assessment utility, not a replacement for a full vulnerability scanner, EDR, SIEM, or formal security review.
- Results depend on OS, privileges, installed utilities, DNS behavior, firewall policy, and network reachability.
- Some checks are heuristic and can produce false positives or false negatives; manually validate important results.
- The built-in tests cover selected paths, not every supported platform or edge case.
- Rebuild the executable after every source change, and test the exact binary you intend to deploy.

## Development checklist

Before releasing a modified build:

1. Run `gofmt` on changed Go files.
2. Run the test suite and `go vet`.
3. Build a fresh executable from the exact source revision.
4. Run `./goshell version` and `./goshell doctor` against that executable.
5. Test commands on each target operating system and in a controlled lab.
6. Review diffs and test results before publishing release artifacts.

## Credits

**Patrick Hoogeveen — `x0xr00t`**  
**Team Sl0ppyRoot**
