// netpulse-go - Zeek JSON logs -> NetPulse live dashboard (schema v3).
//
// Two data planes, both real, no fake data anywhere:
//
//  1. Traffic chart (up/down): kernel interface counters (/proc/net/dev),
//     tx = upload, rx = download - the same ground truth iftop/nload
//     use, updated every second, independent of Zeek's flush timing
//     (Zeek writes a conn.log row only when a connection CLOSES, so
//     per-second deltas from conn.log read 0 during long transfers).
//     Zeek per-tick deltas remain as a fallback if /proc/net/dev is
//     unreadable.
//
//  2. Flows / protocols / DNS / TLS / ARP / records table: Zeek JSON
//     log rows, tailed live from the END of each file (no history
//     replay). The "live" badge reflects actual row freshness - any
//     parsed row or any conn.log write within the last 90 s - not just
//     file existence. If the Zeek container dies, the badge flips to
//     "collector offline" and the terminal prints how to recover it.
//
// Single-consumer rule: tickUp/tickDown and the iface counter delta are
// read+reset ONLY by engineLoop; every other reader (REST handlers) sees
// the lastUp/lastDown snapshot. st.mu guards all shared state; expire()
// holds it too (a previous version crashed with "concurrent map
// iteration and map write").
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const SEND_FLOWS = 1500

var (
	logsDir   = flag.String("logs", ".", "directory with zeek .log files")
	addr      = flag.String("addr", "127.0.0.1:5001", "listen address (use :5001 to expose on the LAN)")
	htmlPath  = flag.String("html", "index.html", "dashboard html")
	localnets = flag.String("localnets", "192.168.137.0/24,127.0.0.0/8", "local CIDRs")
	expireSec = flag.Int("expire", 300, "flow idle timeout (s)")
)

type Flow struct {
	Rt                     string `json:"rt"`
	Ea                     string `json:"ea"`
	Eap                    uint16 `json:"eap"`
	Eb                     string `json:"eb"`
	Ebp                    uint16 `json:"ebp"`
	P                      string `json:"p"`
	V                      int    `json:"v"`
	Apk                    uint64 `json:"apk"`
	Aby                    uint64 `json:"aby"`
	Bpk                    uint64 `json:"bpk"`
	Bby                    uint64 `json:"bby"`
	Tp                     uint64 `json:"tp"`
	Tby                    uint64 `json:"tby"`
	Rab                    uint64 `json:"rab"`
	Rba                    uint64 `json:"rba"`
	Fs                     int64  `json:"fs"`
	Ls                     int64  `json:"ls"`
	Svc                    string `json:"svc"`
	Loc                    string `json:"loc"`
	Dom                    string `json:"dom"`
	St                     string `json:"st"`
	It                     int    `json:"it"`
	Ic                     int    `json:"ic"`
	IcmpType               int    `json:"icmp_type"`
	IcmpCode               int    `json:"icmp_code"`
	pApk, pAby, pBpk, pBby uint64
}

type ArpConv struct {
	I1  string `json:"i1"`
	M1  string `json:"m1"`
	I2  string `json:"i2"`
	M2  string `json:"m2"`
	P1  uint64 `json:"p1"`
	P2  uint64 `json:"p2"`
	Req uint64 `json:"req"`
	Rep uint64 `json:"rep"`
	Tp  uint64 `json:"tp"`
	Fs  int64  `json:"fs"`
	Ls  int64  `json:"ls"`
}

type State struct {
	mu                         sync.Mutex
	flows                      map[string]*Flow
	dns                        []map[string]any
	tls                        []map[string]any
	arp                        map[string]*ArpConv
	rows                       uint64
	lastIn                     time.Time
	connMod                    time.Time
	logsOK                     bool
	dnsRows, dnsQ, dnsR, dnsNX uint64
	dnsRTT, dnsRTTn            uint64
	tickUp, tickDown           uint64
	lastUp, lastDown           uint64
	lastPps                    uint64
	dirOK                      bool
	upSrc                      string
	iface                      string
	ppszPrev                   uint64

	// TLS normalized model + session aggregates. All TLS statistics derive
	// from these fields only - never from independent counters that can drift.
	tlsIdx                                   map[string]int
	tlsTotal                                 uint64
	tlsVer, tlsAlpn, tlsState                map[string]uint64
	tlsSniVis, tlsSniNo, tlsSniNoEst         uint64
	tlsSrvUnique, tlsJa3Unique, tlsJa4Unique uint64
	tlsSrv                                   map[string]*TlsSrv
	tlsSrvOrd                                []string
	tlsJa3                                   map[string]*TlsJa3
	tlsJa3Ord                                []string
	tlsJa4                                   map[string]*TlsJa4
	tlsJa4Ord                                []string
	tlsSniHosts                              map[string]uint64
	tlsSniOrd                                []string
	tlsRate                                  [60]uint32
	tlsRatePos                               int
}

var (
	st = &State{flows: map[string]*Flow{}, arp: map[string]*ArpConv{},
		tlsIdx: map[string]int{}, tlsVer: map[string]uint64{},
		tlsAlpn: map[string]uint64{}, tlsState: map[string]uint64{},
		tlsSrv: map[string]*TlsSrv{}, tlsJa3: map[string]*TlsJa3{}, tlsJa4: map[string]*TlsJa4{},
		tlsSniHosts: map[string]uint64{}}
	started = time.Now()
	history = struct {
		mu sync.Mutex
		s  []map[string]any
	}{}
	cache = struct {
		mu  sync.Mutex
		raw []byte
	}{}
)

// ---------- helpers ----------

func gs(m map[string]any, k string) string {
	v, ok := m[k]
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

func gu16(m map[string]any, k string) uint16 {
	if v, ok := m[k].(float64); ok {
		return uint16(v)
	}
	return 0
}

func gu64(m map[string]any, k string) uint64 {
	if v, ok := m[k].(float64); ok && v >= 0 {
		return uint64(v)
	}
	return 0
}

func gF64(m map[string]any, k string) float64 {
	if v, ok := m[k].(float64); ok {
		return v
	}
	return 0
}

func firstOf(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v := gs(m, k); v != "" {
			return v
		}
	}
	return ""
}

// hb humanizes a bytes-per-second value for terminal log lines.
func hb(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B/s", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB/s", float64(n)/float64(div), "KMGTPE"[exp])
}

// ---------- localnets ----------

var localList []*net.IPNet

func parseLocalnets(s string) {
	for _, c := range strings.Split(s, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(c); err == nil {
			localList = append(localList, ipnet)
		}
	}
}

func seedLocalInterfaces() {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ipn.IP.IsLoopback() {
				continue
			}
			localList = append(localList, ipn)
		}
	}
}

func isLocalIP(ipstr string) bool {
	ip := net.ParseIP(ipstr)
	if ip == nil {
		return false
	}
	for _, n := range localList {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func locOf(ea, eb string) string {
	if isLocalIP(ea) {
		return "a"
	}
	if isLocalIP(eb) {
		return "b"
	}
	return "none"
}

// ---------- interface counters (live up/down ground truth) ----------

var ifaceStat = struct {
	name   string
	prevRx uint64
	prevTx uint64
	prevAt time.Time
	have   bool
}{}

// defaultRouteIface returns the interface owning the default route
// (Destination 00000000 in /proc/net/route), e.g. eth0 on this VM.
func defaultRouteIface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for i, ln := range lines {
		if i == 0 || ln == "" {
			continue // header / trailing newline
		}
		fs := strings.Fields(ln)
		if len(fs) > 1 && fs[1] == "00000000" {
			return fs[0]
		}
	}
	return ""
}

// readIfaceBytes returns cumulative rx/tx byte counters for one interface.
func readIfaceBytes(name string) (rx, tx uint64, ok bool) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, false
	}
	for _, ln := range strings.Split(string(data), "\n") {
		i := strings.Index(ln, ":")
		if i < 0 {
			continue
		}
		if strings.TrimSpace(ln[:i]) != name {
			continue
		}
		fs := strings.Fields(ln[i+1:])
		if len(fs) < 9 {
			return 0, 0, false
		}
		// fields: rx-bytes packets errs drop fifo frame compressed multicast
		//         tx-bytes ...
		rx, _ = strconv.ParseUint(fs[0], 10, 64)
		tx, _ = strconv.ParseUint(fs[8], 10, 64)
		return rx, tx, true
	}
	return 0, 0, false
}

// busiestIface is the fallback pick when there is no default route:
// the non-loopback interface with the most total bytes seen.
func busiestIface() string {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return ""
	}
	best := ""
	var bestBytes uint64
	for _, ln := range strings.Split(string(data), "\n") {
		i := strings.Index(ln, ":")
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(ln[:i])
		if name == "lo" {
			continue
		}
		fs := strings.Fields(ln[i+1:])
		if len(fs) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fs[0], 10, 64)
		tx, _ := strconv.ParseUint(fs[8], 10, 64)
		if rx+tx > bestBytes {
			best, bestBytes = name, rx+tx
		}
	}
	return best
}

// sampleIface converts cumulative interface counters into per-second
// tx/rx rates. Called once per second from engineLoop ONLY - it is a
// single-consumer counter, exactly like tickUp/tickDown.
func sampleIface(now time.Time) (up, down uint64, ok bool) {
	if ifaceStat.name == "" {
		n := defaultRouteIface()
		if n == "" {
			n = busiestIface()
		}
		if n == "" {
			return 0, 0, false
		}
		ifaceStat.name = n
		fmt.Printf("[*] live rates from interface counters: %s (/proc/net/dev)\n", n)
	}
	rx, tx, ok2 := readIfaceBytes(ifaceStat.name)
	if !ok2 {
		// interface vanished (VPN down, USB NIC removed) -> re-pick next tick
		ifaceStat.name = ""
		ifaceStat.have = false
		return 0, 0, false
	}
	if !ifaceStat.have {
		// first sample: no interval to measure yet -> honest 0
		ifaceStat.prevRx, ifaceStat.prevTx, ifaceStat.prevAt, ifaceStat.have = rx, tx, now, true
		return 0, 0, true
	}
	dt := now.Sub(ifaceStat.prevAt).Seconds()
	if dt < 1 {
		dt = 1
	}
	if rx >= ifaceStat.prevRx && tx >= ifaceStat.prevTx {
		down = uint64(float64(rx-ifaceStat.prevRx) / dt)
		up = uint64(float64(tx-ifaceStat.prevTx) / dt)
	}
	// else: counter went backwards (reboot / iface recreated) -> 0 this
	// interval, baseline refreshed below. Never negative, never faked.
	ifaceStat.prevRx, ifaceStat.prevTx, ifaceStat.prevAt = rx, tx, now
	return up, down, true
}

// ---------- domain cache ----------

var dc = struct {
	mu  sync.Mutex
	m   map[string]string
	ord []string
}{m: map[string]string{}}

func dcGet(ip string) string {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.m[ip]
}

func dcSet(ip, dom string) {
	if ip == "" || dom == "" {
		return
	}
	dc.mu.Lock()
	if _, ok := dc.m[ip]; !ok {
		dc.ord = append(dc.ord, ip)
		if len(dc.ord) > 4096 { // bounded: FIFO eviction of oldest ip->name pairs
			delete(dc.m, dc.ord[0])
			dc.ord = dc.ord[1:]
		}
	}
	dc.m[ip] = dom
	dc.mu.Unlock()
}

func annotate(ip, dom string) {
	if ip == "" || dom == "" {
		return
	}
	for _, f := range st.flows {
		if f.Dom == "" && (f.Ea == ip || f.Eb == ip) {
			f.Dom = dom
		}
	}
}

// ---------- mappers ----------

func mapService(zeek string, ebp, eap uint16, proto string) string {
	switch zeek {
	case "ssl":
		return "HTTPS"
	case "http":
		return "HTTP"
	case "dns":
		return "DNS"
	case "ssh":
		return "SSH"
	case "quic", "quic,ssl", "ssl,quic":
		return "QUIC"
	case "ntp":
		return "NTP"
	case "dhcp":
		return "DHCP"
	case "smb":
		return "SMB"
	case "rdp":
		return "RDP"
	case "ftp":
		return "FTP"
	case "smtp":
		return "SMTP"
	}
	if zeek != "" && zeek != "-" {
		return strings.ToUpper(zeek)
	}
	if proto == "UDP" && ebp == 443 {
		return "QUIC"
	}
	if proto == "TCP" {
		switch ebp {
		case 443:
			return "HTTPS"
		case 80:
			return "HTTP"
		case 22:
			return "SSH"
		case 53:
			return "DNS"
		}
		switch eap {
		case 443:
			return "HTTPS"
		case 80:
			return "HTTP"
		}
	}
	return proto
}

func mapState(cs string) string {
	if strings.Contains(cs, "R") {
		return "reset"
	}
	switch cs {
	case "S0":
		return "connecting"
	case "SF", "S1", "S2", "S3":
		return "closed"
	}
	return "data"
}

func mapVersion(v string) string {
	v = strings.TrimPrefix(v, "TLSv")
	v = strings.TrimPrefix(v, "SSLv")
	switch v {
	case "13":
		return "TLS1.3"
	case "12":
		return "TLS1.2"
	case "11":
		return "TLS1.1"
	case "10":
		return "TLS1.0"
	case "3":
		return "SSLv3"
	case "2":
		return "SSLv2"
	}
	if strings.HasPrefix(v, "1.") {
		return "TLS" + v
	}
	return strings.ToUpper(v)
}

// ---------- ingestion ----------

type tail struct {
	off     int64
	partial string
}

var tails = struct {
	mu sync.Mutex
	m  map[string]*tail
}{m: map[string]*tail{}}

var warnMu sync.Mutex
var warned = map[string]bool{}

func ingestAll() {
	entries, err := os.ReadDir(*logsDir)
	if err != nil {
		return
	}
	now := time.Now()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		kind := strings.TrimSuffix(e.Name(), ".log")
		ingestFile(filepath.Join(*logsDir, e.Name()), kind, now)
	}
	st.mu.Lock()
	if fi, err := os.Stat(filepath.Join(*logsDir, "conn.log")); err == nil {
		st.logsOK = true
		st.connMod = fi.ModTime()
	}
	st.mu.Unlock()
}

func ingestFile(path, kind string, now time.Time) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return
	}

	tails.mu.Lock()
	t, ok := tails.m[path]
	if !ok {
		// First time this file is seen: start LIVE at the end of the file.
		// Replaying the whole pre-existing log would cram hours of old rows
		// into one tick - that was the giant fake-looking burst on startup,
		// after which the chart went flat. Live tail = truthful present.
		t = &tail{off: fi.Size()}
		tails.m[path] = t
	}
	tails.mu.Unlock()

	if fi.Size() < t.off { // truncated / rotated -> re-read from start
		t.off = 0
		t.partial = ""
	}
	if fi.Size() == t.off {
		f.Close()
		return
	}
	if _, err := f.Seek(t.off, io.SeekStart); err != nil {
		f.Close()
		return
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return
	}
	t.off += int64(len(data))

	text := t.partial + string(data)
	ls := strings.Split(text, "\n")
	t.partial = ls[len(ls)-1]

	for i := 0; i < len(ls)-1; i++ {
		ln := strings.TrimRight(ls[i], "\r")
		if ln == "" {
			continue
		}
		processRow(kind, ln, now)
	}
}

// zeekFresh reports whether Zeek rows are actually flowing: any parsed
// row OR any conn.log write inside the freshness window. A stale collector
// must NOT show as "live" - that lie is what hid the dead Zeek container
// behind an empty table. Callers hold st.mu.
const zeekFreshWindow = 90 * time.Second

func zeekFresh(now time.Time) bool {
	if !st.lastIn.IsZero() && now.Sub(st.lastIn) < zeekFreshWindow {
		return true
	}
	if !st.connMod.IsZero() && now.Sub(st.connMod) < zeekFreshWindow {
		return true
	}
	return false
}

func processRow(kind, line string, now time.Time) {
	var row map[string]any
	if err := json.Unmarshal([]byte(line), &row); err != nil {
		warnMu.Lock()
		if !warned[kind] {
			warned[kind] = true
			fmt.Printf("[!] %s.log is not JSON - did you load policy/tuning/json-logs.zeek?\n", kind)
		}
		warnMu.Unlock()
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.rows++
	st.lastIn = now
	switch kind {
	case "conn":
		procConn(row, now)
	case "dns":
		procDNS(row, now)
	case "ssl":
		procSSL(row, now)
	case "arp":
		procARP(row, now)
	case "icmp_live":
		procIcmpLive(row, now)
	case "other_ip":
		procOtherIP(row, now)
	}
}

// ---------- processors (st.mu held) ----------

func procConn(row map[string]any, now time.Time) {
	ea := gs(row, "id.orig_h")
	eb := gs(row, "id.resp_h")
	if ea == "" || eb == "" {
		return
	}
	eap := gu16(row, "id.orig_p")
	ebp := gu16(row, "id.resp_p")
	proto := strings.ToUpper(gs(row, "proto"))
	if proto == "" {
		proto = "TCP"
	}
	v := 4
	if strings.Contains(ea, ":") {
		v = 6
	}
	if proto == "ICMP" && v == 6 {
		proto = "ICMPv6"
	}
	// Zeek logs every non-TCP/UDP/ICMP IP protocol as "unknown_transport";
	// fold them into OTHER so the Other tab and protocol counters see them.
	switch proto {
	case "TCP", "UDP", "ICMP", "ICMPv6":
	default:
		proto = "OTHER"
	}
	icmpType, icmpCode := 0, 0
	if proto == "ICMP" || proto == "ICMPv6" {
		icmpType, icmpCode = int(eap), int(ebp)
	}
	key := fmt.Sprintf("%s:%d|%s:%d|%s", ea, eap, eb, ebp, proto)

	f, ok := st.flows[key]
	if !ok {
		f = &Flow{Rt: "flow", Ea: ea, Eap: eap, Eb: eb, Ebp: ebp,
			P: proto, V: v, Fs: now.Unix(), Loc: locOf(ea, eb)}
		f.Svc = mapService(gs(row, "service"), ebp, eap, proto)
		if d := dcGet(ea); d != "" {
			f.Dom = d
		} else if d := dcGet(eb); d != "" {
			f.Dom = d
		}
		f.St = mapState(gs(row, "conn_state"))
		st.flows[key] = f
	}
	apk, aby := gu64(row, "orig_pkts"), gu64(row, "orig_ip_bytes")
	bpk, bby := gu64(row, "resp_pkts"), gu64(row, "resp_ip_bytes")

	if apk+bpk < f.pApk+f.pBpk { // window reset after mid-connection flush
		f.pApk, f.pAby, f.pBpk, f.pBby = 0, 0, 0, 0
		f.Fs = now.Unix()
	}
	dApk := apk - f.pApk
	if apk < f.pApk {
		dApk = apk
	}
	dAby := aby - f.pAby
	if aby < f.pAby {
		dAby = aby
	}
	dBpk := bpk - f.pBpk
	if bpk < f.pBpk {
		dBpk = bpk
	}
	dBby := bby - f.pBby
	if bby < f.pBby {
		dBby = bby
	}
	f.Apk += dApk
	f.Aby += dAby
	f.Bpk += dBpk
	f.Bby += dBby
	f.Tp = f.Apk + f.Bpk
	f.Tby = f.Aby + f.Bby
	f.pApk, f.pAby, f.pBpk, f.pBby = apk, aby, bpk, bby
	switch f.Loc {
	case "a":
		st.tickUp += dAby
		st.tickDown += dBby
	case "b":
		st.tickUp += dBby
		st.tickDown += dAby
	}
	f.Ls = now.Unix()
	f.St = mapState(gs(row, "conn_state"))
	f.It, f.Ic = icmpType, icmpCode
	f.IcmpType, f.IcmpCode = icmpType, icmpCode
}

func procDNS(row map[string]any, now time.Time) {
	nm := gs(row, "query")
	rc := gs(row, "rcode_name")

	an := []string{}
	if v, ok := row["answers"].([]any); ok {
		for _, a := range v {
			if s, ok := a.(string); ok {
				an = append(an, s)
			}
		}
	}

	// Zeek 8.1 emits rcode/rcode_name on every row (0/NOERROR even without a
	// reply), so direction must be decided by reply EVIDENCE, not by rcode.
	resp := false
	if len(an) > 0 {
		resp = true
	}
	if v, ok := row["TTLs"].([]any); ok && len(v) > 0 {
		resp = true
	}
	if b, ok := row["RA"].(bool); ok && b {
		resp = true
	}
	if gF64(row, "rcode") != 0 {
		resp = true
	}

	qr, stt := "q", "pending"
	if resp {
		qr, stt = "r", "answered"
	}
	if b, ok := row["rejected"].(bool); ok && b {
		stt = "rejected"
	}

	// rcode on a query row is a zero value, not a measurement -> blank it.
	if qr == "q" {
		rc = ""
	}

	ty := gs(row, "qtype_name")
	if ty == "" { // numeric qtype fallback: still real Zeek data
		switch int(gF64(row, "qtype")) {
		case 1:
			ty = "A"
		case 2:
			ty = "NS"
		case 5:
			ty = "CNAME"
		case 6:
			ty = "SOA"
		case 12:
			ty = "PTR"
		case 15:
			ty = "MX"
		case 16:
			ty = "TXT"
		case 28:
			ty = "AAAA"
		case 33:
			ty = "SRV"
		case 65:
			ty = "HTTPS"
		case 255:
			ty = "ANY"
		}
	}

	ts := gF64(row, "ts")
	if ts <= 0 {
		ts = float64(now.Unix())
	}

	ev := map[string]any{
		"t":   int64(ts),
		"id":  gu64(row, "trans_id"),
		"qr":  qr,
		"st":  stt,
		"tr":  strings.ToLower(gs(row, "proto")),
		"nm":  nm,
		"ty":  ty,
		"rc":  rc,
		"an":  an,
		"cl":  gs(row, "id.orig_h"),
		"clp": gu16(row, "id.orig_p"),
		"sv":  gs(row, "id.resp_h"),
		"svp": gu16(row, "id.resp_p"),
		"qt":  int64(ts),
		"rt":  uint64(gF64(row, "rtt") * 1000),
	}

	st.dns = append(st.dns, ev)
	st.dnsRows++
	if len(st.dns) > 500 {
		st.dns = st.dns[len(st.dns)-500:]
	}

	// Counters: exactly one increment per row, outside the trim block.
	if qr == "q" {
		st.dnsQ++
	} else {
		st.dnsR++
	}
	if qr == "r" && rc == "NXDOMAIN" {
		st.dnsNX++
	}
	if ms := uint64(gF64(row, "rtt") * 1000); ms > 0 {
		st.dnsRTT += ms
		st.dnsRTTn++
	}

	if nm != "" {
		for _, a := range an {
			dcSet(a, nm)
			annotate(a, nm)
		}
	}
}

// ---------- TLS normalization + session aggregates ----------
//
// Zeek ssl.log is the only source. Fields the collector does not export stay
// empty ("\u2014" in the UI) - nothing is inferred, nothing is fabricated.
const (
	tlsCap     = 400 // ring of recent normalized events
	tlsTrimTo  = 320
	tlsSrvCap  = 800 // recent-destination window (session totals kept separately)
	tlsJa3Cap  = 800
	tlsJa4Cap  = 800
	tlsSniCap  = 800
	tlsDestCap = 64 // destinations tracked per JA3
	tlsCliCap  = 16 // clients tracked per JA3
)

type TlsSrv struct {
	Conns  uint64
	Failed uint64
	First  int64
	Last   int64
	SNI    string
}

type TlsJa3 struct {
	Conns   uint64
	First   int64
	Last    int64
	Dests   map[string]struct{}
	Clients map[string]struct{}
}

var (
	tlsCommonALPN = map[string]bool{"h2": true, "http/1.1": true, "h3": true,
		"h2c": true, "spdy/3.1": true, "webrtc": true, "c-webrtc": true, "ftp": true,
		"imap": true, "pop3": true, "stun.turn": true, "stun.nat-discovery": true,
		"dot": true, "mqtt": true, "amqp": true}
)

func tlsStateRank(s string) int {
	switch s {
	case "SUCCESS":
		return 3
	case "FAILED":
		return 2
	case "INCOMPLETE":
		return 1
	}
	return 0 // UNKNOWN
}

// tlsBumpOrd increments a bounded recent-unique map with FIFO eviction.
// Evicted keys leave the recent window; session-unique totals are kept in
// separate monotonic counters so cards never drift with eviction.
func tlsBumpOrd(m map[string]uint64, ord *[]string, cap int, k string) {
	if _, ok := m[k]; !ok {
		*ord = append(*ord, k)
		if len(*ord) > cap {
			delete(m, (*ord)[0])
			*ord = (*ord)[1:]
		}
	}
	m[k]++
}

func tlsAggNew(ev map[string]any, now time.Time) {
	t := now.Unix()
	st.tlsTotal++
	if v := gs(ev, "ver"); v != "" {
		st.tlsVer[v]++
	}
	alpn := gs(ev, "alpn")
	if alpn == "" {
		alpn = "unknown"
	}
	st.tlsAlpn[alpn]++
	state := gs(ev, "state")
	st.tlsState[state]++
	if sni := gs(ev, "sni"); sni != "" {
		st.tlsSniVis++
		tlsBumpOrd(st.tlsSniHosts, &st.tlsSniOrd, tlsSniCap, sni)
	} else {
		st.tlsSniNo++
		if state == "SUCCESS" {
			st.tlsSniNoEst++
		}
	}
	if ep := gs(ev, "ep"); ep != "" {
		s, ok := st.tlsSrv[ep]
		if !ok {
			if len(st.tlsSrvOrd) >= tlsSrvCap {
				delete(st.tlsSrv, st.tlsSrvOrd[0])
				st.tlsSrvOrd = st.tlsSrvOrd[1:]
			}
			s = &TlsSrv{First: t}
			st.tlsSrv[ep] = s
			st.tlsSrvOrd = append(st.tlsSrvOrd, ep)
			st.tlsSrvUnique++
		}
		s.Conns++
		s.Last = t
		if state == "FAILED" {
			s.Failed++
		}
		if sni := gs(ev, "sni"); sni != "" {
			s.SNI = sni
		}
	}
	if j := gs(ev, "ja3"); j != "" {
		tlsJa3Add(j, ev, now)
	}
	if j := gs(ev, "ja4"); j != "" {
		tlsJa4Add(j, ev, now)
	}
	st.tlsRate[st.tlsRatePos]++
}

func tlsJa3Add(j string, ev map[string]any, now time.Time) {
	t := now.Unix()
	a, ok := st.tlsJa3[j]
	if !ok {
		if len(st.tlsJa3Ord) >= tlsJa3Cap {
			delete(st.tlsJa3, st.tlsJa3Ord[0])
			st.tlsJa3Ord = st.tlsJa3Ord[1:]
		}
		a = &TlsJa3{First: t, Dests: map[string]struct{}{}, Clients: map[string]struct{}{}}
		st.tlsJa3[j] = a
		st.tlsJa3Ord = append(st.tlsJa3Ord, j)
		st.tlsJa3Unique++
	}
	a.Conns++
	a.Last = t
	if ep := gs(ev, "ep"); ep != "" && len(a.Dests) < tlsDestCap {
		a.Dests[ep] = struct{}{}
	}
	if cl := gs(ev, "cl"); cl != "" && len(a.Clients) < tlsCliCap {
		a.Clients[cl] = struct{}{}
	}
}

// tlsMerge folds a second ssl.log row for the same uid into the stored event
// (Zeek may log an attempt first and the established handshake later).
// Aggregates are adjusted by delta so counters always equal the event set.
func tlsMerge(old, nw map[string]any, now time.Time) {
	sniBefore := gs(old, "sni") == ""
	estBefore := gs(old, "state") == "SUCCESS"

	ns := gs(nw, "state")
	if os := gs(old, "state"); tlsStateRank(ns) > tlsStateRank(os) {
		if st.tlsState[os] > 0 {
			st.tlsState[os]--
		}
		st.tlsState[ns]++
		old["state"] = ns
	}
	for _, k := range []string{"sni", "ver", "alpn", "ja3", "ja3s", "ja4", "ja4s", "cipher", "curve", "alert", "hist", "valid"} {
		if gs(old, k) != "" || gs(nw, k) == "" {
			continue
		}
		old[k] = nw[k]
		switch k {
		case "sni":
			tlsBumpOrd(st.tlsSniHosts, &st.tlsSniOrd, tlsSniCap, nw[k].(string))
			if sv := gs(old, "sv"); sv != "" {
				dcSet(sv, nw[k].(string))
				annotate(sv, nw[k].(string))
			}
			if ep := gs(old, "ep"); ep != "" {
				if s, ok := st.tlsSrv[ep]; ok {
					s.SNI = nw[k].(string)
				}
			}
		case "ver":
			st.tlsVer[nw[k].(string)]++
		case "alpn":
			// move the event's ALPN bucket (it counted as "unknown" so far)
			if st.tlsAlpn["unknown"] > 0 {
				st.tlsAlpn["unknown"]--
			}
			st.tlsAlpn[nw[k].(string)]++
		case "ja3":
			tlsJa3Add(nw[k].(string), old, now)
		case "ja4":
			tlsJa4Add(nw[k].(string), old, now)
		}
	}
	// SNI visibility accounting, adjusted by the event's contribution delta:
	// contribution = (no SNI) -> sni_no, plus sni_no_est when state==SUCCESS.
	if sniBefore && gs(old, "sni") != "" {
		st.tlsSniNo--
		st.tlsSniVis++
	}
	if sniBefore && !estBefore && gs(old, "sni") == "" && gs(old, "state") == "SUCCESS" {
		st.tlsSniNoEst++
	}
	if b, ok := nw["resumed"].(bool); ok && b {
		old["resumed"] = true
	}
}

func procSSL(row map[string]any, now time.Time) {
	sni := zStr(row, "server_name")
	ver := mapVersion(gs(row, "version"))
	alpn := zStr(row, "next_protocol")
	cl, sv := gs(row, "id.orig_h"), gs(row, "id.resp_h")
	clp, svp := gu16(row, "id.orig_p"), gu16(row, "id.resp_p")
	uid := gs(row, "uid")

	est := -1
	if b, ok := row["established"].(bool); ok {
		if b {
			est = 1
		} else {
			est = 0
		}
	}
	state := "UNKNOWN"
	switch est {
	case 1:
		state = "SUCCESS"
	case 0:
		if zStr(row, "last_alert") != "" {
			state = "FAILED"
		} else {
			state = "INCOMPLETE"
		}
	}
	resumed := false
	if b, ok := row["resumed"].(bool); ok {
		resumed = b
	}
	fk := ""
	if cl != "" && sv != "" {
		fk = fmt.Sprintf("%s:%d|%s:%d|TCP", cl, clp, sv, svp)
	}
	ep := ""
	if sv != "" {
		ep = fmt.Sprintf("%s:%d", sv, svp)
	}
	ev := map[string]any{
		"rt": "tls", "t": now.Unix(), "hs": "handshake",
		"sni": sni, "ver": ver, "alpn": alpn,
		"cl": cl, "clp": clp, "sv": sv, "svp": svp, "ep": ep,
		"uid":    uid,
		"ja3":    gs(row, "ja3"),
		"ja3s":   gs(row, "ja3s"),
		"ja4":    gs(row, "ja4"),
		"ja4s":   gs(row, "ja4s"),
		"cipher": zStr(row, "cipher"), "curve": zStr(row, "curve"),
		"resumed": resumed, "state": state,
		"alert": zStr(row, "last_alert"), "hist": zStr(row, "ssl_history"),
		"valid": zStr(row, "validation_status"), "fk": fk,
	}

	// One uid = one TLS connection. Merge later rows instead of counting them
	// twice (attempt row + established row, renegotiations).
	if uid != "" {
		if idx, ok := st.tlsIdx[uid]; ok && idx >= 0 && idx < len(st.tls) {
			if old := st.tls[idx]; gs(old, "uid") == uid {
				tlsMerge(old, ev, now)
				return
			}
		}
	}
	st.tls = append(st.tls, ev)
	if uid != "" {
		st.tlsIdx[uid] = len(st.tls) - 1
	}
	if len(st.tls) > tlsCap {
		for _, e := range st.tls[:len(st.tls)-tlsTrimTo] {
			if u := gs(e, "uid"); u != "" {
				delete(st.tlsIdx, u)
			}
		}
		st.tls = st.tls[len(st.tls)-tlsTrimTo:]
		for i, e := range st.tls { // indexes shifted by the reslice
			if u := gs(e, "uid"); u != "" {
				st.tlsIdx[u] = i
			}
		}
	}
	tlsAggNew(ev, now)
	if sni != "" && sv != "" {
		dcSet(sv, sni)
		annotate(sv, sni)
	}
}

// zStr reads a Zeek string field, mapping the "unset" sentinel "-" to "".
func zStr(m map[string]any, k string) string {
	v := gs(m, k)
	if v == "-" {
		return ""
	}
	return v
}

func procARP(row map[string]any, now time.Time) {
	i1 := firstOf(row, "src_ip", "spa", "orig_h")
	i2 := firstOf(row, "dst_ip", "tpa", "resp_h")
	if i1 == "" || i2 == "" || i1 == i2 {
		return
	}
	a, b := i1, i2
	if a > b {
		a, b = b, a
	}
	key := a + "|" + b
	c, ok := st.arp[key]
	if !ok {
		c = &ArpConv{I1: a, I2: b, Fs: now.Unix()}
		st.arp[key] = c
	}
	mac1 := firstOf(row, "src_mac", "sha")
	mac2 := firstOf(row, "dst_mac", "tha")
	if i1 == c.I1 {
		c.P1++
		if mac1 != "" {
			c.M1 = mac1
		}
	} else {
		c.P2++
		if mac1 != "" {
			c.M2 = mac1
		}
	}
	if mac2 != "" {
		if i2 == c.I1 {
			c.M1 = mac2
		} else {
			c.M2 = mac2
		}
	}
	op := strings.ToLower(gs(row, "op") + gs(row, "operation"))
	switch {
	case op == "1" || strings.Contains(op, "request"):
		c.Req++
	case op == "2" || strings.Contains(op, "reply"):
		c.Rep++
	}
	c.Tp = c.P1 + c.P2
	c.Ls = now.Unix()
}

func procIcmpLive(row map[string]any, now time.Time) {
	ea := gs(row, "orig_h")
	eb := gs(row, "resp_h")
	if ea == "" || eb == "" {
		return
	}
	proto := "ICMP"
	v := 4
	if strings.Contains(ea, ":") {
		proto, v = "ICMPv6", 6
	}
	eap := gu16(row, "itype")
	ebp := gu16(row, "icode")
	key := fmt.Sprintf("%s:%d|%s:%d|%s", ea, eap, eb, ebp, proto)
	f, ok := st.flows[key]
	if !ok {
		f = &Flow{Rt: "flow", Ea: ea, Eap: eap, Eb: eb, Ebp: ebp,
			P: proto, V: v, Fs: now.Unix(), Loc: locOf(ea, eb)}
		f.Svc = proto
		f.St = "data"
		if d := dcGet(ea); d != "" {
			f.Dom = d
		} else if d := dcGet(eb); d != "" {
			f.Dom = d
		}
		st.flows[key] = f
	}
	if eap != 0 && f.It == 0 {
		f.It, f.Ic = int(eap), int(ebp)
		f.IcmpType, f.IcmpCode = int(eap), int(ebp)
	}
	f.Ls = now.Unix()
}

// ---------- expiry ----------

// expire runs in engineLoop only, but buildPayload (HTTP handlers) reads
// and even mutates flows under st.mu, so this MUST hold st.mu too -
// otherwise Go can fatal-error with "concurrent map iteration and map
// write" and kill the whole bridge (chart freezes, SSE dies).
func expire(now time.Time) {
	st.mu.Lock()
	for k, f := range st.flows {
		if now.Unix()-f.Ls > int64(*expireSec) {
			delete(st.flows, k)
		}
	}
	st.mu.Unlock()
}

// ---------- payload ----------

type agg struct {
	bytes uint64
	count uint64
	ips   []string
	last  int64
}

type namedAgg struct {
	Name  string   `json:"name"`
	Bytes uint64   `json:"bytes"`
	Count uint64   `json:"count"`
	Ips   []string `json:"ips,omitempty"`
	Last  int64    `json:"last,omitempty"`
}

func buildPayload(now time.Time) map[string]any {
	st.mu.Lock()
	defer st.mu.Unlock()
	live := st.logsOK && zeekFresh(now)
	dirKnown := st.dirOK

	flows := make([]*Flow, 0, len(st.flows))
	protos := map[string]int{"TCP": 0, "UDP": 0, "ICMP": 0, "ICMPv6": 0, "OTHER": 0}
	services := map[string]*agg{}
	domains := map[string]*agg{}
	endpoints := map[string]*agg{}
	var totPk, totBy uint64

	for _, f := range st.flows {
		el := now.Unix() - f.Fs
		if el < 1 {
			el = 1
		}
		f.Rab = f.Aby / uint64(el)
		f.Rba = f.Bby / uint64(el)
		flows = append(flows, f)
		protos[f.P]++
		totPk += f.Tp
		totBy += f.Tby
		s := services[f.Svc]
		if s == nil {
			s = &agg{}
			services[f.Svc] = s
		}
		s.bytes += f.Tby
		s.count++
		if f.Dom != "" {
			d := domains[f.Dom]
			if d == nil {
				d = &agg{ips: []string{}}
				domains[f.Dom] = d
			}
			d.bytes += f.Tby
			d.count++
			if f.Ls > d.last {
				d.last = f.Ls
			}
			for _, ip := range []string{f.Ea, f.Eb} {
				found := false
				for _, x := range d.ips {
					if x == ip {
						found = true
					}
				}
				if !found && len(d.ips) < 6 {
					d.ips = append(d.ips, ip)
				}
			}
		}
		le := ""
		if f.Loc == "a" {
			le = f.Ea
		} else if f.Loc == "b" {
			le = f.Eb
		}
		if le != "" {
			e := endpoints[le]
			if e == nil {
				e = &agg{}
				endpoints[le] = e
			}
			e.bytes += f.Tby
			e.count++
		}
	}
	sort.Slice(flows, func(i, j int) bool { return flows[i].Tby > flows[j].Tby })
	fcut := 0
	if len(flows) > SEND_FLOWS {
		fcut = len(flows) - SEND_FLOWS
		flows = flows[:SEND_FLOWS]
	}

	svcList := []namedAgg{}
	for k, v := range services {
		svcList = append(svcList, namedAgg{Name: k, Bytes: v.bytes, Count: v.count})
	}
	sort.Slice(svcList, func(i, j int) bool { return svcList[i].Bytes > svcList[j].Bytes })
	if len(svcList) > 10 {
		svcList = svcList[:10]
	}
	domList := []namedAgg{}
	for k, v := range domains {
		domList = append(domList, namedAgg{Name: k, Bytes: v.bytes, Count: v.count, Ips: v.ips, Last: v.last})
	}
	sort.Slice(domList, func(i, j int) bool { return domList[i].Bytes > domList[j].Bytes })
	if len(domList) > 50 {
		domList = domList[:50]
	}
	epList := []namedAgg{}
	for k, v := range endpoints {
		epList = append(epList, namedAgg{Name: k, Bytes: v.bytes, Count: v.count})
	}
	sort.Slice(epList, func(i, j int) bool { return epList[i].Bytes > epList[j].Bytes })
	if len(epList) > 10 {
		epList = epList[:10]
	}

	// Snapshot rates written once per second by engineLoop. Never consumed
	// here: REST callers hit this function too, and consuming tick counters
	// in a payload builder would let any poll steal traffic from the chart.
	up, down := st.lastUp, st.lastDown

	var dnsQ, dnsP, dnsM int
	for _, e := range st.dns {
		if e["qr"] == "q" {
			dnsQ++
		}
		if e["st"] == "pending" {
			dnsP++
		}
		if e["st"] == "malformed" {
			dnsM++
		}
	}

	// pps is computed by engineLoop (single writer). buildPayload used to
	// advance the pps window too, so every REST call corrupted the rate.
	pps := st.lastPps

	dnsDrop := uint64(0)
	if st.dnsRows > uint64(len(st.dns)) {
		dnsDrop = st.dnsRows - uint64(len(st.dns))
	}
	avgRTT := uint64(0)
	if st.dnsRTTn > 0 {
		avgRTT = st.dnsRTT / st.dnsRTTn
	}

	health := map[string]any{
		"recv": st.rows, "drop": 0, "ifdrop": 0, "p4": 0, "p6": 0,
		"arp": 0, "nonip": 0, "frag": 0, "fragby": 0, "trunc": 0, "err": 0,
		"tf": 0, "flows": len(st.flows), "pps": pps,
		"dnsq": dnsQ, "dnsr": len(st.dns) - dnsQ, "mal": dnsM, "pend": dnsP,
		"arpt": len(st.arp), "tlsch": len(st.tls), "tlssh": 0,
		"up_s":      int64(now.Sub(started).Seconds()),
		"dns_total": st.dnsRows, "dns_total_q": st.dnsQ,
		"dns_total_r": st.dnsR, "dns_nx": st.dnsNX,
		"dns_avg_rtt": avgRTT,
	}

	history.mu.Lock()
	hist := append([]map[string]any{}, history.s...)
	history.mu.Unlock()
	if len(hist) > 90 {
		hist = hist[len(hist)-90:]
	}

	dnsCopy := append([]map[string]any{}, st.dns...)
	if len(dnsCopy) > 150 {
		dnsCopy = dnsCopy[len(dnsCopy)-150:]
	}
	tlsList := tlsEnriched(300)
	tlsStats := buildTLSStats(now.Unix())
	arpList := []map[string]any{}
	for _, a := range st.arp {
		arpList = append(arpList, map[string]any{
			"rt": "arp", "i1": a.I1, "m1": a.M1, "i2": a.I2, "m2": a.M2,
			"p1": a.P1, "p2": a.P2, "req": a.Req, "rep": a.Rep,
			"tp": a.Tp, "fs": a.Fs, "ls": a.Ls})
	}

	return map[string]any{
		"now": now.Unix(), "updated": time.Now(), "live": live,
		"dir_known": dirKnown, "iface": st.iface, "up_src": st.upSrc,
		"totals": map[string]any{"flows": len(flows), "packets": totPk,
			"bytes": totBy, "up": up, "down": down, "pps": pps,
			"arp": len(arpList), "dns_events": len(dnsCopy)},
		"protos": protos, "services": svcList, "domains": domList,
		"endpoints": epList, "history": hist,
		"flows": flows, "fcut": fcut,
		"dns": dnsCopy, "dnsdrop": dnsDrop,
		"arp": arpList, "tls": tlsList, "tls_stats": tlsStats,
		"health": health,
	}
}

// tlsEnriched returns copies of the recent TLS ring with only OBSERVED
// correlations attached (DNS names seen in dns.log answers/SNI, conn.log flow
// totals). Used by both the SSE payload and /api/tls so views agree.
// Nothing is inferred; an expired flow simply leaves the field absent.
// Caller holds st.mu.
func tlsEnriched(limit int) []map[string]any {
	src := st.tls
	if len(src) > limit {
		src = src[len(src)-limit:]
	}
	out := make([]map[string]any, 0, len(src))
	for _, e := range src {
		c := make(map[string]any, len(e)+3)
		for k, v := range e {
			c[k] = v
		}
		if sv := gs(c, "sv"); sv != "" {
			if d := dcGet(sv); d != "" {
				c["dnsname"] = d
			}
		}
		if fk := gs(c, "fk"); fk != "" {
			if f, ok := st.flows[fk]; ok && f != nil {
				c["fby"], c["fpk"] = f.Tby, f.Tp
			}
		}
		out = append(out, c)
	}
	return out
}

// buildTLSStats derives every TLS statistic from the same aggregate state the
// event counters update - one source, no drift. Caller holds st.mu.
func buildTLSStats(now int64) map[string]any {
	ver := make(map[string]uint64, len(st.tlsVer))
	for k, v := range st.tlsVer {
		ver[k] = v
	}
	alpn := make(map[string]uint64, len(st.tlsAlpn))
	for k, v := range st.tlsAlpn {
		alpn[k] = v
	}
	state := make(map[string]uint64, len(st.tlsState))
	for k, v := range st.tlsState {
		state[k] = v
	}
	rate := make([]uint32, 60)
	for i := 0; i < 60; i++ {
		rate[i] = st.tlsRate[(st.tlsRatePos+1+i)%60]
	}

	type ja3Row struct {
		j      string
		n      uint64
		d, c   int
		fs, ls int64
	}
	ja3s := make([]ja3Row, 0, len(st.tlsJa3))
	for k, a := range st.tlsJa3 {
		ja3s = append(ja3s, ja3Row{k, a.Conns, len(a.Dests), len(a.Clients), a.First, a.Last})
	}
	sort.Slice(ja3s, func(i, j int) bool { return ja3s[i].n > ja3s[j].n })
	topJa3 := make([]map[string]any, 0, 8)
	for i, r := range ja3s {
		if i == 8 {
			break
		}
		topJa3 = append(topJa3, map[string]any{
			"j": r.j, "n": r.n, "d": r.d, "c": r.c, "fs": r.fs, "ls": r.ls})
	}

	ja4s := make([]ja3Row, 0, len(st.tlsJa4))
	for k, a := range st.tlsJa4 {
		ja4s = append(ja4s, ja3Row{k, a.Conns, len(a.Dests), len(a.Clients), a.First, a.Last})
	}
	sort.Slice(ja4s, func(i, j int) bool { return ja4s[i].n > ja4s[j].n })
	topJa4 := make([]map[string]any, 0, 8)
	for i, r := range ja4s {
		if i == 8 {
			break
		}
		topJa4 = append(topJa4, map[string]any{
			"j": r.j, "n": r.n, "d": r.d, "c": r.c, "fs": r.fs, "ls": r.ls})
	}

	type srvRow struct {
		ep, sni string
		n, fail uint64
		fs, ls  int64
	}
	srvs := make([]srvRow, 0, len(st.tlsSrv))
	for k, s := range st.tlsSrv {
		srvs = append(srvs, srvRow{k, s.SNI, s.Conns, s.Failed, s.First, s.Last})
	}
	sort.Slice(srvs, func(i, j int) bool { return srvs[i].n > srvs[j].n })
	topSrv := make([]map[string]any, 0, 10)
	for i, r := range srvs {
		if i == 10 {
			break
		}
		topSrv = append(topSrv, map[string]any{
			"ep": r.ep, "sni": r.sni, "n": r.n, "fail": r.fail, "fs": r.fs, "ls": r.ls})
	}

	// ---- security signals: informational observations, never verdicts ----
	sigs := []map[string]any{}
	addSig := func(k, t, d string, n uint64) {
		if len(sigs) < 8 {
			sigs = append(sigs, map[string]any{"k": k, "t": t, "d": d, "n": n})
		}
	}
	for _, lv := range []string{"SSLv2", "SSLv3", "TLS1.0", "TLS1.1"} {
		if n := st.tlsVer[lv]; n > 0 {
			addSig("legacy", lv+" in use",
				"legacy protocol version observed - informational, not a verdict", n)
		}
	}
	rareN := uint64(0)
	for _, a := range st.tlsJa3 {
		if a.Conns == 1 {
			rareN++
		}
	}
	if rareN > 0 {
		addSig("rare_ja3", fmt.Sprintf("%d JA3 seen once", rareN),
			"rarity within this session - signal, not a verdict", rareN)
	}
	newJa3 := uint64(0)
	for _, a := range st.tlsJa3 {
		if now-a.First >= 0 && now-a.First <= 300 {
			newJa3++
		}
	}
	if newJa3 > 0 {
		addSig("new_ja3", fmt.Sprintf("%d JA3 first seen in last 5 min", newJa3),
			"baseline is session-scoped (bridge uptime only) - signal, not a verdict", newJa3)
	}
	worstEp, worstN := "", uint64(0)
	for k, s := range st.tlsSrv {
		if s.Failed >= 3 && s.Failed > worstN {
			worstN, worstEp = s.Failed, k
		}
	}
	if worstEp != "" {
		addSig("failures", worstEp+" - repeated handshake failures",
			"failed handshakes are network events, not automatically malicious", worstN)
	}
	newDest := uint64(0)
	for _, s := range st.tlsSrv {
		if now-s.First >= 0 && now-s.First <= 120 {
			newDest++
		}
	}
	if newDest > 0 {
		addSig("new_dest", fmt.Sprintf("%d destinations first seen in last 2 min", newDest),
			"baseline is session-scoped - signal, not a verdict", newDest)
	}
	for a, n := range st.tlsAlpn {
		if a != "unknown" && !tlsCommonALPN[a] {
			addSig("alpn", "Uncommon ALPN: "+a,
				"outside the common ALPN set - informational", n)
		}
	}
	if st.tlsSniNo > 0 {
		addSig("sni", fmt.Sprintf("%d connections without SNI", st.tlsSniNo),
			"TLS 1.3 resumption, ECH or incomplete handshakes can hide SNI - reduced visibility, not a verdict", st.tlsSniNo)
	}

	hasCipher := false
	for _, e := range st.tls {
		if gs(e, "cipher") != "" {
			hasCipher = true
			break
		}
	}
	return map[string]any{
		"total": st.tlsTotal, "shown": len(st.tls),
		"ver": ver, "alpn": alpn, "state": state,
		"sni_vis": st.tlsSniVis, "sni_no": st.tlsSniNo, "sni_no_est": st.tlsSniNoEst,
		"servers": st.tlsSrvUnique, "ja3_n": st.tlsJa3Unique, "ja4_n": st.tlsJa4Unique, "sni_hosts": len(st.tlsSniHosts),
		"has_ja3": st.tlsJa3Unique > 0, "has_ja4": st.tlsJa4Unique > 0, "has_cipher": hasCipher,
		"rate": rate, "top_ja3": topJa3, "top_ja4": topJa4, "top_srv": topSrv, "signals": sigs,
	}
}

// ---------- engine loop ----------

func engineLoop() {
	ingestAll()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastTick := time.Now()
	statusN := 0
	lastWarn := time.Time{}
	zeekWasSilent := false
	for now := range tick.C {
		ingestAll()

		st.mu.Lock()
		dt := now.Sub(lastTick).Seconds()
		if dt < 1 {
			dt = 1
		}
		lastTick = now

		// Single consumer of the per-tick byte deltas. Everything else
		// (REST handlers) reads the lastUp/lastDown snapshot via buildPayload.
		zUp, zDown := st.tickUp, st.tickDown
		st.tickUp, st.tickDown = 0, 0

		var up, down uint64
		if iu, id, ok := sampleIface(now); ok {
			// Kernel interface counters: the truthful live source.
			// tx = upload, rx = download.
			up, down = iu, id
			st.dirOK = true
			st.upSrc = "iface"
			st.iface = ifaceStat.name
		} else {
			// No /proc/net/dev: fall back to Zeek deltas as a TOTAL rate
			// (dir_known=false makes the dashboard label it honestly).
			down = zUp + zDown
			up = 0
			st.dirOK = false
			st.upSrc = "zeek"
			st.iface = ""
		}
		st.lastUp, st.lastDown = up, down

		// log rows/s - computed here only, single writer
		pps := uint64(0)
		if st.rows >= st.ppszPrev {
			pps = uint64(float64(st.rows-st.ppszPrev) / dt)
		}
		st.ppszPrev = st.rows
		st.lastPps = pps

		// TLS connection-rate window: one bucket per second, rotated here by
		// the single writer. The payload only copies - never advances it.
		if n := int(dt); n > 0 {
			if n > 60 {
				n = 60
			}
			for i := 0; i < n; i++ {
				st.tlsRatePos = (st.tlsRatePos + 1) % 60
				st.tlsRate[st.tlsRatePos] = 0
			}
		}

		flowsN := len(st.flows)
		lastRow := st.lastIn
		st.mu.Unlock()

		// Zeek silence watchdog: the chart keeps working from interface
		// counters even when the collector is dead - say so loudly instead
		// of leaving an empty table unexplained.
		silence := time.Duration(0)
		if lastRow.IsZero() {
			silence = now.Sub(started)
		} else {
			silence = now.Sub(lastRow)
		}
		if silence > 30*time.Second {
			if lastWarn.IsZero() {
				fmt.Printf("[!] no Zeek rows for %v - flows/protocols/DNS/table stay EMPTY (chart still live from iface counters)\n", silence.Round(time.Second))
				fmt.Printf("    check the collector:  docker ps | grep -i zeek ; docker logs --tail 20 netpulse-zeek\n")
				lastWarn = now
				zeekWasSilent = true
			} else if now.Sub(lastWarn) >= 30*time.Second {
				fmt.Printf("[!] still no Zeek rows (%v) - collector is not writing to %s\n", silence.Round(time.Second), *logsDir)
				lastWarn = now
			}
		} else if zeekWasSilent && silence < 2*time.Second {
			fmt.Printf("[*] Zeek rows flowing again\n")
			zeekWasSilent = false
			lastWarn = time.Time{}
		}

		p := buildPayload(now)
		tot := p["totals"].(map[string]any)

		history.mu.Lock()
		history.s = append(history.s, map[string]any{
			"t": p["now"], "up": tot["up"], "down": tot["down"], "pps": tot["pps"]})
		if len(history.s) > 180 {
			history.s = history.s[len(history.s)-180:]
		}
		history.mu.Unlock()

		raw, _ := json.Marshal(p)
		cache.mu.Lock()
		cache.raw = raw
		cache.mu.Unlock()

		expire(time.Now())

		statusN++
		if statusN >= 15 {
			statusN = 0
			src := st.upSrc
			if src == "iface" {
				src = "iface:" + ifaceStat.name
			}
			fmt.Printf("[pulse] rows/s=%d src=%s up=%s down=%s flows=%d\n",
				pps, src, hb(up), hb(down), flowsN)
		}
	}
}

// ---------- HTTP ----------

func indexHandler(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(*htmlPath)
	if err != nil {
		http.Error(w, "dashboard html missing - run the index.html extraction step", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func streamHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	fl, ok := w.(http.Flusher)
	if !ok {
		return
	}
	for {
		cache.mu.Lock()
		raw := cache.raw
		cache.mu.Unlock()
		if raw != nil {
			if _, err := fmt.Fprintf(w, "data: %s\n\n", raw); err != nil {
				return // client gone
			}
			fl.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func flowsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildPayload(time.Now()))
}

func flowsProtoHandler(w http.ResponseWriter, r *http.Request) {
	proto := strings.TrimPrefix(r.URL.Path, "/api/flows/")
	want, ok := map[string]string{"tcp": "TCP", "udp": "UDP", "icmp": "ICMP",
		"icmpv6": "ICMPv6", "other": "OTHER"}[strings.ToLower(proto)]
	if !ok {
		http.Error(w, "unknown protocol", 404)
		return
	}
	st.mu.Lock()
	out := []*Flow{}
	for _, f := range st.flows {
		if f.P == want {
			out = append(out, f)
		}
	}
	live := st.logsOK
	st.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Tby > out[j].Tby })
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"proto": want, "count": len(out),
		"live": live, "flows": out})
}

func dnsHandler(w http.ResponseWriter, r *http.Request) {
	st.mu.Lock()
	d := append([]map[string]any{}, st.dns...)
	drop := uint64(0)
	if st.dnsRows > uint64(len(st.dns)) {
		drop = st.dnsRows - uint64(len(st.dns))
	}
	st.mu.Unlock()
	if len(d) > 300 {
		d = d[len(d)-300:]
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"dns": d, "dnsdrop": drop})
}

func tlsHandler(w http.ResponseWriter, r *http.Request) {
	st.mu.Lock()
	t := tlsEnriched(300)
	stats := buildTLSStats(time.Now().Unix())
	st.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"tls": t, "stats": stats})
}

func arpHandler(w http.ResponseWriter, r *http.Request) {
	st.mu.Lock()
	a := []map[string]any{}
	for _, c := range st.arp {
		a = append(a, map[string]any{"rt": "arp", "i1": c.I1, "m1": c.M1,
			"i2": c.I2, "m2": c.M2, "p1": c.P1, "p2": c.P2,
			"req": c.Req, "rep": c.Rep, "tp": c.Tp, "fs": c.Fs, "ls": c.Ls})
	}
	st.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"arp": a})
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	p := buildPayload(time.Now())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"live": p["live"],
		"totals": p["totals"],
		"protos": p["protos"], "services": p["services"],
		"domains": p["domains"], "endpoints": p["endpoints"],
		"history": p["history"], "dir_known": p["dir_known"],
		"iface": p["iface"], "up_src": p["up_src"]})
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	st.mu.Lock()
	ok := st.logsOK
	fresh := ok && zeekFresh(time.Now())
	st.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"collector_connected": ok, "fresh": fresh, "stale": !fresh,
		"note": "collector = zeek json logs; fresh = rows within last 90s"})
}

func ipHandler(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"your_ip": ip})
}

// ---------- main ----------

func main() {
	flag.Parse()
	seedLocalInterfaces()
	parseLocalnets(*localnets)

	names := []string{}
	for _, n := range localList {
		names = append(names, n.String())
	}
	fmt.Printf("[*] NetPulse Go bridge on %s (logs=%s)\n", *addr, *logsDir)
	fmt.Printf("[*] local networks for flow direction: %s\n", strings.Join(names, ", "))

	if _, err := os.Stat(*htmlPath); err != nil {
		fmt.Println("[!] dashboard html not found - run the index.html extraction step")
	}

	go engineLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/api/stream", streamHandler)
	mux.HandleFunc("/api/flows", flowsHandler)
	mux.HandleFunc("/api/flows/", flowsProtoHandler)
	mux.HandleFunc("/api/dns", dnsHandler)
	mux.HandleFunc("/api/tls", tlsHandler)
	mux.HandleFunc("/api/arp", arpHandler)
	mux.HandleFunc("/api/stats", statsHandler)
	mux.HandleFunc("/api/status", statusHandler)
	mux.HandleFunc("/api/ip", ipHandler)

	log.Fatal(http.ListenAndServe(*addr, mux))
}

type TlsJa4 struct {
	Conns   uint64
	First   int64
	Last    int64
	Dests   map[string]struct{}
	Clients map[string]struct{}
}

func tlsJa4Add(j string, ev map[string]any, now time.Time) {
	t := now.Unix()
	a, ok := st.tlsJa4[j]
	if !ok {
		if len(st.tlsJa4Ord) >= tlsJa4Cap {
			delete(st.tlsJa4, st.tlsJa4Ord[0])
			st.tlsJa4Ord = st.tlsJa4Ord[1:]
		}
		a = &TlsJa4{First: t, Dests: map[string]struct{}{}, Clients: map[string]struct{}{}}
		st.tlsJa4[j] = a
		st.tlsJa4Ord = append(st.tlsJa4Ord, j)
		st.tlsJa4Unique++
	}
	a.Conns++
	a.Last = t
	if ep := gs(ev, "ep"); ep != "" && len(a.Dests) < tlsDestCap {
		a.Dests[ep] = struct{}{}
	}
	if cl := gs(ev, "cl"); cl != "" && len(a.Clients) < tlsCliCap {
		a.Clients[cl] = struct{}{}
	}
}

// ---------- other IP protocols (other_ip.log from other_ip.zeek) ----------

// ipProtoNames names the IP protocol numbers seen in other_ip.log.
var ipProtoNames = map[int]string{
	2: "IGMP", 4: "IPIP", 41: "IPv6-in-IP", 47: "GRE", 50: "ESP", 51: "AH",
	88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP", 115: "L2TP",
	132: "SCTP", 136: "UDPLite", 137: "MPLS-in-IP",
}

// procOtherIP handles one row of other_ip.log: one packet of a
// non-TCP/UDP/ICMP IPv4 protocol. Both directions merge into one flow.
func procOtherIP(row map[string]any, now time.Time) {
	src := gs(row, "orig_h")
	dst := gs(row, "resp_h")
	if src == "" || dst == "" {
		return
	}
	pn := int(gu64(row, "proto"))
	ln := gu64(row, "len")

	ea, eb, fwd := src, dst, true
	if ea > eb {
		ea, eb, fwd = eb, ea, false
	}
	name, known := ipProtoNames[pn]
	if !known {
		name = fmt.Sprintf("IP-%d", pn)
	}

	key := fmt.Sprintf("%s:0|%s:0|OTHER%d", ea, eb, pn)
	f, ok := st.flows[key]
	if !ok {
		f = &Flow{Rt: "flow", Ea: ea, Eb: eb, P: "OTHER", V: 4,
			Fs: now.Unix(), Loc: locOf(ea, eb), Svc: name, St: "data"}
		if d := dcGet(ea); d != "" {
			f.Dom = d
		} else if d := dcGet(eb); d != "" {
			f.Dom = d
		}
		st.flows[key] = f
	}
	if fwd {
		f.Apk++
		f.Aby += ln
	} else {
		f.Bpk++
		f.Bby += ln
	}
	f.Tp = f.Apk + f.Bpk
	f.Tby = f.Aby + f.Bby
	f.Ls = now.Unix()
}
