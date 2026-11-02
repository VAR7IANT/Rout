package rout

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// sysSampler reads CPU, memory, disk and network figures from /proc. It keeps a short
// history so the dashboard can draw trends without storing anything on disk.

type SysPoint struct {
	At        int64   `json:"at"` // Unix seconds
	CPU       float64 `json:"cpu"`
	MemUsed   uint64  `json:"mem_used"`
	NetRxRate float64 `json:"net_rx_rate"` // bytes per second
	NetTxRate float64 `json:"net_tx_rate"`
}

type SysInfo struct {
	CPUPercent float64    `json:"cpu_percent"`
	Cores      int        `json:"cores"`
	Load1      float64    `json:"load1"`
	MemTotal   uint64     `json:"mem_total"`
	MemUsed    uint64     `json:"mem_used"`
	SwapTotal  uint64     `json:"swap_total"`
	SwapUsed   uint64     `json:"swap_used"`
	DiskTotal  uint64     `json:"disk_total"`
	DiskUsed   uint64     `json:"disk_used"`
	NetRxRate  float64    `json:"net_rx_rate"`
	NetTxRate  float64    `json:"net_tx_rate"`
	NetRxTotal uint64     `json:"net_rx_total"` // since boot
	NetTxTotal uint64     `json:"net_tx_total"`
	UptimeSec  uint64     `json:"uptime_sec"`
	Hostname   string     `json:"hostname,omitempty"`
	History    []SysPoint `json:"history"`
}

type sysSampler struct {
	mu      sync.Mutex
	proc    string // /proc root; replaced in tests
	last    cpuTimes
	lastNet netTotals
	lastAt  time.Time
	cur     SysInfo
	history []SysPoint
	started bool
}

type cpuTimes struct{ busy, total uint64 }
type netTotals struct{ rx, tx uint64 }

func newSysSampler() *sysSampler { return &sysSampler{proc: "/proc"} }

const sysHistory = 90

func (m *sysSampler) start(ctx context.Context) {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()
	m.sample()
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.sample()
			}
		}
	}()
}

// snapshot returns the latest figures, sampling once if nothing has been read yet.
func (m *sysSampler) snapshot() SysInfo {
	m.mu.Lock()
	empty := m.lastAt.IsZero()
	m.mu.Unlock()
	if empty {
		m.sample()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.cur
	out.History = append([]SysPoint(nil), m.history...)
	return out
}

func (m *sysSampler) sample() {
	now := time.Now()
	cpu := readCPU(m.proc + "/stat")
	net := readNet(m.proc + "/net/dev")
	total, used, swapT, swapU := readMem(m.proc + "/meminfo")
	info := SysInfo{MemTotal: total, MemUsed: used, SwapTotal: swapT, SwapUsed: swapU, NetRxTotal: net.rx, NetTxTotal: net.tx}
	info.Load1 = readLoad(m.proc + "/loadavg")
	info.UptimeSec = readUptime(m.proc + "/uptime")
	info.Cores = countCores(m.proc + "/stat")
	if h, e := os.Hostname(); e == nil {
		info.Hostname = h
	}
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil {
		info.DiskTotal = st.Blocks * uint64(st.Bsize)
		info.DiskUsed = (st.Blocks - st.Bfree) * uint64(st.Bsize)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.lastAt.IsZero() {
		if d := cpu.total - m.last.total; d > 0 && cpu.total >= m.last.total {
			info.CPUPercent = float64(cpu.busy-m.last.busy) / float64(d) * 100
			if info.CPUPercent < 0 {
				info.CPUPercent = 0
			}
		}
		if secs := now.Sub(m.lastAt).Seconds(); secs > 0 {
			if net.rx >= m.lastNet.rx {
				info.NetRxRate = float64(net.rx-m.lastNet.rx) / secs
			}
			if net.tx >= m.lastNet.tx {
				info.NetTxRate = float64(net.tx-m.lastNet.tx) / secs
			}
		}
	}
	m.last, m.lastNet, m.lastAt = cpu, net, now
	m.cur = info
	m.history = append(m.history, SysPoint{At: now.Unix(), CPU: info.CPUPercent, MemUsed: used, NetRxRate: info.NetRxRate, NetTxRate: info.NetTxRate})
	if len(m.history) > sysHistory {
		m.history = m.history[len(m.history)-sysHistory:]
	}
}

func readCPU(path string) cpuTimes {
	f, e := os.Open(path)
	if e != nil {
		return cpuTimes{}
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return cpuTimes{}
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTimes{}
	}
	var vals []uint64
	for _, v := range fields[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		vals = append(vals, n)
	}
	var total uint64
	for i, v := range vals {
		if i < 8 { // user..steal; guest time is already inside user
			total += v
		}
	}
	idle := vals[3]
	if len(vals) > 4 {
		idle += vals[4] // iowait counts as idle
	}
	return cpuTimes{busy: total - idle, total: total}
}

func countCores(path string) int {
	f, e := os.Open(path)
	if e != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if t := sc.Text(); strings.HasPrefix(t, "cpu") && len(t) > 3 && t[3] >= '0' && t[3] <= '9' {
			n++
		}
	}
	return n
}

func readMem(path string) (total, used, swapTotal, swapUsed uint64) {
	f, e := os.Open(path)
	if e != nil {
		return
	}
	defer f.Close()
	vals := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fs := strings.Fields(rest)
		if len(fs) == 0 {
			continue
		}
		n, _ := strconv.ParseUint(fs[0], 10, 64)
		vals[k] = n * 1024
	}
	total = vals["MemTotal"]
	avail, ok := vals["MemAvailable"]
	if !ok {
		avail = vals["MemFree"] + vals["Buffers"] + vals["Cached"]
	}
	if total >= avail {
		used = total - avail
	}
	swapTotal = vals["SwapTotal"]
	if swapTotal >= vals["SwapFree"] {
		swapUsed = swapTotal - vals["SwapFree"]
	}
	return
}

func readNet(path string) netTotals {
	f, e := os.Open(path)
	if e != nil {
		return netTotals{}
	}
	defer f.Close()
	var t netTotals
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "lo" || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") {
			continue
		}
		fs := strings.Fields(rest)
		if len(fs) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fs[0], 10, 64)
		tx, _ := strconv.ParseUint(fs[8], 10, 64)
		t.rx += rx
		t.tx += tx
	}
	return t
}

func readLoad(path string) float64 {
	b, e := os.ReadFile(path)
	if e != nil {
		return 0
	}
	fs := strings.Fields(string(b))
	if len(fs) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fs[0], 64)
	return v
}

func readUptime(path string) uint64 {
	b, e := os.ReadFile(path)
	if e != nil {
		return 0
	}
	fs := strings.Fields(string(b))
	if len(fs) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fs[0], 64)
	return uint64(v)
}
