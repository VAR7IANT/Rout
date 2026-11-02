package rout

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ---- public addresses ------------------------------------------------------------------

type pubIPCache struct {
	v4, v6 string
	at     time.Time
	busy   bool
}

type PublicIPs struct {
	IPv4      string     `json:"ipv4"`
	IPv6      string     `json:"ipv6"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	Checking  bool       `json:"checking"`
	// Local reports whether the machine has a global address of each family at all,
	// independent of the outbound probe.
	LocalIPv4 bool `json:"local_ipv4"`
	LocalIPv6 bool `json:"local_ipv6"`
}

// hostFamilies reports whether any interface carries a global unicast address of each family.
func hostFamilies() (v4, v6 bool) {
	addrs, e := net.InterfaceAddrs()
	if e != nil {
		return false, false
	}
	for _, ad := range addrs {
		ipn, ok := ad.(*net.IPNet)
		if !ok || !ipn.IP.IsGlobalUnicast() || ipn.IP.IsPrivate() {
			continue
		}
		if ipn.IP.To4() != nil {
			v4 = true
		} else {
			v6 = true
		}
	}
	return
}

// publicIPs returns the cached probe result and starts a refresh in the background when it is
// stale; a request for the overview never waits for the outbound probe.
func (s *WebServer) publicIPs() PublicIPs {
	s.ipMu.Lock()
	c := s.ipCache
	stale := c.at.IsZero() || s.now().Sub(c.at) > 5*time.Minute
	if stale && !c.busy {
		s.ipCache.busy = true
		c.busy = true
		go func() {
			v4, v6 := s.detectIPs()
			s.ipMu.Lock()
			s.ipCache = pubIPCache{v4: v4, v6: v6, at: s.now()}
			s.ipMu.Unlock()
		}()
	}
	s.ipMu.Unlock()
	out := PublicIPs{IPv4: c.v4, IPv6: c.v6, Checking: c.busy}
	if !c.at.IsZero() {
		t := c.at
		out.CheckedAt = &t
	}
	out.LocalIPv4, out.LocalIPv6 = hostFamilies()
	return out
}

// ---- update check ----------------------------------------------------------------------

type updateInfo struct {
	Current   string     `json:"current"`
	Latest    string     `json:"latest,omitempty"`
	Available bool       `json:"available"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// latestReleaseTag asks GitHub for the newest stable release. It only reads: installing an
// update stays a command-line operation (`rout update`).
func latestReleaseTag(ctx context.Context) (string, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/VAR7IANT/Rout/releases/latest", nil)
	if e != nil {
		return "", e
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	r, e := httpClient().Do(req)
	if e != nil {
		return "", errors.New("无法查询更新")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", errors.New("查询更新失败")
	}
	var rel struct {
		Tag   string `json:"tag_name"`
		Draft bool   `json:"draft"`
		Pre   bool   `json:"prerelease"`
	}
	if e = json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&rel); e != nil || rel.Draft || rel.Pre {
		return "", errors.New("最新发布版本标签无效")
	}
	return rel.Tag, nil
}

// updateStatus returns the last check, refreshing it when force is set or it is over a day
// old... but never more than once a minute.
func (s *WebServer) updateStatus(ctx context.Context, force bool) updateInfo {
	s.updMu.Lock()
	defer s.updMu.Unlock()
	age := s.now().Sub(s.updAt)
	if s.updAt.IsZero() && !force {
		return updateInfo{Current: Version}
	}
	if !force && age < 24*time.Hour {
		return s.updCache
	}
	if force && age < time.Minute && !s.updAt.IsZero() {
		return s.updCache
	}
	info := updateInfo{Current: Version}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tag, e := s.fetchLatest(cctx)
	now := s.now()
	info.CheckedAt = &now
	if e != nil {
		info.Error = e.Error()
	} else if latest, ok := parseVersion(tag); !ok {
		info.Error = "最新发布版本标签无效"
	} else {
		current, _ := parseVersion("v" + Version)
		info.Latest = tag
		info.Available = compareVersions(latest, current) > 0
	}
	s.updCache, s.updAt = info, now
	return info
}

// ---- DNS ---------------------------------------------------------------------------------

type NetworkView struct {
	PublicIPs PublicIPs `json:"public_ips"`
	DNS       struct {
		Servers []string `json:"servers"`
		OK      bool     `json:"ok"`
		Millis  int64    `json:"millis"`
		Error   string   `json:"error,omitempty"`
	} `json:"dns"`
}

func resolverList(path string) []string {
	b, e := readSmall(path, 64<<10)
	if e != nil {
		return []string{}
	}
	out := []string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" && net.ParseIP(f[1]) != nil {
			out = append(out, f[1])
		}
	}
	return out
}

func (s *WebServer) networkView(ctx context.Context) NetworkView {
	var v NetworkView
	v.PublicIPs = s.publicIPs()
	v.DNS.Servers = resolverList("/etc/resolv.conf")
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	start := time.Now()
	_, e := net.DefaultResolver.LookupHost(cctx, "github.com")
	v.DNS.Millis = time.Since(start).Milliseconds()
	v.DNS.OK = e == nil
	if e != nil {
		v.DNS.Error = "域名解析失败"
	}
	return v
}
