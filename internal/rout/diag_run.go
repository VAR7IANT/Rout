package rout

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// loopbackFor is where a test client reaches a node's own listener.
func loopbackFor(p Profile) string {
	switch ip := net.ParseIP(p.Listen); {
	case ip == nil, ip.IsUnspecified() && ip.To4() != nil:
		return "127.0.0.1"
	case ip.IsUnspecified():
		if p.inboundMode() == inIPv6 && ipv6LoopbackWorks() {
			return "::1"
		}
		return "127.0.0.1"
	}
	return p.Listen
}

// diagnoseNode tests a node: its sockets, then (with an engine) the protocol handshake and
// the real exit. A node that sends traffic through an outbound proxy also tests that
// proxy's own layers first, so a failing exit is not blamed on the node.
func (a *App) diagnoseNode(ctx context.Context, p Profile, env diagEnv, opts diagOpts) diagReport {
	var rep diagReport
	d := diagger{a: a, rep: &rep}
	if !d.layerListen(env, p) {
		return rep
	}
	if p.Outbound != nil {
		sub := a.diagnoseProxy(ctx, Exit{Proxy: *p.Outbound}, env, diagOpts{})
		for _, s := range sub.Steps {
			if s.Layer < 5 { // endpoint layers of the exit; protocol/exit come from the full test below
				rep.Steps = append(rep.Steps, s)
			}
		}
		if _, failed := sub.Failed(); failed {
			rep.Steps = append(rep.Steps, diagStep{Layer: 5, Level: diagInfo, Text: a.T("出站代理有问题，跳过节点协议测试")})
			return rep
		}
	}
	if !opts.Full || env.full == nil {
		d.add(5, diagWarn, "尚未验证代理协议握手（端口可达不代表代理可用）")
		return rep
	}
	res := env.full(a, p, loopbackFor(p), p.Port)
	if res.ClientErr != nil {
		d.add(5, diagFail, "无法启动本地检测客户端：%s", a.Error(res.ClientErr))
		return rep
	}
	d.layerExit(res)
	return rep
}

func (a *App) diagnose(ctx context.Context, p Profile, env diagEnv, opts diagOpts) diagReport {
	if p.Kind == "relay" {
		return a.diagnoseRelay(ctx, p, env, opts)
	}
	return a.diagnoseNode(ctx, p, env, opts)
}

// reportError turns the first failed layer into an error (a non-zero exit status for the
// scripted `rout test`).
func reportError(rep diagReport) error {
	if layer, ok := rep.Failed(); ok {
		return fmt.Errorf("检测未通过：第 %d 层「%s」失败", layer, diagLayerNames[layer])
	}
	return nil
}

// printReport shows a report grouped by layer.
func (u *UI) printReport(rep diagReport) {
	last := 0
	for _, s := range rep.Steps {
		if s.Layer != last {
			last = s.Layer
			fmt.Fprintf(u.writer(), "\n  %s\n", u.bold(fmt.Sprintf("%d. %s", s.Layer, u.a.T(diagLayerNames[s.Layer]))))
		}
		prefix := "    "
		switch s.Level {
		case diagOK:
			fmt.Fprintln(u.writer(), prefix+u.paint(colorOK, "✓ ")+s.Text)
		case diagWarn:
			fmt.Fprintln(u.writer(), prefix+u.paint(colorWarn, "! ")+s.Text)
		case diagFail:
			fmt.Fprintln(u.writer(), prefix+u.paint(colorErr, "✗ ")+s.Text)
		default:
			fmt.Fprintln(u.writer(), prefix+u.dim("· "+s.Text))
		}
	}
	fmt.Fprintln(u.writer())
	u.printVerdict(rep)
}

// printVerdict states the overall result without overclaiming.
func (u *UI) printVerdict(rep diagReport) {
	switch {
	case rep.Count(diagFail) > 0:
		layer, _ := rep.Failed()
		u.fail(fmt.Sprintf(u.a.T("失败发生在第 %d 层：%s"), layer, u.a.T(diagLayerNames[layer])))
	case rep.Has(5, diagOK) && rep.Has(6, diagOK):
		u.good("本地监听、目标连通、协议握手与实际出口均已验证；公网端口仍需用外部客户端确认")
	case rep.Count(diagWarn) > 0:
		u.warn("部分层只做了有限验证（见上面的 !）；不要据此认为整个节点可用")
	default:
		u.good("已执行的检测全部通过")
	}
}

// diagEnvOrDefault returns the UI's test override or the real environment.
func (u *UI) diagEnvOrDefault() diagEnv {
	if u.diag != nil {
		return *u.diag
	}
	return defaultDiagEnv()
}

// Probe is `rout test ID`: the layered diagnosis including the engine-based protocol and
// exit test.
func (a *App) Probe(p Profile) error {
	if !p.Enabled {
		return errors.New("节点已停用")
	}
	u := &UI{a: a}
	if p.Kind != "relay" {
		v4, v6 := DetectPublicIPs()
		a.printf("本服务器公网 IPv4：%s\n", orUnavailable(a, v4))
		a.printf("本服务器公网 IPv6：%s\n", orUnavailable(a, v6))
	}
	a.say("正在分层检测…")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	rep := a.diagnose(ctx, p, defaultDiagEnv(), diagOpts{Full: true})
	u.printReport(rep)
	return reportError(rep)
}
