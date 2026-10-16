package rout

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

func decode64(s string) ([]byte, error) {
	for _, e := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := e.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("Base64 无效")
}

// URIOutbound is used for diagnostics; forwarding itself preserves the original stream.
func URIOutbound(raw string) (M, error) {
	if _, _, e := ParseTarget(raw); e != nil {
		return nil, e
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	port, _ := strconv.Atoi(u.Port())
	out := M{"tag": "node", "server": u.Hostname(), "server_port": port}
	scheme := u.Scheme
	if scheme == "ss" {
		var cred string
		if pass, ok := u.User.Password(); ok {
			cred = u.User.Username() + ":" + pass
		} else {
			b, e := decode64(u.User.Username())
			if e != nil {
				return nil, e
			}
			cred = string(b)
		}
		parts := strings.SplitN(cred, ":", 2)
		if len(parts) != 2 {
			return nil, errors.New("SS 凭据无效")
		}
		out["type"] = "shadowsocks"
		out["method"] = parts[0]
		out["password"] = parts[1]
		return out, nil
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	if sni == "" {
		sni = u.Hostname()
	}
	tls := M{"enabled": true, "server_name": sni}
	if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
		tls["insecure"] = true
	}
	if v := q.Get("alpn"); v != "" {
		tls["alpn"] = strings.Split(v, ",")
	}
	security := q.Get("security")
	if security == "reality" {
		if q.Get("pbk") == "" {
			return nil, errors.New("Reality 链接缺少公钥")
		}
		tls["reality"] = M{"enabled": true, "public_key": q.Get("pbk"), "short_id": q.Get("sid")}
		tls["utls"] = M{"enabled": true, "fingerprint": "chrome"}
	}
	switch scheme {
	case "vless":
		out["type"] = "vless"
		out["uuid"] = u.User.Username()
		if v := q.Get("flow"); v != "" {
			out["flow"] = v
		}
		if security != "none" && security != "" {
			out["tls"] = tls
		}
	case "anytls", "trojan":
		out["type"] = scheme
		out["password"] = u.User.Username()
		out["tls"] = tls
	case "hy2", "hysteria2":
		out["type"] = "hysteria2"
		out["password"] = u.User.Username()
		out["tls"] = tls
	case "tuic":
		out["type"] = "tuic"
		out["uuid"] = u.User.Username()
		pass, _ := u.User.Password()
		out["password"] = pass
		out["tls"] = tls
		cc := q.Get("congestion_control")
		if cc == "" {
			cc = "bbr"
		}
		out["congestion_control"] = cc
	}
	switch transport := q.Get("type"); transport {
	case "", "tcp":
	case "ws":
		host := q.Get("host")
		if host == "" {
			host = u.Hostname()
		}
		out["transport"] = M{"type": "ws", "path": q.Get("path"), "headers": M{"Host": host}}
	case "grpc":
		out["transport"] = M{"type": "grpc", "service_name": q.Get("serviceName")}
	default:
		return nil, errors.New("该传输类型暂不支持内置检测，请使用原客户端验证")
	}
	return out, nil
}
