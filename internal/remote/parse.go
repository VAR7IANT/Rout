package remote

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
)

var (
	base64Body   = regexp.MustCompile(`^[A-Za-z0-9+/=_\-\s]+$`)
	clashMarker  = regexp.MustCompile(`(?m)^(proxies|proxy-providers)[ \t]*:`)
	linkMarker   = regexp.MustCompile(`(?m)^[A-Za-z][A-Za-z0-9+.\-]{1,19}://`)
	singboxHint  = regexp.MustCompile(`^\s*\{[\s\S]*"outbounds"\s*:`)
	providerHint = regexp.MustCompile(`(?m)^proxy-providers[ \t]*:`)
)

// Parse reads a subscription body in any supported format: Clash/Mihomo YAML, a list of share
// links, or either of those wrapped in Base64. The detected format is reported; unsupported
// formats produce an explanatory error instead of an empty result.
func Parse(body []byte) (Parsed, error) {
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	text := strings.TrimSpace(string(body))
	if text == "" {
		return Parsed{}, errors.New("订阅内容为空")
	}
	return parseText(text, 0)
}

func parseText(text string, depth int) (Parsed, error) {
	switch {
	case singboxHint.MatchString(text):
		return Parsed{}, errors.New("暂不支持导入 sing-box JSON 订阅，请使用 Base64 或 Clash/Mihomo 格式")
	case clashMarker.MatchString(text):
		if providerHint.MatchString(text) && !regexp.MustCompile(`(?m)^proxies[ \t]*:`).MatchString(text) {
			return Parsed{}, errors.New("配置只含 proxy-providers（远程节点集），请直接添加其中的订阅地址")
		}
		p, err := ParseClash([]byte(text))
		return p, err
	case linkMarker.MatchString(text):
		p, err := ParseLinks(text)
		if err != nil {
			return Parsed{}, err
		}
		if p.Entries == 0 {
			return Parsed{}, errors.New("没有找到节点")
		}
		return p, nil
	}
	if depth == 0 && base64Body.MatchString(text) {
		dec, err := decodeB64(strings.Join(strings.Fields(text), ""))
		if err == nil && len(dec) > 0 {
			p, perr := parseText(strings.TrimSpace(string(dec)), 1)
			if perr == nil && p.Format == "links" {
				p.Format = "base64"
			}
			return p, perr
		}
	}
	return Parsed{}, errors.New("无法识别订阅格式（支持 Base64 节点列表、分享链接和 Clash/Mihomo YAML）")
}
