package rout

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

//go:embed messages.json
var messageData []byte
var messages = func() map[string]string {
	var m map[string]string
	if e := json.Unmarshal(messageData, &m); e != nil {
		panic(e)
	}
	return m
}()
var formatToken = regexp.MustCompile(`%[sdvwq]`)

type messagePattern struct {
	re         *regexp.Regexp
	translated string
}

var patterns = func() []messagePattern {
	keys := make([]string, 0, len(messages))
	for k := range messages {
		if formatToken.MatchString(k) {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	var out []messagePattern
	for _, k := range keys {
		parts := formatToken.Split(k, -1)
		var s strings.Builder
		s.WriteString("(?s)^")
		for i, p := range parts {
			if i > 0 {
				s.WriteString("(.*?)")
			}
			s.WriteString(regexp.QuoteMeta(p))
		}
		s.WriteString("$")
		out = append(out, messagePattern{regexp.MustCompile(s.String()), messages[k]})
	}
	return out
}()

func Translate(lang, s string) string {
	if lang != "en" {
		return s
	}
	if out, ok := messages[s]; ok {
		return out
	}
	for _, p := range patterns {
		groups := p.re.FindStringSubmatch(s)
		if groups == nil {
			continue
		}
		i := 0
		return formatToken.ReplaceAllStringFunc(p.translated, func(_ string) string {
			i++
			if i < len(groups) {
				return Translate(lang, groups[i])
			}
			return ""
		})
	}
	if i := strings.Index(s, ": "); i >= 0 {
		right := s[i+2:]
		translated := Translate(lang, right)
		if right != translated {
			return s[:i+2] + translated
		}
	}
	return s
}
func (a *App) T(s string) string { return Translate(a.Language, s) }
func (a *App) Error(e error) string {
	if e == nil {
		return ""
	}
	return a.T(e.Error())
}
func (a *App) say(s string)                 { fmt.Println(a.T(s)) }
func (a *App) printf(s string, args ...any) { fmt.Printf(a.T(s), args...) }
func FormatError(lang string, e error) error {
	if e == nil {
		return nil
	}
	return fmt.Errorf("%s%s", Translate(lang, "错误："), Translate(lang, e.Error()))
}
