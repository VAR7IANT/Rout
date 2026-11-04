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

// Traditional Chinese (Taiwan) is generated from the Simplified Chinese source strings by
// scripts/gen_zh_tw.py; "chars" converts text that is not in the catalog character by
// character, so nothing is ever left in Simplified script.
//
//go:embed messages_zh_tw.json
var messageDataTW []byte
var messagesTW, charsTW = func() (map[string]string, map[rune]rune) {
	var raw struct {
		Messages map[string]string `json:"messages"`
		Chars    map[string]string `json:"chars"`
	}
	if e := json.Unmarshal(messageDataTW, &raw); e != nil {
		panic(e)
	}
	chars := map[rune]rune{}
	for k, v := range raw.Chars {
		a, b := []rune(k), []rune(v)
		if len(a) == 1 && len(b) == 1 {
			chars[a[0]] = b[0]
		}
	}
	return raw.Messages, chars
}()

type messagePattern struct {
	re         *regexp.Regexp
	translated string
}

func buildPatterns(catalog map[string]string) []messagePattern {
	keys := make([]string, 0, len(catalog))
	for k := range catalog {
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
		out = append(out, messagePattern{regexp.MustCompile(s.String()), catalog[k]})
	}
	return out
}

var patterns = buildPatterns(messages)
var patternsTW = buildPatterns(messagesTW)

// toTraditional converts text outside the catalog character by character.
func toTraditional(s string) string {
	return strings.Map(func(r rune) rune {
		if t, ok := charsTW[r]; ok {
			return t
		}
		return r
	}, s)
}

func Translate(lang, s string) string {
	if lang == "zh-TW" {
		out, known := translateTW(s)
		if !known {
			return toTraditional(out)
		}
		return out
	}
	return translateArg(lang, s)
}

// translateArg translates a whole message, or one argument of a formatted message. An
// argument that is not catalog text (a node name, an address) is returned unchanged.
func translateArg(lang, s string) string {
	switch lang {
	case "en":
		return translateWith(lang, messages, patterns, s)
	case "zh-TW":
		out, _ := translateTW(s)
		return out
	}
	return s
}

func translateTW(s string) (string, bool) {
	if out, ok := messagesTW[s]; ok {
		return out, true
	}
	// English internals (stable diagnostics) are shown in Chinese through their source.
	for chinese, english := range messages {
		if english == s {
			return translateWith("zh-TW", messagesTW, patternsTW, chinese), true
		}
	}
	out := translateWith("zh-TW", messagesTW, patternsTW, s)
	return out, out != s
}

func translateWith(lang string, catalog map[string]string, pats []messagePattern, s string) string {
	if out, ok := catalog[s]; ok {
		return out
	}
	for _, p := range pats {
		groups := p.re.FindStringSubmatch(s)
		if groups == nil {
			continue
		}
		i := 0
		return formatToken.ReplaceAllStringFunc(p.translated, func(_ string) string {
			i++
			if i < len(groups) {
				return translateArg(lang, groups[i])
			}
			return ""
		})
	}
	if i := strings.Index(s, ": "); i >= 0 {
		right := s[i+2:]
		translated := translateArg(lang, right)
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
