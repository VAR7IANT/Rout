package rout

import (
	"strings"
	"testing"
	"unicode"
)

func TestTraditionalChineseCatalogCoversEveryMessage(t *testing.T) {
	for key := range messages {
		han := false
		for _, c := range key {
			han = han || unicode.Is(unicode.Han, c)
		}
		if !han || strings.HasPrefix(key, "请选择语言 /") {
			continue
		}
		v, ok := messagesTW[key]
		if !ok {
			t.Errorf("missing zh-TW translation (run scripts/gen_zh_tw.py): %q", key)
			continue
		}
		if toTraditional(v) != v {
			t.Errorf("zh-TW translation still contains Simplified characters: %q", v)
		}
		if len(formatToken.FindAllString(key, -1)) != len(formatToken.FindAllString(v, -1)) {
			t.Errorf("placeholder mismatch: %q", key)
		}
	}
	if got := Translate("zh-TW", "节点 ID 无效"); got != "節點 ID 無效" {
		t.Fatal(got)
	}
	// Formatted messages translate their template; plain arguments (names) stay unchanged.
	if got := Translate("zh-TW", "入站 我的节点 正常"); got != "入站 我的节点 正常" && !strings.HasPrefix(got, "入站 ") {
		t.Fatal(got)
	}
	// Stable English diagnostics are shown in Traditional Chinese through their source.
	if got := Translate("zh-TW", msgHTTPSNoCaddy); toTraditional(got) != got || got == msgHTTPSNoCaddy {
		t.Fatal(got)
	}
}

func TestTraditionalChineseMenusAndCompatibleSettings(t *testing.T) {
	a := testApp(t)
	a.Language = ""
	u, out := testUI(a, "3\n8\n0\n0\n")
	if e := u.mainMenu(); e != nil {
		t.Fatal(e)
	}
	text := out.String()
	if !strings.Contains(text, "節點管理") || !strings.Contains(text, "Web 管理面板") || !strings.Contains(text, "一鍵安裝") {
		t.Fatalf("zh-TW menu missing:\n%s", text)
	}
	// After the language prompt, nothing may be left in Simplified script.
	body := text[strings.Index(text, "繁體中文")+len("繁體中文"):]
	for _, line := range strings.Split(body, "\n") {
		if toTraditional(line) != line {
			t.Errorf("Simplified text in zh-TW menu: %q", line)
		}
	}
	s, e := a.LoadSettings()
	if e != nil || s.Language != "zh-CN" || s.LanguageVariant != "zh-TW" || s.lang() != "zh-TW" {
		t.Fatalf("settings %+v %v", s, e)
	}
	// An older version accepts only zh-CN/en in "language": the stored value stays valid.
	if languageOr("zh-TW") != "zh-CN" {
		t.Fatal("helper processes must not receive zh-TW")
	}
}

// Regression: the command line must start in the saved Traditional Chinese, not fall back
// to the backward-compatible "zh-CN" stored next to the variant.
func TestSavedTraditionalChineseIsUsedByCommands(t *testing.T) {
	home := t.TempDir()
	a := &App{Home: home}
	s := Settings{}
	s.setLang("zh-TW")
	if e := a.SaveSettings(s); e != nil {
		t.Fatal(e)
	}
	e := Run([]string{"--home", home, "--service", "none", "definitely-not-a-command"})
	if e == nil || !strings.Contains(e.Error(), "錯誤") {
		t.Fatalf("error not in Traditional Chinese: %v", e)
	}
}
