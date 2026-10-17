package rout

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// errQuit unwinds every menu when the user types q/quit at a menu prompt. It is a
// clean exit, never reported as an error.
var errQuit = errors.New("quit")

// normalizeInput is the single place where typed answers are cleaned: surrounding
// whitespace is trimmed, full-width forms from Chinese input methods are folded to
// ASCII, and letters compare case-insensitively.
func normalizeInput(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r == '　':
			r = ' '
		case r >= '！' && r <= '～':
			r -= 0xfee0
		}
		b.WriteRune(r)
	}
	return strings.ToLower(strings.TrimSpace(b.String()))
}

// parseYesNo understands y/yes/n/no in any case, plus 是/否 in either language.
func parseYesNo(s string) (yes, ok bool) {
	switch normalizeInput(s) {
	case "y", "yes", "是", "好", "确认":
		return true, true
	case "n", "no", "否", "不":
		return false, true
	}
	return false, false
}

// matchesKeyword compares a typed confirmation word case-insensitively.
func matchesKeyword(input, word string) bool {
	return normalizeInput(input) != "" && normalizeInput(input) == normalizeInput(word)
}

// Menu shortcuts accepted next to numbers.
func menuShortcut(s string) string {
	switch normalizeInput(s) {
	case "b", "back", "返回":
		return "back"
	case "q", "quit", "exit", "退出":
		return "quit"
	}
	return ""
}

// yes asks a yes/no question. The default is shown in capitals ([Y/n] or [y/N]) and
// taken on an empty answer; ordinary prompts default to yes, destructive ones to no.
func (u *UI) yes(prompt string, def bool) bool {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	for u.err == nil {
		s := u.ask(u.a.T(prompt)+" "+hint, "")
		if u.err != nil {
			return false
		}
		if strings.TrimSpace(s) == "" {
			return def
		}
		if v, ok := parseYesNo(s); ok {
			return v
		}
		u.say("请输入 y 或 n")
	}
	return false
}

// confirmWord guards destructive actions: the user must type the keyword (any case).
// Anything else, including an empty answer, cancels.
func (u *UI) confirmWord(prompt, word string) bool {
	fmt.Fprintln(u.writer(), u.paint("33", "! ")+u.a.T(prompt))
	return matchesKeyword(u.ask(fmt.Sprintf(u.a.T("输入 %s 确认，其他任意输入取消"), word), ""), word)
}

// number asks for an item number in 1..max. 0 (or b/back) returns 0, q quits; the
// result is -1 when input ended.
func (u *UI) number(prompt string, max int) int {
	allowed := []string{"0"}
	for i := 1; i <= max; i++ {
		allowed = append(allowed, itoa(i))
	}
	v := u.choose(prompt, allowed, "0")
	if u.err != nil {
		return -1
	}
	n, _ := strconv.Atoi(v)
	return n
}
