package rout

import (
	"fmt"
	"os"
	"strings"
	"unicode"
)

// Restrained terminal styling: colors only on a real TTY, never with NO_COLOR or
// TERM=dumb, never in captured/test output. Everything stays readable without color.
func colorEnabled(tty bool) bool {
	return tty && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
}
func (u *UI) colorOn() bool {
	if u.out != nil {
		return colorEnabled(u.forceColor) // tests may simulate a color terminal
	}
	st, e := os.Stdout.Stat()
	return colorEnabled(e == nil && st.Mode()&os.ModeCharDevice != 0)
}
func (u *UI) paint(code, s string) string {
	if !u.colorOn() {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}
func (u *UI) bold(s string) string { return u.paint("1", s) }
func (u *UI) dim(s string) string  { return u.paint("2", s) }

// heading prints a section title with an underline sized for CJK and Latin text.
func (u *UI) heading(title string) {
	t := u.a.T(title)
	fmt.Fprintf(u.writer(), "\n%s\n%s\n", u.bold(t), u.dim(strings.Repeat("─", displayWidth(t))))
}
func (u *UI) good(s string) { fmt.Fprintln(u.writer(), u.paint("32", "✓ ")+u.a.T(s)) }
func (u *UI) warn(s string) { fmt.Fprintln(u.writer(), u.paint("33", "! ")+u.a.T(s)) }
func (u *UI) warnf(s string, args ...any) {
	fmt.Fprintln(u.writer(), u.paint("33", "! ")+fmt.Sprintf(u.a.T(s), args...))
}
func (u *UI) fail(s string) { fmt.Fprintln(u.writer(), u.paint("31", "✗ ")+s) }

// displayWidth counts East Asian wide characters as two terminal columns.
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		switch {
		case r == '\033':
			continue
		case unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hangul, r) || unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r) || (r >= 0xFF01 && r <= 0xFF60) || (r >= 0x3000 && r <= 0x303F):
			w += 2
		default:
			w++
		}
	}
	return w
}
func pad(s string, width int) string {
	if n := displayWidth(s); n < width {
		return s + strings.Repeat(" ", width-n)
	}
	return s
}

// menuItem keys are stable identifiers; numbers are assigned only for display.
type menuItem struct{ key, label, note string }

func item(key, label string) menuItem { return menuItem{key: key, label: label} }

// itemNote adds a one-line explanation printed under the label.
func itemNote(key, label, note string) menuItem { return menuItem{key, label, note} }
func (u *UI) printItem(n string, it menuItem) {
	fmt.Fprintf(u.writer(), "  %s  %s\n", u.paint("36", fmt.Sprintf("%2s", n)), u.a.T(it.label))
	if it.note != "" {
		fmt.Fprintf(u.writer(), "      %s\n", u.dim(u.a.T(it.note)))
	}
}

// menu renders a vertical numbered menu and returns the selected key. "0" always means
// Back (or Exit at top level) and returns "".
func (u *UI) menu(title string, items []menuItem, back string) string {
	if title != "" {
		u.heading(title)
	}
	allowed := []string{"0"}
	for i, it := range items {
		n := itoa(i + 1)
		allowed = append(allowed, n)
		u.printItem(n, it)
	}
	fmt.Fprintf(u.writer(), "  %s  %s\n", u.paint("36", " 0"), u.a.T(back))
	hint := "输入编号 · 0 或 b 返回 · q 退出 Rout"
	if back == "退出" {
		hint = "输入编号 · 0 或 q 退出 Rout"
	}
	fmt.Fprintln(u.writer(), "  "+u.dim(u.a.T(hint)))
	v := u.choose("选择", allowed, "0")
	if v == "" || v == "0" {
		return ""
	}
	n := 0
	fmt.Sscan(v, &n)
	return items[n-1].key
}

// option asks for one of a few labeled choices (no Back entry) and returns its key.
func (u *UI) option(prompt string, items []menuItem, def string) string {
	fmt.Fprintln(u.writer(), u.a.T(prompt))
	allowed := []string{}
	defNumber := "1"
	for i, it := range items {
		n := itoa(i + 1)
		allowed = append(allowed, n)
		if it.key == def {
			defNumber = n
		}
		u.printItem(n, it)
	}
	v := u.choose("选择", allowed, defNumber)
	n := 0
	fmt.Sscan(v, &n)
	if n < 1 || n > len(items) {
		return ""
	}
	return items[n-1].key
}
