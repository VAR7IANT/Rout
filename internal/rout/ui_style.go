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

// accent is the single highlight color: bright blue, readable on dark and light terminals.
const accent = "94"

func (u *UI) paint(code, s string) string {
	if !u.colorOn() {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}
func (u *UI) bold(s string) string { return u.paint("1", s) }
func (u *UI) dim(s string) string  { return u.paint("2", s) }

// Semantic colors: one place to change the palette.
const (
	colorOK   = "32"
	colorWarn = "33"
	colorErr  = "31"
)

// fancy enables glyph-only enhancements (status dots, progress bars). It is true on a
// color terminal and on a real, non-dumb terminal without color; captured output,
// pipes and scripted commands stay plain.
func (u *UI) fancy() bool {
	if u.colorOn() {
		return true
	}
	return u.out == nil && u.interactive() && os.Getenv("TERM") != "dumb"
}

// enter pushes a menu level onto the breadcrumb and returns the function that pops it.
// Entering the level that is already on top changes nothing.
func (u *UI) enter(name string) func() {
	if n := len(u.path); n > 0 && u.path[n-1] == name {
		return func() {}
	}
	u.path = append(u.path, name)
	depth := len(u.path)
	return func() {
		if len(u.path) >= depth {
			u.path = u.path[:depth-1]
		}
	}
}

// breadcrumb renders the current menu path, dropping the oldest levels when the line
// would not fit the terminal.
func (u *UI) breadcrumb() string {
	parts := make([]string, len(u.path))
	for i, p := range u.path {
		parts[i] = u.a.T(p)
	}
	limit := u.width() - 1
	if limit < 24 {
		limit = 24
	}
	line := strings.Join(parts, " › ")
	for len(parts) > 1 && displayWidth(line) > limit {
		parts = parts[1:]
		line = "… › " + strings.Join(parts, " › ")
	}
	return line
}

// heading prints a section title with an underline sized for CJK and Latin text. A
// title that is the current menu level is shown as the full breadcrumb path.
func (u *UI) heading(title string) {
	t := u.a.T(title)
	if n := len(u.path); n > 1 && u.path[n-1] == title {
		t = u.breadcrumb()
	}
	rule := displayWidth(t)
	if max := u.width() - 1; rule > max && max > 0 {
		rule = max
	}
	fmt.Fprintf(u.writer(), "\n%s\n%s\n", u.bold(t), u.dim(strings.Repeat("─", rule)))
}
func (u *UI) good(s string) { fmt.Fprintln(u.writer(), u.paint(colorOK, "✓ ")+u.a.T(s)) }
func (u *UI) warn(s string) { fmt.Fprintln(u.writer(), u.paint(colorWarn, "! ")+u.a.T(s)) }
func (u *UI) warnf(s string, args ...any) {
	fmt.Fprintln(u.writer(), u.paint(colorWarn, "! ")+fmt.Sprintf(u.a.T(s), args...))
}
func (u *UI) fail(s string) { fmt.Fprintln(u.writer(), u.paint(colorErr, "✗ ")+s) }

// Status levels used for dots and colors.
const (
	levelOK = iota
	levelWarn
	levelErr
	levelOff
)

// dot returns a colored status dot on a fancy terminal and nothing otherwise, so the
// status word next to it always carries the meaning.
func (u *UI) dot(level int) string {
	if !u.fancy() {
		return ""
	}
	switch level {
	case levelOK:
		return u.paint(colorOK, "●") + " "
	case levelWarn:
		return u.paint(colorWarn, "●") + " "
	case levelErr:
		return u.paint(colorErr, "●") + " "
	}
	return u.dim("○") + " "
}

// usageBar draws a quota bar such as ▓▓▓▓░░░░ colored by how much is used. It is empty
// when the terminal is plain or the width is too small to spare the columns.
func (u *UI) usageBar(used, limit uint64) string {
	if !u.fancy() || limit == 0 || u.width() < 44 {
		return ""
	}
	const cells = 8
	ratio := float64(used) / float64(limit)
	if ratio > 1 {
		ratio = 1
	}
	filled := int(ratio*cells + 0.5)
	if used > 0 && filled == 0 {
		filled = 1
	}
	code := colorOK
	switch {
	case ratio >= 0.9:
		code = colorErr
	case ratio >= 0.7:
		code = colorWarn
	}
	return u.paint(code, strings.Repeat("▓", filled)) + u.dim(strings.Repeat("░", cells-filled)) + fmt.Sprintf(" %d%%", int(ratio*100))
}

// segments prints parts joined by " · " on one line, continuing on a new line with the
// same indent when the terminal is too narrow, so no line is cut or wrapped mid-item.
func (u *UI) segments(indent string, parts ...string) {
	limit := u.width() - 1
	if limit < 24 {
		limit = 24
	}
	line := indent
	started := false
	for _, part := range parts {
		add := part
		if started {
			add = " · " + part
		}
		if started && displayWidth(line)+displayWidth(add) > limit {
			fmt.Fprintln(u.writer(), line)
			line, add = indent, part
		}
		line += add
		started = true
	}
	fmt.Fprintln(u.writer(), line)
}

// hint prints a dim help line, wrapped at its " · " separators on narrow terminals.
func (u *UI) hint(text string) {
	parts := strings.Split(u.a.T(text), " · ")
	for i := range parts {
		parts[i] = u.dim(parts[i])
	}
	u.segments("  ", parts...)
}

// displayWidth counts East Asian wide characters as two terminal columns.
func displayWidth(s string) int {
	w := 0
	inEscape := false
	for _, r := range s {
		switch {
		case inEscape:
			// A CSI color sequence ends at its first letter; none of it occupies a column.
			if r >= '@' && r <= '~' && r != '[' {
				inEscape = false
			}
		case r == '\033':
			inEscape = true
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

// menuItem keys are stable identifiers; numbers are assigned only for display. group,
// when set, prints a small section title above the item; badge is a short dim status
// shown to the right of the label.
type menuItem struct{ key, label, note, group, badge string }

func item(key, label string) menuItem { return menuItem{key: key, label: label} }

// itemNote adds a one-line explanation printed under the label.
func itemNote(key, label, note string) menuItem { return menuItem{key: key, label: label, note: note} }

// badgeColumn is where right-aligned item badges start on a roomy terminal.
const badgeColumn = 30

func (u *UI) printItem(n string, it menuItem) {
	if it.group != "" {
		fmt.Fprintf(u.writer(), "\n  %s\n", u.dim(u.a.T(it.group)))
	}
	label := u.a.T(it.label)
	line := fmt.Sprintf("  %s  %s", u.paint(accent, fmt.Sprintf("%2s", n)), label)
	if it.badge != "" {
		// Two spaces at least keep the label and the badge visibly separate on any width.
		gap := badgeColumn - displayWidth(label)
		if gap < 2 || u.width() < badgeColumn+16 {
			gap = 2
		}
		line += strings.Repeat(" ", gap) + u.dim(it.badge)
	}
	fmt.Fprintln(u.writer(), line)
	if it.note != "" {
		fmt.Fprintf(u.writer(), "      %s\n", u.dim(u.a.T(it.note)))
	}
}

// navHint prints the navigation help: in full the first time in a session, then short.
func (u *UI) navHint(back string) {
	top := back == "退出"
	switch {
	case !u.hintShown && top:
		u.hint("输入编号 · 0 或 q 退出 Rout")
	case !u.hintShown:
		u.hint("输入编号 · 0 或 b 返回 · q 退出 Rout")
	case top:
		u.hint("0 或 q 退出")
	default:
		u.hint("0 返回 · q 退出")
	}
	u.hintShown = true
}

// menu renders a vertical numbered menu and returns the selected key. "0" always means
// Back (or Exit at top level) and returns "".
func (u *UI) menu(title string, items []menuItem, back string) string {
	return u.menuAsk(title, items, back, true)
}

// menuAsk is menu with a choice of default: with withDefault false an empty answer
// asks again instead of taking "0", so a stray Enter cannot leave the main menu.
func (u *UI) menuAsk(title string, items []menuItem, back string, withDefault bool) string {
	if title != "" {
		u.heading(title)
	}
	allowed := []string{"0"}
	for i, it := range items {
		n := itoa(i + 1)
		allowed = append(allowed, n)
		u.printItem(n, it)
	}
	fmt.Fprintf(u.writer(), "  %s  %s\n", u.paint(accent, " 0"), u.a.T(back))
	u.navHint(back)
	def := "0"
	if !withDefault {
		def = ""
	}
	v := u.choose("选择", allowed, def)
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
