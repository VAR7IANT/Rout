package rout

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

var logoLines = []string{
	"██████╗  ██████╗ ██╗   ██╗████████╗",
	"██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝",
	"██████╔╝██║   ██║██║   ██║   ██║   ",
	"██╔══██╗██║   ██║██║   ██║   ██║   ",
	"██║  ██║╚██████╔╝╚██████╔╝   ██║   ",
	"╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ",
}

// A restrained top-to-bottom blue gradient (xterm-256 palette).
var logoGradient = []int{39, 38, 33, 32, 27, 26}

const (
	logoWidth  = 35
	logoCredit = "Support by VAR7IANT"
)

// terminalWidth reads the window size of stdout, then $COLUMNS, then assumes 80.
func terminalWidth() int {
	var ws struct{ Row, Col, X, Y uint16 }
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, os.Stdout.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws))); e == 0 && ws.Col > 0 {
		return int(ws.Col)
	}
	if n, e := strconv.Atoi(os.Getenv("COLUMNS")); e == nil && n > 0 {
		return n
	}
	return 80
}

// terminalHeight reads the window rows of stdout, then $LINES; 0 means unknown.
func terminalHeight() int {
	var ws struct{ Row, Col, X, Y uint16 }
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, os.Stdout.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws))); e == 0 && ws.Row > 0 {
		return int(ws.Row)
	}
	if n, e := strconv.Atoi(os.Getenv("LINES")); e == nil && n > 0 {
		return n
	}
	return 0
}

// compactBannerRows is the window height below which the large logo is replaced by the
// two-line banner, so the first menu fits on one screen.
const compactBannerRows = 30

func (u *UI) height() int {
	if u.termHeight > 0 {
		return u.termHeight
	}
	if u.out != nil {
		return 0 // captured output has no window
	}
	return terminalHeight()
}
func (u *UI) width() int {
	if u.termWidth > 0 {
		return u.termWidth
	}
	return terminalWidth()
}

// interactive is true only for a real terminal session; captured output, pipes and
// scripted commands never get the logo.
func (u *UI) interactive() bool {
	if u.out != nil {
		return false
	}
	in, e1 := os.Stdin.Stat()
	out, e2 := os.Stdout.Stat()
	return e1 == nil && e2 == nil && in.Mode()&os.ModeCharDevice != 0 && out.Mode()&os.ModeCharDevice != 0
}

// renderLogo returns the banner for a given width and color mode. Every colored
// span ends with a reset, so the terminal state is never left modified.
func renderLogo(width int, color, rich bool) string {
	version := "v" + Version
	var b strings.Builder
	if width < logoWidth+4 {
		title := "ROUT " + version
		credit := logoCredit
		if displayWidth(credit) > width {
			credit = "VAR7IANT"
		}
		if displayWidth(title) > width {
			title = "ROUT"
		}
		if color {
			title = strings.Replace(title, "ROUT", "\033[1;34mROUT\033[0m", 1)
			credit = "\033[2m" + credit + "\033[0m"
		}
		b.WriteString(title + "\n" + credit + "\n")
		return b.String()
	}
	for i, line := range logoLines {
		switch {
		case color && rich:
			fmt.Fprintf(&b, "  \033[38;5;%dm%s\033[0m\n", logoGradient[i], line)
		case color:
			fmt.Fprintf(&b, "  \033[34m%s\033[0m\n", line)
		default:
			fmt.Fprintf(&b, "  %s\n", line)
		}
	}
	// Credit and version, each centered beneath the logo.
	for _, sub := range []string{logoCredit, version} {
		pad := 2 + (logoWidth-displayWidth(sub))/2
		if pad < 2 {
			pad = 2
		}
		if color {
			sub = "\033[2m" + sub + "\033[0m"
		}
		b.WriteString(strings.Repeat(" ", pad) + sub + "\n")
	}
	return b.String()
}
func richColor() bool {
	t := os.Getenv("TERM")
	return strings.Contains(t, "256color") || os.Getenv("COLORTERM") != ""
}

// showLogo prints the banner once per interactive session.
func (u *UI) showLogo() {
	if u.logoShown || (!u.interactive() && !u.forceLogo) {
		return
	}
	u.logoShown = true
	width := u.width()
	if h := u.height(); h > 0 && h < compactBannerRows && width > logoWidth+3 {
		width = logoWidth + 3 // the compact banner is chosen below logoWidth+4 columns
	}
	fmt.Fprint(u.writer(), "\n"+renderLogo(width, u.colorOn(), richColor() || u.forceColor))
}
