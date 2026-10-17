package rout

import (
	"os"
	"syscall"
)

// dropFileCache asks the kernel to evict a file's clean pages (best effort). The file must
// already be synced, otherwise its dirty pages stay.
func dropFileCache(f *os.File) {
	rc, e := f.SyscallConn()
	if e != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		const posixFadvDontNeed = 4
		_, _, _ = syscall.Syscall6(syscall.SYS_FADVISE64, fd, 0, 0, posixFadvDontNeed, 0, 0)
	})
}
