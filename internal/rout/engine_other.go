//go:build !linux

package rout

import "os"

func dropFileCache(*os.File) {}
