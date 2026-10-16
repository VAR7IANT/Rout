package main

import (
	"fmt"
	"github.com/VAR7IANT/Rout/internal/rout"
	"os"
)

func main() {
	if e := rout.Run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "错误：", e)
		os.Exit(1)
	}
}
