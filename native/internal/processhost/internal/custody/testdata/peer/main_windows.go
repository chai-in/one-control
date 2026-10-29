package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

type instruction struct {
	Session int
	Frame   string
	Read    bool
}

func main() {
	if len(os.Args) != 5 {
		os.Exit(2)
	}
	var readers [2]*bufio.Reader
	var writers [2]*os.File
	for i := 0; i < 2; i++ {
		r, e := strconv.ParseUint(os.Args[1+i*2], 10, 64)
		if e != nil {
			os.Exit(2)
		}
		w, e := strconv.ParseUint(os.Args[2+i*2], 10, 64)
		if e != nil {
			os.Exit(2)
		}
		readers[i] = bufio.NewReader(os.NewFile(uintptr(r), "fixture-response"))
		writers[i] = os.NewFile(uintptr(w), "fixture-request")
	}
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		var c instruction
		if json.Unmarshal(s.Bytes(), &c) != nil || c.Session < 0 || c.Session > 1 {
			os.Exit(3)
		}
		if c.Read {
			line, e := readers[c.Session].ReadString('\n')
			if e != nil {
				os.Exit(4)
			}
			fmt.Print(line)
		} else {
			if _, e := fmt.Fprintln(writers[c.Session], c.Frame); e != nil {
				os.Exit(5)
			}
			fmt.Println("sent")
		}
	}
}
