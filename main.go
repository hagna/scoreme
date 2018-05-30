package main

import (
	"bufio"
	"crypto/sha1"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

var passwdfile = flag.String("passwd", "/home/pi/passwd", "Password file to check")
var timeout = flag.Duration("timeout", 10*time.Minute, "Timeout")
var debug = flag.Bool("debug", false, "Turn on debug.")
var rules = `
The rules are these:
1. -1 for missing
2. +1/n points for each valid hash (04E2B8C988822005B768843B50A08BABDBA654FD:2 <-- n is 2 here)
`

func main() {
	flag.Parse()
	var score int
	var escore float32
	s := bufio.NewScanner(os.Stdin)
	var hashes []string
	for {

		if ok := s.Scan(); !ok {
			err := s.Err()
			if err != nil {
				fmt.Println(err)
			}
			break

		}
		hashes = append(hashes, fmt.Sprintf("%X", sha1.Sum(s.Bytes())))
	}
	if *debug {
		fmt.Printf("opening %s\n", *passwdfile)
	}
	pfile, err := os.Open(*passwdfile)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer pfile.Close()
	type scoredata struct {
		score int
		extra float32
	}
	hash := make(map[string]*scoredata)
	for _, v := range hashes {
		if _, ok := hash[v]; !ok {
			hash[v] = &scoredata{-1, 0}
		} else {
			val := hash[v]
			val.score = val.score - 1
			val.extra = val.extra - 1
		}
	}
	done := make(chan bool)
	go func() {
		p := bufio.NewScanner(pfile)
		for {
			if ok := p.Scan(); !ok {
				err := p.Err()
				if err != nil {
					fmt.Println(err)
				}
				break
			}
			l := p.Text()
			f := strings.Split(strings.TrimSpace(l), ":")
			line := f[0]
			extra, err := strconv.Atoi(f[1])
			if err != nil {
				fmt.Println(err)
				return
			}
			if newval, ok := hash[line]; ok {
				e := float32(2) * float32(1/float32(extra))
				if *debug {
					fmt.Printf("extra points 1/%d %f %f %f\n", extra, e, newval.extra, hash[line].extra)
				}
				newval.score += 2
				newval.extra += e
				hash[line] = newval

			}

		}
		for k, v := range hash {
			if *debug {
				fmt.Printf("%s: %d\n", k, v)
			}
			score += v.score
			escore += v.extra

		}
		fmt.Printf("Score is %d (%.2f).\n", score, escore)
		done <- true
	}()
	select {
	case <-done:
		break
	case <-time.After(*timeout):
		fmt.Printf("Time elapsed (%s)\n", *timeout)
	}

}
