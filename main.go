package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	passwdfile = flag.String("passwd", "/home/pi/passwd", "Password file to check")
	timeout    = flag.Duration("timeout", 10*time.Minute, "Timeout")
	datadir    = flag.String("datadir", "/home/pi/data", "The dir containing the hash tree.")
	update     = flag.Bool("update", false, "Update the datadir")
	prefixlen  = flag.Uint("prefixlen", 8, "Prefix length to use for generating hash tree.")
	splitlen   = flag.Uint("splitlen", 2, "Path length")
	debug      = flag.Bool("debug", false, "Turn on debug.")
	rules      = `
The rules are these:
1. -1 for missing
2. +1 points for each valid hash
3. Add bonus for rare passwords that only occur twice as in 04E2B8C988822005B768843B50A08BABDBA654FD:2
`
)

// exists checks if a file or directory exists.
func exists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if !os.IsNotExist(err) {
		return false
	}
	return false
}

func splitN(n uint) func(string) []string {
	return func(a string) []string {
		var res []string
		var i uint
		for i = 0; i < uint(len(a)); i += n {
			if uint(len(a[i:])) < n {
				res = append(res, a[i:])
			} else {
				res = append(res, a[i:i+n])
			}
		}
		return res
	}
}

func NewTreeEntry(key, val string) error {
	return mkTreeEntry(splitN(*splitlen), key, val)
}

func mkTreeEntry(splitter func(string) []string, key, val string) error {
	p := splitter(key)
	path := *datadir + "/" + strings.Join(p, "/")
	if err := os.MkdirAll(path, 0744); err != nil {
		return err
	}
	t := path + "/v"
	if !exists(t) {
		if fh, err := os.Create(t); err != nil {
			return err
		} else {
			fh.Write([]byte(val + "\n"))
			defer fh.Close()
		}
	} else {
		if dat, err := ioutil.ReadFile(t); err != nil {
			return err
		} else {
			if err := ioutil.WriteFile(t, append(dat, []byte(fmt.Sprintf("%s\n", val))...), 0644); err != nil {
				return err
			}
		}
	}
	return nil
}

func getHash(h string) ([]byte, error) {
	p := splitN(*splitlen)(h[:*prefixlen])
	path := *datadir + "/" + strings.Join(p, "/") + "/v"
	if !exists(path) {
		return nil, fmt.Errorf("%s (%s) not found", h, path)
	}
	if dat, err := ioutil.ReadFile(path); err != nil {
		return nil, err
	} else {
		return dat, err
	}
}

func main() {
	flag.Parse()
	var score int
	var escore float32
	var hashes []string

	if !exists(*datadir) {
		fmt.Printf("%s doesn't exist so creating the index there.\n", *datadir)
		pfile, err := os.Open(*passwdfile)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer pfile.Close()
		p := bufio.NewScanner(pfile)
		for {
			if ok := p.Scan(); !ok {
				err := p.Err()
				if err != nil {
					fmt.Println(err)
				}
				break
			}
			l := strings.TrimSpace(p.Text())
			if err := NewTreeEntry(l[:*prefixlen], l); err != nil {
				fmt.Println(err)
				break
			}
		}
		return
	}

	s := bufio.NewScanner(os.Stdin)
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
		for k, v := range hash {
			if dat, err := getHash(k); err != nil {
				fmt.Println(err)
				continue
			} else {
				p := bufio.NewScanner(bytes.NewReader(dat))
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
					h := f[0]
					extra, err := strconv.Atoi(f[1])
					if err != nil {
						fmt.Println(err)
						return
					}
					fmt.Printf("compare \"%s\" to \"%s\"\n", k, h)
					if k == h {
						e := float32(2) * float32(1/float32(extra))
						score += 1
						escore += e

					}
				}
				if *debug {
					fmt.Printf("%s: %d\n", k, v)
				}
			}

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
