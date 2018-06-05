package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/boltdb/bolt"
	"github.com/peterh/liner"
	"github.com/pkg/browser"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	HASHLEN   = 20
	AUTHHASH  = "B84A50AC94A94B9A0A160639AA19DEDD4ABB436A"
	RECORDLEN = 42
	POINT     = 1
)

var (
	addr       = flag.String("addr", ":8080", "Easy mode webserver addr")
	ezmode     = flag.Bool("easy", false, "Use easy mode.")
	MYBUCKET   = flag.String("bucketname", "bucket1", "Bucket name for boltdb.")
	dbname     = flag.String("dbname", "./db", "Database name for boltdb.")
	passwdfile = flag.String("passwd", "./passwd", "Password file to check")
	timeout    = flag.Duration("timeout", 2*time.Minute, "Timeout")
	update     = flag.Bool("update", false, "Update db")
	prefixlen  = flag.Uint("prefixlen", 4, "Prefix length to use for generating hash tree.")
	filename   = flag.String("filename", "", "Filename of passwords to check.")
	debug      = flag.Bool("debug", false, "Turn on debug.")
	batchsize  = flag.Int("batchsize", 100000, "Batch size for indexing")
	nocheat    = flag.Bool("nocheat", false, "Don't cheat at openwest competition?")
	rules      = `
The rules are these:
1. -1 for missing
2. +1 points for each valid hash
3. Add bonus for rare passwords that only occur twice as in 04E2B8C988822005B768843B50A08BABDBA654FD:2
`
	usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), rules)
	}
)

type Hashes struct {
	buf        []byte
	currentkey string
	db         *bolt.DB
}

func isAuth() bool {
	s := liner.NewLiner()
	defer s.Close()
	p, err := s.PasswordPrompt("Password: ")
	if err != nil {
		fmt.Println(err)
	}
	p = strings.TrimSpace(p)

	v := fmt.Sprintf("%X", sha1.Sum([]byte(p)))
	return v == AUTHHASH
}

func (h *Hashes) flush() error {
	db := h.db
	key, err := hex.DecodeString(h.currentkey)
	if err != nil {
		return err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(*MYBUCKET))
		err := b.Put(key, h.buf)
		return err
	})
	if err != nil {
		return err
	}
	h.buf = []byte{}
	return nil

}

func (h *Hashes) Add(dat []byte) {
	h.buf = append(h.buf, append(dat, []byte("\n")...)...)
}

func NewTreeEntry(hashes *Hashes, key, val string) error {
	if *debug {
		fmt.Printf("NewTreeEntry key is %s\n", key)
	}
	return mkTreeEntry(hashes, key, val)
}

func mkTreeEntry(hashes *Hashes, key, val string) error {
	if key != hashes.currentkey && hashes.currentkey != "" {
		if err := hashes.flush(); err != nil {
			return err
		}
	}
	hashes.currentkey = key
	i := strings.Index(val, ":")
	if i == -1 {
		return fmt.Errorf("No \":\" in value \"%s\"", val)
	}
	bval, err := hex.DecodeString(val[:i])
	if err != nil {
		return err
	}
	bval = append(bval, []byte(val[i:])...)
	hashes.Add(bval)
	return nil
}

func getHash(db *bolt.DB, h string) ([]byte, error) {
	var res []byte
	bh, err := hex.DecodeString(h[:*prefixlen])
	if err != nil {
		return nil, err
	}
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(*MYBUCKET))
		res = b.Get(bh)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func findHash(scorechan chan int, escorechan chan float32, db *bolt.DB, fh io.ReadCloser) {
	defer fh.Close()
	s := bufio.NewScanner(fh)
	if *ezmode {
		prefix := make([]byte, len("passwords="))
		fh.Read(prefix)
		s.Split(htmlBodySplitter)
	}
	for {

		if ok := s.Scan(); !ok {
			err := s.Err()
			if err != nil {
				fmt.Println(err)
			}
			break

		}
		if *ezmode {
			fmt.Printf("checking \"%s\"\n", s.Text())
		}
		k := fmt.Sprintf("%X", sha1.Sum(s.Bytes()))

		if dat, err := getHash(db, k); err != nil {
			if *debug {
				fmt.Println(err)
			}
			continue
		} else {

			datlen := len(dat) / RECORDLEN
			i := sort.Search(datlen, func(i int) bool {
				rec := dat[i*RECORDLEN : i*RECORDLEN+RECORDLEN]
				a := strings.ToUpper(hex.EncodeToString(rec[:HASHLEN]))

				res := a >= k

				return res
			})
			if i == datlen {
				scorechan <- -POINT
			} else {

				rec := dat[i*RECORDLEN : i*RECORDLEN+RECORDLEN]
				a := strings.ToUpper(hex.EncodeToString(rec[:HASHLEN]))
				if a == k {
					scorechan <- POINT
					extra, err := strconv.Atoi(strings.TrimSpace(string(rec[HASHLEN+1:])))
					if err != nil {
						fmt.Println(err)
						break
					}
					e := float32(POINT) * float32(1/float32(extra))
					escorechan <- e
				} else {
					scorechan <- -POINT
				}
			}
		}

	}

}

const CRLF_l = 7
const CRLF_html = "%0D%0A"

func dropCR(data []byte) []byte {
	if len(data) >= CRLF_l && string(data[len(data)-CRLF_l:]) == CRLF_html {
		return data[0 : len(data)-CRLF_l]
	}
	return data
}

func unescape(data []byte) []byte {
	s, err := url.QueryUnescape(string(data))
	if err != nil {
		fmt.Println(err)
	}
	return []byte(s)
}

func htmlBodySplitter(data []byte, atEOF bool) (advance int, token []byte, err error) {
	//	fmt.Printf("splitter called with\n%s", hex.Dump(data))
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, []byte(CRLF_html)); i >= 0 {
		// We have a full newline-terminated line.
		return i + CRLF_l - 1, unescape(dropCR(data[0:i])), nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), unescape(dropCR(data)), nil
	}
	// Request more data.
	return 0, nil, nil
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if *nocheat {
		if !isAuth() {
			fmt.Println("Access Denied")
			return
		}
	}

	db, err := bolt.Open(*dbname, 0644, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(*MYBUCKET))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})
	defer db.Close()
	if *update {

		fmt.Printf("Update %s\n", *dbname)
		pfile, err := os.Open(*passwdfile)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer pfile.Close()
		p := bufio.NewScanner(pfile)
		b := *batchsize
		hashes := Hashes{db: db}
		start := time.Now()
		for {
			if b < 0 {
				b = *batchsize
				t := time.Now()
				elapsed := t.Sub(start)
				start = time.Now()
				fmt.Printf("%d hashes indexed in %s\n", *batchsize, elapsed.String())
			}

			if ok := p.Scan(); !ok {
				err := p.Err()
				if err != nil {
					fmt.Println(err)
				}
				break
			}
			l := strings.Trim(p.Text(), "\n")
			//l := strings.TrimSpace(p.Text())
			if err := NewTreeEntry(&hashes, l[:*prefixlen], l); err != nil {
				fmt.Println(err)
				break
			}
			if *debug {
				fmt.Printf(".")
			}
			b--
		}
		fmt.Printf("\n")
		hashes.flush()
		return
	}

	done := make(chan bool)
	escorechan := make(chan float32)
	scorechan := make(chan int)
	var score int
	var escore float32

	if *ezmode {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<head></head><body><form action="/check" method="post">
<input type="submit"><br>
<textarea rows="50" cols="40" name="passwords">Passwords go here</textarea>
</form></body>`)
		})
		http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
			findHash(scorechan, escorechan, db, r.Body)
			fmt.Fprintf(w, "Score is %d (%.2f).\n", score, escore)
			w.(http.Flusher).Flush()
		})
		go http.ListenAndServe(*addr, nil)
		time.Sleep(1 * time.Second)
		go browser.OpenURL("http://127.0.0.1" + *addr + "/")
	} else {
		go func() {
			fh, err := os.Open(*filename)
			if err != nil {
				fmt.Println(err)
				done <- true
				return
			}
			findHash(scorechan, escorechan, db, fh)
			done <- true
		}()
		go func() {
			time.Sleep(*timeout)
			fmt.Println("Timeout")
			done <- true
		}()
	}

FOR:
	for {
		select {
		case s := <-escorechan:
			escore += s
		case s := <-scorechan:
			score += s
		case <-done:
			break FOR
		default:
			time.Sleep(1 * time.Millisecond)
		}
	}
	fmt.Printf("Score is %d (%.2f).\n", score, escore)

}
