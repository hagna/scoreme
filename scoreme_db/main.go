package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/boltdb/bolt"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	MYBUCKET   = flag.String("bucketname", "bucket1", "Bucket name for boltdb.")
	dbname     = flag.String("dbname", "db", "Database name for boltdb.")
	passwdfile = flag.String("passwd", os.Getenv("HOME")+"/passwd", "Password file to check")
	timeout    = flag.Duration("timeout", 2*time.Minute, "Timeout")
	update     = flag.Bool("update", false, "Update db")
	prefixlen  = flag.Uint("prefixlen", 8, "Prefix length to use for generating hash tree.")
	splitlen   = flag.Uint("splitlen", 2, "Path length")
	debug      = flag.Bool("debug", false, "Turn on debug.")
	batchsize  = flag.Int("batchsize", 100000, "Batch size for indexing")
	rules      = `
The rules are these:
1. -1 for missing
2. +1 points for each valid hash
3. Add bonus for rare passwords that only occur twice as in 04E2B8C988822005B768843B50A08BABDBA654FD:2
4. If timeout happens before scoring you don't get any points.
`
	usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), rules)
	}
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

func NewTreeEntry(db *bolt.DB, key, val string) error {
	return mkTreeEntry(db, splitN(*splitlen), key, val)
}

func mkTreeEntry(db *bolt.DB, dbsplitter func(string) []string, key, val string) error {
	bkey, err := hex.DecodeString(key)
	if err != nil {
		return err
	}
	i := strings.Index(val, ":")
	if i == -1 {
		return fmt.Errorf("No \":\" in value \"%s\"", val)
	}
	bval, err := hex.DecodeString(val[:i])
	if err != nil {
		return err
	}
	bval = append(bval, []byte(val[i:])...)

	t := bkey
	var existingvalue []byte
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(*MYBUCKET))
		v := b.Get(t)
		existingvalue = v
		return nil
	})
	if err != nil {
		return err
	}
	if existingvalue == nil {

		err := db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(*MYBUCKET))
			err := b.Put(t, append(bval, []byte("\n")...))
			return err
		})
		if err != nil {
			return err
		}
		if *debug {
			fmt.Printf("Storing new value \nkey\n%s\nvalue\n%s\n", hex.Dump(t), hex.Dump(bval))
		}
	} else {
		newvalue := append(existingvalue, append(bval, []byte("\n")...)...)
		err := db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(*MYBUCKET))
			err := b.Put(t, newvalue)
			return err
		})
		if err != nil {
			return err
		}
		if *debug {
			fmt.Printf("Update value \nkey\n%s\nvalue\n%s\n", hex.Dump(t), hex.Dump(newvalue))
		}

	}
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
		if *debug {
			fmt.Printf("found hash for key\n%s\nvalue\n%s\n", hex.Dump(bh), hex.Dump(res))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

const HASHLEN = 20

func ppsplitter(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) >= HASHLEN+1 {
		i := bytes.Index(data[HASHLEN+1:], []byte("\n")) + HASHLEN + 1
		if i == -1 {
			return 0, nil, nil
		}
		if atEOF {
			advance = 0
		} else {
			advance = i + 1
		}
		err = nil
		token = data[:i]
		return
	} else {
		if atEOF {
			return 0, nil, nil
		}
		return 0, []byte{}, fmt.Errorf("Data is not long enough to advance")
	}

}

func main() {
	flag.Usage = usage
	flag.Parse()
	var score int
	var escore float32
	var hashes []string

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
			l := strings.TrimSpace(p.Text())
			if err := NewTreeEntry(db, l[:*prefixlen], l); err != nil {
				fmt.Println(err)
				break
			}
			b--
		}
		fmt.Printf("\n")
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
			if dat, err := getHash(db, k); err != nil {
				if *debug {
					fmt.Println(err)
				}
				continue
			} else {
				p := bufio.NewScanner(bytes.NewReader(dat))
				p.Split(ppsplitter)
				for {
					if ok := p.Scan(); !ok {
						err := p.Err()
						if err != nil {
							fmt.Println("ERROR scanning")
							fmt.Println(err)
						}
						break
					}
					rec := p.Bytes()
					i := bytes.LastIndex(rec, []byte(":"))
					if i == -1 {
						fmt.Printf("No \":\" found in stored value \n%s\n", hex.Dump(rec))
						break
					}
					hash := strings.ToUpper(hex.EncodeToString(rec[:i]))
					h := hash
					extra, err := strconv.Atoi(string(rec[i+1:]))
					if err != nil {
						fmt.Println(err)
						break
					}
					if *debug {
						fmt.Printf("compare \"%s\" to \"%s\"\n", k, h)
					}
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
		fmt.Printf("Timeout (%s)\n", *timeout)
	}

}
