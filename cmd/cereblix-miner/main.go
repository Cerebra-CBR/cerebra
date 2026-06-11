// cereblix-miner is the standalone NeuroMorph CPU miner for AMD64 (Intel/AMD).
// It pulls work from any Cereblix node over HTTP (getwork) and submits shares.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"cereblix/core"
	nm "cereblix/neuromorph"
)

type work struct {
	ID     string `json:"id"`
	Header string `json:"header"`
	Target string `json:"target"`
	Seed   string `json:"seed"`
	Epoch  uint64 `json:"epoch"`
	Height uint64 `json:"height"`
}

var (
	nodeURL   string
	addr      string
	hashCount atomic.Uint64
	current   atomic.Pointer[work]
	client    = &http.Client{Timeout: 15 * time.Second}
)

func main() {
	flag.StringVar(&nodeURL, "node", "http://188.34.181.191/cereblix/api", "node RPC base URL")
	flag.StringVar(&addr, "addr", "", "your CRB address (rewards go here)")
	threads := flag.Int("threads", runtime.NumCPU(), "mining threads")
	flag.Parse()

	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║   Cereblix · NeuroMorph CPU miner  v1.0       ║")
	fmt.Println("║   one CPU = one vote                          ║")
	fmt.Println("╚══════════════════════════════════════════════╝")
	// Double-click friendly: ask for the address instead of dying instantly.
	stdin := bufio.NewReader(os.Stdin)
	for !core.ValidAddr(addr) {
		if addr != "" {
			fmt.Println("Invalid address. It must look like: crb1 + 40 hex chars.")
		}
		fmt.Println("No wallet yet? Create one at http://188.34.181.191/cereblix/wallet/")
		fmt.Print("Enter your CRB address (crb1...): ")
		line, err := stdin.ReadString('\n')
		if err != nil {
			fmt.Println("error: address required (-addr crb1...)")
			os.Exit(1)
		}
		addr = strings.TrimSpace(line)
	}
	log.Printf("node: %s | address: %s | threads: %d", nodeURL, addr, *threads)

	if err := fetchWork(); err != nil {
		log.Printf("cannot reach node: %v", err)
		fmt.Print("Press Enter to exit...")
		stdin.ReadString('\n')
		os.Exit(1)
	}
	go workLoop()
	for i := 0; i < *threads; i++ {
		go mineThread(uint64(i))
	}

	last := uint64(0)
	for {
		time.Sleep(15 * time.Second)
		cur := hashCount.Load()
		w := current.Load()
		log.Printf("hashrate: %.1f H/s | mining block %d (epoch %d)",
			float64(cur-last)/15.0, w.Height, w.Epoch)
		last = cur
	}
}

func fetchWork() error {
	resp, err := client.Get(nodeURL + "/getwork?addr=" + addr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var w work
	if err := json.NewDecoder(resp.Body).Decode(&w); err != nil {
		return err
	}
	if w.Header == "" {
		return fmt.Errorf("node returned no work")
	}
	old := current.Load()
	if old == nil || old.ID != w.ID || old.Header != w.Header {
		current.Store(&w)
	}
	return nil
}

func workLoop() {
	for {
		time.Sleep(3 * time.Second)
		if err := fetchWork(); err != nil {
			log.Printf("getwork failed: %v (retrying)", err)
		}
	}
}

func mineThread(id uint64) {
	var vm *nm.VM
	var vmSeed string
	for {
		w := current.Load()
		if w.Seed != vmSeed {
			seed, _ := hex.DecodeString(w.Seed)
			vm = nm.NewVM(nm.DeriveParams(seed))
			vmSeed = w.Seed
		}
		header, err := hex.DecodeString(w.Header)
		if err != nil || len(header) != core.HeaderLen {
			time.Sleep(time.Second)
			continue
		}
		targetRaw, _ := hex.DecodeString(w.Target)
		target := new(big.Int).SetBytes(targetRaw)

		nonce := id<<56 | (uint64(time.Now().UnixNano()) & 0x00FFFFFFFFFFFF)
		for i := 0; ; i++ {
			for b := 0; b < 8; b++ {
				header[core.NonceOffset+b] = byte(nonce >> (8 * b))
			}
			hash := vm.Hash(header, w.Height)
			hashCount.Add(1)
			if new(big.Int).SetBytes(hash[:]).Cmp(target) <= 0 {
				submit(w.ID, nonce, w.Height)
				fetchWork()
				break
			}
			nonce++
			if i%32 == 0 && current.Load() != w {
				break // new work arrived
			}
		}
	}
}

func submit(id string, nonce uint64, height uint64) {
	body, _ := json.Marshal(map[string]any{"id": id, "nonce": nonce})
	resp, err := client.Post(nodeURL+"/submitwork", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("submit failed: %v", err)
		return
	}
	defer resp.Body.Close()
	var out map[string]string
	json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "" {
		log.Printf("block %d rejected: %s", height, out["error"])
		return
	}
	log.Printf("*** BLOCK %d FOUND AND ACCEPTED *** hash %s", height, out["hash"])
}
