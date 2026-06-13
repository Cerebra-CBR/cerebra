// cereblix-miner is the standalone NeuroMorph CPU miner for AMD64 (Intel/AMD).
// It pulls work from any Cereblix node over HTTP (getwork) and submits shares.
//
// First run shows a tiny setup wizard (address, server, pool/solo, threads) and
// saves everything to cereblix-miner.json right next to the binary, so next time
// it just remembers. Power users / services can still pass -addr -node -threads
// on the command line (those override the saved config and skip the wizard).
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"cereblix/core"
	nm "cereblix/neuromorph"
)

const (
	minerVersion     = "1.2"
	hostMain         = "https://cereblix.com"
	hostRU           = "https://ru.cereblix.com"
	updateVersionURL = "https://github.com/Cerebra-CBR/cereblix/releases/latest/download/miner-version.txt"
	releasePage      = "https://github.com/Cerebra-CBR/cereblix/releases/latest"
)

type work struct {
	ID     string `json:"id"`
	Header string `json:"header"`
	Target string `json:"target"`
	Seed   string `json:"seed"`
	Epoch  uint64 `json:"epoch"`
	Height uint64 `json:"height"`
	// Extranonce is a per-miner tag a POOL assigns (0 for solo mining straight
	// against a node). The miner pins it into the top 16 bits of every nonce it
	// tries, so a share is cryptographically bound to this miner and the pool
	// cannot be tricked into crediting one miner's work to another. See mineThread.
	Extranonce uint64 `json:"extranonce"`
}

// config persists the user's choices next to the binary (cereblix-miner.json).
type config struct {
	Addr    string `json:"addr"`
	Node    string `json:"node"`    // full base URL, incl. /pool/api or /api
	Mode    string `json:"mode"`    // "pool" or "solo" (display only; Node is authoritative)
	Threads int    `json:"threads"`
}

var (
	nodeURL   string
	addr      string
	hashCount atomic.Uint64
	shares    atomic.Uint64 // accepted pool shares this session
	blocks    atomic.Uint64 // real blocks found (solo, or pool shares that hit the network target)
	current   atomic.Pointer[work]
	client    = &http.Client{Timeout: 15 * time.Second}
)

func configPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "cereblix-miner.json")
	}
	return "cereblix-miner.json"
}

func loadConfig() (config, bool) {
	var c config
	b, err := os.ReadFile(configPath())
	if err != nil || json.Unmarshal(b, &c) != nil {
		return config{}, false
	}
	return c, true
}

func saveConfig(c config) {
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(configPath(), b, 0644); err != nil {
		log.Printf("warning: could not save config (%v)", err)
		return
	}
	fmt.Printf("\n✔ Settings saved to %s\n", configPath())
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func modeFromURL(u string) string {
	if strings.Contains(u, "/pool/") {
		return "pool"
	}
	return "solo"
}

func buildNode(host, mode string) string {
	if mode == "solo" {
		return host + "/api"
	}
	return host + "/pool/api"
}

func read(r *bufio.Reader) string {
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}

func printCfg(c config) {
	host := c.Node
	for _, h := range []string{hostMain, hostRU} {
		if strings.HasPrefix(c.Node, h) {
			host = h
		}
	}
	fmt.Printf("   address : %s\n", c.Addr)
	fmt.Printf("   mode    : %s\n", c.Mode)
	fmt.Printf("   node    : %s  (%s)\n", c.Node, host)
	fmt.Printf("   threads : %d\n", c.Threads)
}

// wizard walks the user through setup, pre-filling from any existing config.
func wizard(in *bufio.Reader, cur config) config {
	c := cur

	// 1) address
	for !core.ValidAddr(c.Addr) {
		if c.Addr != "" {
			fmt.Println("Invalid address - it must look like: crb1 + 40 hex chars.")
		}
		fmt.Println("No wallet yet? Create one at https://cereblix.com/wallet/")
		fmt.Print("Enter your CRB address (crb1...): ")
		c.Addr = read(in)
	}

	// 2) server
	fmt.Println()
	fmt.Println("Which server do you want to mine through?")
	fmt.Println("  1) cereblix.com      - main server (recommended)")
	fmt.Println("  2) ru.cereblix.com   - Russia / CIS node  [pick this if your machine is in")
	fmt.Println("                         RU/CIS or cereblix.com is slow/blocked for you]")
	fmt.Println("  3) custom            - enter your own node URL")
	fmt.Print("Choose [1/2/3] (default 1): ")
	host, custom := hostMain, ""
	switch read(in) {
	case "2":
		host = hostRU
	case "3":
		for {
			fmt.Print("Full node base URL (e.g. http://1.2.3.4:18751/api): ")
			custom = read(in)
			if strings.HasPrefix(custom, "http://") || strings.HasPrefix(custom, "https://") {
				break
			}
			fmt.Println("Must start with http:// or https://")
		}
	}

	// 3) mode (for built-in hosts; a custom URL already encodes it)
	if custom != "" {
		c.Node = custom
		c.Mode = modeFromURL(custom)
	} else {
		fmt.Println()
		fmt.Println("Mining mode:")
		fmt.Println("  1) pool  - steady, frequent payouts; best for laptops & normal CPUs (recommended)")
		fmt.Println("  2) solo  - you keep the whole 50 CRB block, but it's a lottery (big rigs only)")
		fmt.Print("Choose [1/2] (default 1): ")
		if read(in) == "2" {
			c.Mode = "solo"
		} else {
			c.Mode = "pool"
		}
		c.Node = buildNode(host, c.Mode)
	}

	// 4) threads
	def := runtime.NumCPU()
	fmt.Println()
	fmt.Printf("Threads (CPU cores to use). This machine has %d. Tip: use physical cores and\n", def)
	fmt.Println("leave 1 free for the system; more threads than cores does not help.")
	fmt.Printf("Threads (default %d, Enter to accept): ", def)
	c.Threads = def
	if n, err := strconv.Atoi(read(in)); err == nil && n > 0 {
		c.Threads = n
	}
	return c
}

// --- self-update -----------------------------------------------------------

func dlURL() string {
	base := "https://github.com/Cerebra-CBR/cereblix/releases/latest/download/"
	if runtime.GOOS == "windows" {
		return base + "cereblix-miner-windows-amd64.exe"
	}
	return base + "cereblix-miner-linux-amd64"
}

// newer reports whether version a is higher than b ("1.10" > "1.9").
func newer(a, b string) bool {
	ap, bp := strings.Split(strings.TrimSpace(a), "."), strings.Split(b, ".")
	for i := 0; i < len(ap); i++ {
		var x, y int
		fmt.Sscanf(ap[i], "%d", &x)
		if i < len(bp) {
			fmt.Sscanf(bp[i], "%d", &y)
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// checkUpdate asks GitHub for the latest miner version. If GitHub is blocked
// (common in RU/CIS) it just suggests a manual check and moves on. If a newer
// version exists it offers a one-key auto-update.
func checkUpdate(in *bufio.Reader, tty bool) {
	cl := &http.Client{Timeout: 6 * time.Second}
	resp, err := cl.Get(updateVersionURL)
	if err != nil {
		fmt.Println("ℹ Could not reach GitHub to check for updates (it may be blocked in your region).")
		fmt.Println("  Check for a newer miner manually:", releasePage)
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	latest := strings.TrimSpace(string(b))
	if resp.StatusCode != 200 || latest == "" || !newer(latest, minerVersion) {
		return // up to date, or couldn't determine
	}
	fmt.Printf("\n⬆  A newer miner is available: v%s (you have v%s)\n", latest, minerVersion)
	fmt.Printf("   Download: %s\n", dlURL())
	if !tty {
		fmt.Println("   Run interactively to auto-update, or download manually.")
		return
	}
	fmt.Print("   Auto-update now? [y/N]: ")
	if strings.ToLower(read(in)) != "y" {
		fmt.Println("   Skipped. You can update later anytime.")
		return
	}
	if err := selfUpdate(); err != nil {
		fmt.Println("   Update failed:", err)
		fmt.Println("   Download manually:", dlURL())
		return
	}
	fmt.Println("   ✔ Updated to v" + latest + ". Restarting the miner...")
	exe, _ := os.Executable()
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if cmd.Start() == nil {
		os.Exit(0)
	}
}

// selfUpdate downloads the new binary and swaps it in, keeping a .old backup.
// Renaming a running executable is allowed on both Windows and Linux.
func selfUpdate() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cl := &http.Client{Timeout: 180 * time.Second}
	resp, err := cl.Get(dlURL())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if len(data) < 1_000_000 { // sanity: a real binary is several MB
		return fmt.Errorf("downloaded file looks wrong (%d bytes)", len(data))
	}
	if err := os.WriteFile(exe+".new", data, 0o755); err != nil {
		return err
	}
	os.Remove(exe + ".old")
	if err := os.Rename(exe, exe+".old"); err != nil {
		return err
	}
	if err := os.Rename(exe+".new", exe); err != nil {
		os.Rename(exe+".old", exe) // revert
		return err
	}
	return nil
}

// runUpdate is the -update flag: fetch latest, install if newer, then exit.
func runUpdate() {
	cl := &http.Client{Timeout: 10 * time.Second}
	resp, err := cl.Get(updateVersionURL)
	if err != nil {
		fmt.Println("Could not reach GitHub (it may be blocked in your region).")
		fmt.Println("Download the latest miner manually:", releasePage)
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	latest := strings.TrimSpace(string(b))
	if resp.StatusCode != 200 || latest == "" {
		fmt.Println("Couldn't determine the latest version. Check manually:", releasePage)
		return
	}
	if !newer(latest, minerVersion) {
		fmt.Printf("Already up to date (v%s).\n", minerVersion)
		return
	}
	fmt.Printf("Updating v%s -> v%s ...\n", minerVersion, latest)
	if err := selfUpdate(); err != nil {
		fmt.Println("Update failed:", err)
		fmt.Println("Download manually:", dlURL())
		return
	}
	fmt.Println("✔ Updated to v" + latest + ". Start the miner again to run the new version.")
}

func main() {
	// delete the old binary left over from a previous self-update. On Windows the
	// just-exited old process can hold the file for a moment, so retry until gone.
	if exe, err := os.Executable(); err == nil {
		go func() {
			for i := 0; i < 20; i++ {
				if os.Remove(exe+".old") == nil {
					return
				}
				time.Sleep(300 * time.Millisecond)
			}
		}()
	}

	var fNode, fAddr string
	var fThreads int
	var fReset, fReconf, fUpdate bool
	flag.StringVar(&fNode, "node", "", "node RPC base URL (overrides saved config)")
	flag.StringVar(&fAddr, "addr", "", "your CRB address (overrides saved config)")
	flag.IntVar(&fThreads, "threads", 0, "mining threads (overrides saved config)")
	flag.BoolVar(&fReset, "reset", false, "wipe the saved config and reconfigure")
	flag.BoolVar(&fReconf, "reconfigure", false, "re-run the setup wizard")
	flag.BoolVar(&fUpdate, "update", false, "download & install the latest miner from GitHub, then exit")
	flag.Parse()

	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║   Cereblix · NeuroMorph CPU miner  v1.2       ║")
	fmt.Println("║   one CPU = one vote                          ║")
	fmt.Println("╚══════════════════════════════════════════════╝")

	if fUpdate {
		runUpdate()
		return
	}

	cfg, have := loadConfig()
	if fReset {
		os.Remove(configPath())
		cfg, have = config{}, false
		fmt.Println("Config reset.")
	}
	// command-line flags override the saved config (and run non-interactively)
	if fAddr != "" {
		cfg.Addr = fAddr
	}
	if fNode != "" {
		cfg.Node, cfg.Mode = fNode, modeFromURL(fNode)
	}
	if fThreads > 0 {
		cfg.Threads = fThreads
	}
	flagsGiven := fAddr != "" || fNode != ""

	in := bufio.NewReader(os.Stdin)
	tty := isTTY()
	complete := core.ValidAddr(cfg.Addr) && cfg.Node != ""

	switch {
	case flagsGiven:
		// service / power-user mode: honour flags, no wizard
	case fReconf && tty:
		cfg = wizard(in, cfg)
		saveConfig(cfg)
	case complete && have && tty:
		fmt.Printf("\nSaved settings (from %s):\n", configPath())
		printCfg(cfg)
		fmt.Print("\nPress Enter to start mining with these, or type 'c' to change: ")
		if read(in) == "c" {
			cfg = wizard(in, cfg)
			saveConfig(cfg)
		}
	case !complete && tty:
		cfg = wizard(in, cfg)
		saveConfig(cfg)
	}

	// fallbacks (non-interactive or partial config)
	if cfg.Node == "" {
		cfg.Node, cfg.Mode = buildNode(hostMain, "solo"), "solo"
	}
	if cfg.Mode == "" {
		cfg.Mode = modeFromURL(cfg.Node)
	}
	if cfg.Threads <= 0 {
		cfg.Threads = runtime.NumCPU()
	}
	for !core.ValidAddr(cfg.Addr) {
		if !tty {
			fmt.Println("error: a valid address is required. Run with -addr crb1... or run interactively.")
			os.Exit(1)
		}
		fmt.Println("No wallet yet? Create one at https://cereblix.com/wallet/")
		fmt.Print("Enter your CRB address (crb1...): ")
		cfg.Addr = read(in)
	}

	nodeURL, addr = cfg.Node, cfg.Addr
	threads := cfg.Threads

	checkUpdate(in, tty)

	fmt.Println()
	fmt.Printf("⚙  All your settings live in:  %s\n", configPath())
	fmt.Println("   They're loaded automatically next time. To change them:")
	fmt.Println("     -reconfigure   re-run this setup")
	fmt.Println("     -reset         wipe the config and start fresh")
	fmt.Println("   (or just edit / delete that file).")
	fmt.Println()
	log.Printf("mode: %s | node: %s | address: %s | threads: %d", cfg.Mode, nodeURL, addr, threads)

	// Try once for a friendly status line, but NEVER exit on failure: the miner
	// keeps retrying until it reaches a node, or until the user stops it (Ctrl+C).
	if err := fetchWork(); err != nil {
		log.Printf("node not reachable yet (%v) - will keep retrying, just leave it running", err)
	} else {
		log.Printf("connected - mining")
	}
	go workLoop()
	for i := 0; i < threads; i++ {
		go mineThread(uint64(i))
	}

	last := uint64(0)
	for {
		time.Sleep(15 * time.Second)
		cur := hashCount.Load()
		w := current.Load()
		if w == nil {
			log.Printf("still waiting for the node... (no work yet) - retrying, leave it running")
			continue
		}
		log.Printf("hashrate: %.1f H/s | block %d (epoch %d) | shares %d · blocks %d",
			float64(cur-last)/15.0, w.Height, w.Epoch, shares.Load(), blocks.Load())
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
		return fmt.Errorf("node/proxy returned a non-JSON response (temporary outage? HTTP %d) - retrying", resp.StatusCode)
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
		if w == nil { // no work yet (node unreachable) - wait, never crash
			time.Sleep(time.Second)
			continue
		}
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

		// Nonce layout: [extranonce:16][thread:8][counter:40]. The pool-assigned
		// extranonce occupies the top 16 bits and stays FIXED, so every share this
		// miner produces is bound to its identity (the pool rejects a nonce whose
		// top bits don't match the extranonce it handed this address). Solo mining
		// gets extranonce 0, which reproduces ordinary per-thread nonce search.
		const enShift, threadShift = 48, 40
		const counterMask = (uint64(1) << threadShift) - 1
		base := (w.Extranonce&0xFFFF)<<enShift | (id&0xFF)<<threadShift
		ctr := uint64(time.Now().UnixNano()) & counterMask
		for i := 0; ; i++ {
			nonce := base | (ctr & counterMask)
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
			ctr++
			if i%32 == 0 && current.Load() != w {
				break // new work arrived
			}
		}
	}
}

func submit(id string, nonce uint64, height uint64) {
	// nonce as a string so 64-bit values (extranonce in the top bits) survive
	// JSON without precision loss; the node/pool accept string or number.
	body, _ := json.Marshal(map[string]any{"id": id, "nonce": strconv.FormatUint(nonce, 10)})
	resp, err := client.Post(nodeURL+"/submitwork", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("submit failed: %v", err)
		return
	}
	defer resp.Body.Close()
	// A node answers {"result":"accepted","hash":...} - that's a real block.
	// A pool answers {"result":"share","block":bool} - "share" is just a proof at
	// the easier pool target (NOT a block); "block":true means this share also met
	// the network target and the pool turned it into a real block.
	var out struct {
		Result string `json:"result"`
		Hash   string `json:"hash"`
		Block  bool   `json:"block"`
		Error  string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	switch {
	case out.Error != "":
		log.Printf("submit for block %d rejected: %s", height, out.Error)
	case out.Result == "stale" || out.Result == "duplicate":
		// transient (new work raced in / already counted) - not worth a line
	case out.Result == "share":
		n := shares.Add(1)
		if out.Block {
			blocks.Add(1)
			log.Printf("*** your share solved BLOCK %d for the pool! *** (share #%d) - reward is shared", height, n)
		} else {
			log.Printf("share accepted (#%d) - paid out automatically by the pool", n)
		}
	default: // solo mining straight against a node: an accepted submit IS a block
		blocks.Add(1)
		log.Printf("*** BLOCK %d FOUND AND ACCEPTED *** %s", height, out.Hash)
	}
}
