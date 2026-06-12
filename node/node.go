// Package node wires the Cereblix chain into a P2P + RPC daemon with an
// optional built-in CPU miner.
package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"cereblix/core"
	nm "cereblix/neuromorph"
)

const (
	syncInterval  = 10 * time.Second
	batchBlocks   = 200
	templateMaxAge = 8 * time.Second
)

type Node struct {
	Chain *core.Chain

	dataDir   string
	publicURL string // advertised to peers, may be empty

	peersMu sync.Mutex
	peers   map[string]time.Time // base URL -> last success

	client *http.Client

	tmplMu    sync.Mutex
	templates map[string]*core.Block // template id -> unmined block

	cpMu       sync.Mutex
	checkpoint core.Checkpoint // latest signed authority checkpoint we hold/serve

	hashCount atomic.Uint64 // built-in miner counter
	stop      chan struct{}
}

func New(chain *core.Chain, dataDir, publicURL string, seedPeers []string) *Node {
	n := &Node{
		Chain:     chain,
		dataDir:   dataDir,
		publicURL: strings.TrimRight(publicURL, "/"),
		peers:     map[string]time.Time{},
		client:    safePeerClient(),
		templates: map[string]*core.Block{},
		stop:      make(chan struct{}),
	}
	n.loadPeers()
	for _, p := range seedPeers {
		n.addPeer(p)
	}
	chain.OnNewBlock = func(b *core.Block) { go n.broadcastBlock(b) }
	return n
}

// ------------------------------------------------------------------ peers

func (n *Node) peersFile() string { return filepath.Join(n.dataDir, "peers.json") }

func (n *Node) loadPeers() {
	raw, err := os.ReadFile(n.peersFile())
	if err != nil {
		return
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		for _, p := range list {
			n.addPeer(p)
		}
	}
}

func (n *Node) savePeers() {
	list := n.peerList()
	raw, _ := json.Marshal(list)
	_ = os.WriteFile(n.peersFile(), raw, 0o644)
}

func (n *Node) addPeer(peerURL string) {
	peerURL = strings.TrimRight(strings.TrimSpace(peerURL), "/")
	if peerURL == "" || !strings.HasPrefix(peerURL, "http") {
		return
	}
	if n.publicURL != "" && peerURL == n.publicURL {
		return
	}
	// SSRF guard: a peer URL arrives unauthenticated via the X-Cerebra-Peer
	// header, and the node will later issue requests to it during sync/discovery.
	// Reject loopback/private/link-local literals so the node can't be aimed at
	// internal services (e.g. cloud metadata 169.254.169.254) or used as a relay.
	if !peerHostAllowed(peerURL) {
		return
	}
	n.peersMu.Lock()
	if _, ok := n.peers[peerURL]; !ok && len(n.peers) < 64 {
		n.peers[peerURL] = time.Time{}
	}
	n.peersMu.Unlock()
}

// safePeerClient builds the HTTP client used for ALL outbound peer requests. Its
// dialer re-checks the *resolved* IP at connect time and refuses to connect to
// loopback/private/link-local/unspecified addresses. This is the authoritative
// SSRF defense: peerHostAllowed only screens IP-literal URLs, so a hostname that
// resolves (or DNS-rebinds) to 169.254.169.254 / 127.0.0.1 / RFC1918 would slip
// past it — but the dial Control hook here blocks the actual connection.
func safePeerClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("refusing dial to unresolved address %q", address)
			}
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
				ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				return fmt.Errorf("refusing dial to non-public address %s", ip)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			MaxIdleConns:          64,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 2 * time.Second,
		},
	}
}

// peerHostAllowed rejects URLs whose host is a loopback/private/link-local IP
// literal or an obvious localhost name. Public hostnames/IPs are allowed.
func peerHostAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if h := strings.ToLower(host); h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return false
		}
	}
	return true
}

func (n *Node) peerList() []string {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()
	out := make([]string, 0, len(n.peers))
	for p := range n.peers {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (n *Node) markPeer(url string, ok bool) {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()
	if ok {
		n.peers[url] = time.Now()
	}
}

// ------------------------------------------------------------ http helpers

func (n *Node) getJSON(url string, out any) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	if n.publicURL != "" {
		req.Header.Set("X-Cerebra-Peer", n.publicURL)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (n *Node) postJSON(url string, body any, out any) error {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.publicURL != "" {
		req.Header.Set("X-Cerebra-Peer", n.publicURL)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ------------------------------------------------------------------- sync

type tipInfo struct {
	Height  uint64 `json:"height"`
	Hash    string `json:"hash"`
	CumWork string `json:"cumwork"` // hex
}

func (n *Node) myTip() tipInfo {
	tip := n.Chain.Tip()
	return tipInfo{
		Height:  tip.Height,
		Hash:    tip.Hash(),
		CumWork: n.Chain.CumWork().Text(16),
	}
}

func (n *Node) SyncLoop() {
	for {
		select {
		case <-n.stop:
			return
		case <-time.After(syncInterval):
		}
		for _, p := range n.peerList() {
			n.syncWithPeer(p)
			n.fetchCheckpoint(p)
		}
		n.savePeers()
		n.discoverPeers()
	}
}

func (n *Node) syncWithPeer(peer string) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("sync: recovered from panic on peer %s: %v", peer, rec)
		}
	}()
	var their tipInfo
	if err := n.getJSON(peer+"/p2p/tip", &their); err != nil {
		return
	}
	n.markPeer(peer, true)
	if len(their.CumWork) > 80 { // a 256-bit cumwork is ~64 hex; reject absurd values
		return
	}
	theirWork, ok := new(big.Int).SetString(their.CumWork, 16)
	if !ok || theirWork.Cmp(n.Chain.CumWork()) <= 0 {
		return
	}
	// Find the common ancestor (binary search over heights).
	ourH := n.Chain.Height()
	lo, hi := uint64(0), ourH
	if their.Height < hi {
		hi = their.Height
	}
	anc := uint64(0)
	for lo <= hi {
		mid := (lo + hi) / 2
		var hr struct {
			Hash string `json:"hash"`
		}
		if err := n.getJSON(fmt.Sprintf("%s/p2p/hash?h=%d", peer, mid), &hr); err != nil {
			return
		}
		ours := n.Chain.BlockAt(mid)
		if ours != nil && ours.Hash() == hr.Hash {
			anc = mid
			lo = mid + 1
		} else {
			if mid == 0 {
				return // genesis mismatch: not our network
			}
			hi = mid - 1
		}
	}
	log.Printf("sync: peer %s ahead (h=%d vs %d), fetching from %d", peer, their.Height, ourH, anc+1)
	var pending []*core.Block
	from := anc + 1
	for {
		var batch []*core.Block
		url := fmt.Sprintf("%s/p2p/blocks?from=%d&count=%d", peer, from, batchBlocks)
		if err := n.getJSON(url, &batch); err != nil || len(batch) == 0 {
			break
		}
		pending = append(pending, batch...)
		from += uint64(len(batch))
		if from > their.Height || len(pending) >= 5000 {
			if err := n.Chain.TryAdoptChain(anc+1, pending); err != nil {
				log.Printf("sync: adopt failed: %v", err)
				return
			}
			anc = n.Chain.Height()
			pending = nil
			if from > their.Height {
				break
			}
		}
	}
	if len(pending) > 0 {
		if err := n.Chain.TryAdoptChain(anc+1, pending); err != nil {
			log.Printf("sync: adopt failed: %v", err)
			return
		}
	}
	log.Printf("sync: now at height %d", n.Chain.Height())
}

// fetchCheckpoint pulls a peer's authority checkpoint, verifies its signature
// against the hardcoded authority key, and enforces it if it matches our chain.
func (n *Node) fetchCheckpoint(peer string) {
	var cp core.Checkpoint
	if err := n.getJSON(peer+"/p2p/checkpoint", &cp); err != nil {
		return
	}
	if !cp.Verify() {
		return
	}
	if n.Chain.ApplyCheckpoint(cp) {
		n.cpMu.Lock()
		if cp.Height >= n.checkpoint.Height {
			n.checkpoint = cp
		}
		n.cpMu.Unlock()
		log.Printf("checkpoint: enforcing authority checkpoint at height %d", cp.Height)
	}
}

func (n *Node) discoverPeers() {
	for _, p := range n.peerList() {
		var list []string
		if err := n.getJSON(p+"/p2p/peers", &list); err == nil {
			for _, u := range list {
				n.addPeer(u)
			}
		}
	}
}

func (n *Node) broadcastBlock(b *core.Block) {
	for _, p := range n.peerList() {
		go func(peer string) {
			var resp map[string]string
			_ = n.postJSON(peer+"/p2p/block", b, &resp)
		}(p)
	}
}

func (n *Node) broadcastTx(t *core.Tx) {
	for _, p := range n.peerList() {
		go func(peer string) {
			_ = n.postJSON(peer+"/p2p/tx", t, nil)
		}(p)
	}
}

// ------------------------------------------------------- per-IP rate limiter

// rateLimiter is a token-bucket limiter keyed by client IP. It fronts the
// unauthenticated, internet-exposed P2P port so a single source cannot flood
// the node with expensive PoW-verify (/p2p/block) or sync requests. Limits are
// generous enough for honest peers syncing in 200-block batches.
type rateLimiter struct {
	mu     sync.Mutex
	b      map[string]*tokenBucket
	rate   float64 // tokens refilled per second
	burst  float64 // bucket capacity
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// rlMaxBuckets caps the limiter's memory footprint.
const rlMaxBuckets = 8192

func newRateLimiter(rate, burst float64) *rateLimiter {
	return &rateLimiter{b: map[string]*tokenBucket{}, rate: rate, burst: burst}
}

// gcLocked frees memory while preserving active throttle state. It first drops
// buckets that have fully refilled (idle — recreating one later yields the same
// full burst, so no limit is lost). If still over cap (a genuine large-scale
// distinct-IP flood), it trims arbitrary entries down to the cap. Unlike the
// previous full-map wipe, honest peers currently being throttled keep their
// depleted buckets. Caller must hold rl.mu.
func (rl *rateLimiter) gcLocked(now time.Time) {
	for ip, tb := range rl.b {
		if tb.tokens+now.Sub(tb.last).Seconds()*rl.rate >= rl.burst {
			delete(rl.b, ip)
		}
	}
	for ip := range rl.b {
		if len(rl.b) <= rlMaxBuckets {
			break
		}
		delete(rl.b, ip)
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	tb := rl.b[ip]
	if tb == nil {
		// Bound memory without throwing away active throttle state: a flood of
		// spoofed-source IPs must not reset everyone's bucket to full burst (the
		// old full-map wipe did exactly that). Evict idle/expired buckets first.
		if len(rl.b) >= rlMaxBuckets {
			rl.gcLocked(now)
		}
		tb = &tokenBucket{tokens: rl.burst, last: now}
		rl.b[ip] = tb
	}
	tb.tokens += now.Sub(tb.last).Seconds() * rl.rate
	if tb.tokens > rl.burst {
		tb.tokens = rl.burst
	}
	tb.last = now
	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (rl *rateLimiter) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(clientIP(r)) {
			writeErr(w, 429, "rate limit exceeded")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// -------------------------------------------------------------- p2p server

func (n *Node) P2PHandler() http.Handler {
	mux := http.NewServeMux()
	reg := func(w http.ResponseWriter, r *http.Request) {
		if u := r.Header.Get("X-Cerebra-Peer"); u != "" {
			n.addPeer(u)
		}
	}
	mux.HandleFunc("/p2p/tip", func(w http.ResponseWriter, r *http.Request) {
		reg(w, r)
		writeJSON(w, n.myTip())
	})
	mux.HandleFunc("/p2p/hash", func(w http.ResponseWriter, r *http.Request) {
		h, _ := strconv.ParseUint(r.URL.Query().Get("h"), 10, 64)
		b := n.Chain.BlockAt(h)
		if b == nil {
			writeErr(w, 404, "no such height")
			return
		}
		writeJSON(w, map[string]string{"hash": b.Hash()})
	})
	mux.HandleFunc("/p2p/blocks", func(w http.ResponseWriter, r *http.Request) {
		from, _ := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
		count, _ := strconv.Atoi(r.URL.Query().Get("count"))
		if count <= 0 || count > batchBlocks {
			count = batchBlocks
		}
		writeJSON(w, n.Chain.Blocks(from, count))
	})
	mux.HandleFunc("/p2p/block", func(w http.ResponseWriter, r *http.Request) {
		reg(w, r)
		var b core.Block
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			writeErr(w, 400, "bad json")
			return
		}
		err := n.Chain.AddBlock(&b)
		if err == nil {
			log.Printf("p2p: accepted block %d %s", b.Height, b.Hash()[:16])
			writeJSON(w, map[string]string{"result": "accepted"})
			return
		}
		if errors.Is(err, errNotTip) || strings.Contains(err.Error(), "not extending tip") {
			// Maybe a longer chain exists; sync will pick it up.
			if u := r.Header.Get("X-Cerebra-Peer"); u != "" {
				go n.syncWithPeer(strings.TrimRight(u, "/"))
			}
		}
		writeErr(w, 400, err.Error())
	})
	mux.HandleFunc("/p2p/tx", func(w http.ResponseWriter, r *http.Request) {
		var t core.Tx
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			writeErr(w, 400, "bad json")
			return
		}
		if err := n.Chain.AddTx(&t); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, map[string]string{"result": "accepted"})
	})
	mux.HandleFunc("/p2p/peers", func(w http.ResponseWriter, r *http.Request) {
		reg(w, r)
		writeJSON(w, n.peerList())
	})
	// Serve the latest authority checkpoint so peers can pull and enforce it.
	// Receivers verify the signature against the hardcoded authority key, so a
	// relaying peer cannot forge one.
	mux.HandleFunc("/p2p/checkpoint", func(w http.ResponseWriter, r *http.Request) {
		n.cpMu.Lock()
		cp := n.checkpoint
		n.cpMu.Unlock()
		if cp.Hash == "" {
			writeErr(w, 404, "no checkpoint")
			return
		}
		writeJSON(w, cp)
	})
	return mux
}

var errNotTip = errors.New("not extending tip")

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0 && len(s) <= 18
}

// -------------------------------------------------------------- rpc server

func (n *Node) RPCHandler() http.Handler {
	mux := http.NewServeMux()
	h := func(path string, fn http.HandlerFunc) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			if r.Method == "OPTIONS" {
				return
			}
			fn(w, r)
		})
	}

	h("/api/status", func(w http.ResponseWriter, r *http.Request) {
		tip := n.Chain.Tip()
		tgt, _ := tip.TargetInt()
		diff := core.WorkOf(tgt)
		// Network hashrate estimate over a short recent window (~8 blocks) so it
		// reacts quickly when miners join or leave. The window is the time
		// actually elapsed, including the gap since the last block, so a sudden
		// drop in mining is reflected within a block or two rather than 20.
		var hashrate float64
		hgt := n.Chain.Height()
		now := uint64(time.Now().Unix())
		if hgt >= 1 {
			const hrWindow = 8
			w0 := uint64(hrWindow)
			if hgt < w0 {
				w0 = hgt
			}
			first := n.Chain.BlockAt(hgt - w0)
			work := new(big.Int)
			for i := hgt - w0 + 1; i <= hgt; i++ {
				t, _ := n.Chain.BlockAt(i).TargetInt()
				work.Add(work, core.WorkOf(t))
			}
			// Elapsed time = window span, but never less than time since the
			// last block (an overdue block drags the estimate down in real time).
			dt := float64(tip.Time) - float64(first.Time)
			if sinceTip := float64(now) - float64(tip.Time); sinceTip > dt {
				dt = sinceTip
			}
			if dt < 1 {
				dt = 1
			}
			wf, _ := new(big.Float).SetInt(work).Float64()
			hashrate = wf / dt
		}
		blockAge := int64(now) - int64(tip.Time)
		if blockAge < 0 {
			blockAge = 0
		}
		_, epoch := n.Chain.EpochSeedForNext()
		writeJSON(w, map[string]any{
			"height":     tip.Height,
			"tip":        tip.Hash(),
			"time":       tip.Time,
			"target":     tip.Target,
			"difficulty": diff.String(),
			"supply":     n.Chain.Supply(),
			"mempool":    len(n.Chain.MempoolTxs()),
			"peers":      len(n.peerList()),
			"epoch":      epoch,
			"reward":        core.BlockSubsidy(tip.Height + 1),
			"hashrate":      hashrate,
			"block_age":     blockAge,
			"now":           now,
			"fee_suggested": n.Chain.SuggestedFee(),
			"chain_id":        core.ChainID,
			"chain_id_height": core.ChainIDHeight,
		})
	})

	h("/api/balance", func(w http.ResponseWriter, r *http.Request) {
		addr := r.URL.Query().Get("addr")
		if !core.ValidAddr(addr) {
			writeErr(w, 400, "bad address")
			return
		}
		acc := n.Chain.Account(addr)
		recv, mined, sent, txn := n.Chain.AddrTotals(addr)
		writeJSON(w, map[string]any{"address": addr, "balance": acc.Balance, "nonce": acc.Nonce,
			"spendable": n.Chain.SpendableBalance(addr),
			"received":  recv, "mined": mined, "sent": sent, "txn": txn})
	})

	h("/api/history", func(w http.ResponseWriter, r *http.Request) {
		addr := r.URL.Query().Get("addr")
		if !core.ValidAddr(addr) {
			writeErr(w, 400, "bad address")
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 200 {
			limit = 50
		}
		writeJSON(w, n.Chain.History(addr, limit))
	})

	h("/api/blocks", func(w http.ResponseWriter, r *http.Request) {
		last, _ := strconv.Atoi(r.URL.Query().Get("last"))
		if last <= 0 || last > 100 {
			last = 15
		}
		hgt := n.Chain.Height()
		from := uint64(0)
		if uint64(last) <= hgt {
			from = hgt - uint64(last) + 1
		}
		blocks := n.Chain.Blocks(from, last)
		out := make([]map[string]any, 0, len(blocks))
		for i := len(blocks) - 1; i >= 0; i-- {
			b := blocks[i]
			out = append(out, map[string]any{
				"height": b.Height, "hash": b.Hash(), "time": b.Time,
				"txs": len(b.Txs), "miner": b.Txs[0].To, "reward": b.Txs[0].Amount,
			})
		}
		writeJSON(w, out)
	})

	h("/api/block", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if hs := q.Get("h"); hs != "" {
			hgt, err := strconv.ParseUint(hs, 10, 64)
			if err != nil {
				writeErr(w, 400, "bad height")
				return
			}
			b := n.Chain.BlockAt(hgt)
			if b == nil {
				writeErr(w, 404, "not found")
				return
			}
			writeJSON(w, b)
			return
		}
		if hash := q.Get("hash"); hash != "" {
			b := n.Chain.BlockByHash(hash)
			if b == nil {
				writeErr(w, 404, "not found")
				return
			}
			writeJSON(w, b)
			return
		}
		writeErr(w, 400, "need h= or hash=")
	})

	h("/api/mempool", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, n.Chain.MempoolTxs())
	})

	h("/api/tx", func(w http.ResponseWriter, r *http.Request) {
		// GET /api/tx?id=<txid> looks up a transaction (explorer).
		if r.Method == "GET" {
			id := r.URL.Query().Get("id")
			if len(id) != 64 {
				writeErr(w, 400, "need id=<64 hex>")
				return
			}
			loc := n.Chain.FindTx(id)
			if !loc.Found {
				writeErr(w, 404, "transaction not found")
				return
			}
			writeJSON(w, loc)
			return
		}
		if r.Method != "POST" {
			writeErr(w, 405, "GET (lookup) or POST (submit) only")
			return
		}
		var t core.Tx
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			writeErr(w, 400, "bad json")
			return
		}
		if err := n.Chain.AddTx(&t); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		go n.broadcastTx(&t)
		writeJSON(w, map[string]string{"result": "accepted", "txid": t.ID()})
	})

	h("/api/mined", func(w http.ResponseWriter, r *http.Request) {
		addr := r.URL.Query().Get("addr")
		if !core.ValidAddr(addr) {
			writeErr(w, 400, "bad address")
			return
		}
		writeJSON(w, map[string]any{"address": addr, "blocks": n.Chain.MinedBlocks(addr)})
	})

	h("/api/richlist", func(w http.ResponseWriter, r *http.Request) {
		n2, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n2 <= 0 || n2 > 200 {
			n2 = 25
		}
		writeJSON(w, n.Chain.RichList(n2))
	})

	// /api/search?q= classifies a query and points the explorer at the right view.
	h("/api/search", func(w http.ResponseWriter, r *http.Request) {
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		switch {
		case q == "":
			writeErr(w, 400, "empty query")
		case core.ValidAddr(q):
			writeJSON(w, map[string]string{"type": "address", "value": q})
		case isAllDigits(q):
			hgt, _ := strconv.ParseUint(q, 10, 64)
			if n.Chain.BlockAt(hgt) == nil {
				writeErr(w, 404, "no block at that height")
				return
			}
			writeJSON(w, map[string]any{"type": "block", "height": hgt})
		case len(q) == 64 && isHex(q):
			if b := n.Chain.BlockByHash(q); b != nil {
				writeJSON(w, map[string]any{"type": "block", "height": b.Height})
				return
			}
			if loc := n.Chain.FindTx(q); loc.Found {
				writeJSON(w, map[string]string{"type": "tx", "value": q})
				return
			}
			writeErr(w, 404, "no block or transaction with that hash")
		default:
			writeErr(w, 400, "unrecognized query (height, block hash, txid, or crb1 address)")
		}
	})

	h("/api/getwork", func(w http.ResponseWriter, r *http.Request) {
		addr := r.URL.Query().Get("addr")
		tmpl, err := n.getTemplate(addr)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		seed, epoch := n.Chain.EpochSeedForNext()
		writeJSON(w, map[string]any{
			"id":     tmpl.PrevHash + "|" + addr,
			"header": hex.EncodeToString(tmpl.HeaderBytes()),
			"target": tmpl.Target,
			"seed":   hex.EncodeToString(seed),
			"epoch":  epoch,
			"height": tmpl.Height,
		})
	})

	h("/api/submitwork", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeErr(w, 405, "POST only")
			return
		}
		var req struct {
			ID    string `json:"id"`
			Nonce uint64 `json:"nonce"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, 400, "bad json")
			return
		}
		n.tmplMu.Lock()
		tmpl := n.templates[req.ID]
		n.tmplMu.Unlock()
		if tmpl == nil {
			writeErr(w, 404, "stale or unknown work id")
			return
		}
		b := *tmpl
		b.Nonce = req.Nonce
		if err := n.Chain.AddBlock(&b); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		log.Printf("miner: external miner found block %d %s", b.Height, b.Hash()[:16])
		writeJSON(w, map[string]string{"result": "accepted", "hash": b.Hash()})
	})

	h("/api/params", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"coin":             "Cereblix",
			"ticker":           "CRB",
			"unit":             core.CoinUnit,
			"block_time":       core.BlockTargetSpacing,
			"halving_interval": core.HalvingInterval,
			"epoch_length":     core.EpochLength,
			"initial_reward":   core.InitialReward,
			"max_supply":       uint64(core.InitialReward) * core.HalvingInterval * 2,
			"algo":             "NeuroMorph v1",
		})
	})

	// /api/checkpoint: POST (localhost, from the authority signing tool) pushes a
	// signed checkpoint; GET returns the one we currently hold.
	h("/api/checkpoint", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			// Defense in depth: only the local authority signing tool may POST
			// here. The signature check below already makes forgery impossible,
			// but enforcing loopback means even a misconfigured Apache that
			// proxied this path can't let a remote caller reach it.
			if ip := net.ParseIP(clientIP(r)); ip == nil || !ip.IsLoopback() {
				writeErr(w, 403, "checkpoint POST is localhost-only")
				return
			}
			var cp core.Checkpoint
			if err := json.NewDecoder(r.Body).Decode(&cp); err != nil {
				writeErr(w, 400, "bad json")
				return
			}
			if !cp.Verify() {
				writeErr(w, 400, "bad checkpoint signature")
				return
			}
			n.Chain.ApplyCheckpoint(cp)
			n.cpMu.Lock()
			if cp.Height >= n.checkpoint.Height {
				n.checkpoint = cp
			}
			n.cpMu.Unlock()
			writeJSON(w, map[string]any{"result": "accepted", "height": cp.Height})
			return
		}
		n.cpMu.Lock()
		cp := n.checkpoint
		n.cpMu.Unlock()
		writeJSON(w, cp)
	})

	return mux
}

// getTemplate returns a cached or fresh mining template for `addr`.
func (n *Node) getTemplate(addr string) (*core.Block, error) {
	if !core.ValidAddr(addr) {
		return nil, errors.New("bad or missing addr")
	}
	id := n.Chain.Tip().Hash() + "|" + addr
	n.tmplMu.Lock()
	defer n.tmplMu.Unlock()
	// Serve a STABLE template per tip: once built for this tip, reuse it unchanged
	// until a new block arrives (new tip -> new id below). Rebuilding with a fresh
	// Time while the tip is unchanged desyncs pool miners - they cache the header
	// and submit a nonce computed for the OLD Time, which the node would then
	// reject as "insufficient proof of work", throwing away real work. A frozen
	// Time stays valid on an unchanged tip (always < now+300 and > median-time-past).
	if t, ok := n.templates[id]; ok {
		return t, nil
	}
	tmpl, err := n.Chain.BuildTemplate(addr)
	if err != nil {
		return nil, err
	}
	id = tmpl.PrevHash + "|" + addr
	// Drop templates from older tips.
	for k := range n.templates {
		if !strings.HasPrefix(k, tmpl.PrevHash) {
			delete(n.templates, k)
		}
	}
	// Hard cap: many distinct addresses at the SAME tip all share the PrevHash
	// prefix above and survive the prune, so /api/getwork spam with random
	// addresses could grow this unbounded. Bound it regardless.
	const maxTemplates = 512
	if _, exists := n.templates[id]; !exists && len(n.templates) >= maxTemplates {
		for k := range n.templates {
			delete(n.templates, k)
			break
		}
	}
	n.templates[id] = tmpl
	return tmpl, nil
}

// ------------------------------------------------------------ built-in miner

func (n *Node) Mine(threads int, coinbase string) {
	log.Printf("miner: starting %d threads, paying to %s", threads, coinbase)
	for i := 0; i < threads; i++ {
		go n.mineWorker(uint64(i), coinbase)
	}
	go func() {
		t := time.NewTicker(30 * time.Second)
		last := uint64(0)
		for range t.C {
			cur := n.hashCount.Load()
			log.Printf("miner: %.1f H/s (height %d)", float64(cur-last)/30.0, n.Chain.Height())
			last = cur
		}
	}()
}

func (n *Node) mineWorker(id uint64, coinbase string) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("miner: worker %d recovered from panic: %v; restarting", id, rec)
			time.Sleep(time.Second)
			go n.mineWorker(id, coinbase)
		}
	}()
	var vm *nm.VM
	var vmEpoch uint64 = ^uint64(0)
	for {
		tmpl, err := n.Chain.BuildTemplate(coinbase)
		if err != nil {
			log.Printf("miner: template error: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		seed, epoch := n.Chain.EpochSeedForNext()
		if vm == nil || epoch != vmEpoch {
			vm = nm.NewVM(nm.DeriveParams(seed))
			vmEpoch = epoch
		}
		target, _ := tmpl.TargetInt()
		header := tmpl.HeaderBytes()
		height := tmpl.Height
		prevHash := tmpl.PrevHash
		nonce := id<<56 | uint64(time.Now().UnixNano())&0xFFFFFFFF<<8
		deadline := time.Now().Add(templateMaxAge)
		for time.Now().Before(deadline) {
			putNonce(header, nonce)
			hash := vm.Hash(header, height)
			n.hashCount.Add(1)
			if core.HashMeetsTarget(hash, target) {
				b := *tmpl
				b.Nonce = nonce
				if err := n.Chain.AddBlock(&b); err != nil {
					log.Printf("miner: block rejected: %v", err)
				} else {
					log.Printf("miner: FOUND block %d %s", b.Height, b.Hash()[:16])
				}
				break
			}
			nonce++
			if n.Chain.Tip().Hash() != prevHash {
				break // tip moved, rebuild template
			}
		}
	}
}

func putNonce(header []byte, nonce uint64) {
	for i := 0; i < 8; i++ {
		header[core.NonceOffset+i] = byte(nonce >> (8 * i))
	}
}

// ---------------------------------------------------------------- serving

// maxRequestBytes caps any single request body. Blocks/txs are tiny; this
// stops a peer from exhausting memory with a giant POST.
const maxRequestBytes = 8 << 20 // 8 MiB

// harden wraps a handler with a body-size cap and a panic guard so that no
// single malformed request can crash the node or exhaust its memory.
func harden(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("recovered from handler panic: %v", rec)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
		h.ServeHTTP(w, r)
	})
}

// newServer builds an http.Server with timeouts that defeat slow-loris and
// idle-socket exhaustion attacks (ListenAndServe's default has none).
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           harden(h),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64 KiB
	}
}

func (n *Node) Serve(p2pAddr, rpcAddr string) error {
	errc := make(chan error, 2)
	// Per-IP rate limit on the unauthenticated, internet-exposed P2P port.
	// ~25 req/s/IP, burst 50 - far above honest peer sync, far below a flood.
	p2pRL := newRateLimiter(25, 50)
	go func() {
		log.Printf("p2p listening on %s", p2pAddr)
		errc <- newServer(p2pAddr, p2pRL.wrap(n.P2PHandler())).ListenAndServe()
	}()
	go func() {
		log.Printf("rpc listening on %s", rpcAddr)
		errc <- newServer(rpcAddr, n.RPCHandler()).ListenAndServe()
	}()
	go n.SyncLoop()
	return <-errc
}
