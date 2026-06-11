// cereblix-pool: a minimal CPU mining pool for Cereblix.
//
// It speaks the SAME getwork/submitwork protocol as the node, so the stock
// cereblix-miner works against it unchanged - point -node at the pool. The pool
// hands out work paying to the pool wallet but at an EASIER "share" target, so
// small miners get steady, low-variance credit even when network difficulty is
// high. Each submitted share is re-verified (NeuroMorph hash). When a share also
// meets the real network target the pool forwards the block to the node; the
// reward (minus a pool fee) is split among miners proportional to their shares
// in that round, then paid out from the pool wallet once it crosses a threshold.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"cereblix/core"
	nm "cereblix/neuromorph"
)

var (
	nodeAPI   string
	poolAddr  string
	priv      ed25519.PrivateKey
	feePermil uint64 // pool fee in per-mille (e.g. 10 = 1%)
	shareShift uint
	minPayout uint64
	statePath string
)

// ---------------------------------------------------------------- work cache

type work struct {
	nodeID      string
	header      []byte
	seed        []byte
	height      uint64
	netTarget   *big.Int
	shareTarget *big.Int
	seen        map[uint64]bool
}

var (
	workMu     sync.Mutex
	curWork    *work
	lastFetch  time.Time
	vmMu       sync.Mutex
	vm         *nm.VM
	vmEpoch    uint64 = ^uint64(0)
)

// ------------------------------------------------------------- accounting

type state struct {
	mu       sync.Mutex
	Shares   map[string]float64 `json:"-"`       // current round (ephemeral)
	Owed     map[string]uint64  `json:"owed"`    // accrued, not yet paid
	Paid     map[string]uint64  `json:"paid"`    // lifetime paid
	Found    int                `json:"found"`   // blocks found by the pool
	RoundShares float64         `json:"-"`
}

var st = &state{Shares: map[string]float64{}, Owed: map[string]uint64{}, Paid: map[string]uint64{}}

func (s *state) load() {
	if raw, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(raw, s)
	}
	if s.Owed == nil {
		s.Owed = map[string]uint64{}
	}
	if s.Paid == nil {
		s.Paid = map[string]uint64{}
	}
	s.Shares = map[string]float64{}
}

func (s *state) save() {
	raw, _ := json.Marshal(s)
	_ = os.WriteFile(statePath, raw, 0o600)
}

// ------------------------------------------------------------------ node i/o

func nodeGet(path string, out any) error {
	resp, err := http.Get(nodeAPI + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("node http %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// refreshWork fetches a fresh template (paying to the pool) from the node, at
// most every ~2s, and computes the share target from the network target.
func refreshWork() (*work, error) {
	workMu.Lock()
	defer workMu.Unlock()
	if curWork != nil && time.Since(lastFetch) < 2*time.Second {
		return curWork, nil
	}
	var gw struct {
		ID, Header, Target, Seed string
		Height                   uint64
		Epoch                    uint64
	}
	if err := nodeGet("/getwork?addr="+poolAddr, &gw); err != nil {
		return nil, err
	}
	header, err1 := hex.DecodeString(gw.Header)
	seed, err2 := hex.DecodeString(gw.Seed)
	netT, ok := new(big.Int).SetString(gw.Target, 16)
	if err1 != nil || err2 != nil || !ok || len(header) != core.HeaderLen {
		return nil, errors.New("bad template from node")
	}
	shareT := new(big.Int).Lsh(netT, shareShift)
	if shareT.Cmp(core.MaxTarget) > 0 {
		shareT = new(big.Int).Set(core.MaxTarget)
	}
	if curWork == nil || curWork.nodeID != gw.ID {
		curWork = &work{nodeID: gw.ID, header: header, seed: seed, height: gw.Height,
			netTarget: netT, shareTarget: shareT, seen: map[uint64]bool{}}
	}
	lastFetch = time.Now()
	return curWork, nil
}

func hashFor(w *work, nonce uint64) [32]byte {
	hdr := make([]byte, len(w.header))
	copy(hdr, w.header)
	for i := 0; i < 8; i++ {
		hdr[core.NonceOffset+i] = byte(nonce >> (8 * i))
	}
	epoch := w.height / core.EpochLength
	vmMu.Lock()
	if vm == nil || epoch != vmEpoch {
		vm = nm.NewVM(nm.DeriveParams(w.seed))
		vmEpoch = epoch
	}
	h := vm.Hash(hdr, w.height)
	vmMu.Unlock()
	return h
}

// ------------------------------------------------------------------- handlers

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func getworkHandler(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Query().Get("addr")
	if !core.ValidAddr(addr) {
		writeJSON(w, 400, map[string]string{"error": "bad or missing addr"})
		return
	}
	wk, err := refreshWork()
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "pool backend unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"id":     wk.nodeID + "|" + addr,
		"header": hex.EncodeToString(wk.header),
		"target": core.TargetToHex(wk.shareTarget),
		"seed":   hex.EncodeToString(wk.seed),
		"height": wk.height,
	})
}

func submitworkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var req struct {
		ID    string `json:"id"`
		Nonce uint64 `json:"nonce"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	i := strings.LastIndex(req.ID, "|")
	if i < 0 {
		writeJSON(w, 400, map[string]string{"error": "bad work id"})
		return
	}
	nodeID, miner := req.ID[:i], req.ID[i+1:]
	if !core.ValidAddr(miner) {
		writeJSON(w, 400, map[string]string{"error": "bad miner addr"})
		return
	}
	workMu.Lock()
	wk := curWork
	stale := wk == nil || wk.nodeID != nodeID
	workMu.Unlock()
	if stale {
		writeJSON(w, 200, map[string]string{"result": "stale"})
		return
	}
	// dedup
	workMu.Lock()
	if wk.seen[req.Nonce] {
		workMu.Unlock()
		writeJSON(w, 200, map[string]string{"result": "duplicate"})
		return
	}
	wk.seen[req.Nonce] = true
	workMu.Unlock()

	h := hashFor(wk, req.Nonce)
	if !core.HashMeetsTarget(h, wk.shareTarget) {
		writeJSON(w, 400, map[string]string{"error": "low difficulty share"})
		return
	}
	// valid share
	st.mu.Lock()
	st.Shares[miner]++
	st.RoundShares++
	st.mu.Unlock()

	block := core.HashMeetsTarget(h, wk.netTarget)
	if block {
		// forward the real block to the node
		body, _ := json.Marshal(map[string]any{"id": nodeID, "nonce": req.Nonce})
		resp, err := http.Post(nodeAPI+"/submitwork", "application/json", strings.NewReader(string(body)))
		if err == nil {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var rr struct{ Result, Error string }
			_ = json.Unmarshal(raw, &rr)
			if rr.Result == "accepted" {
				onBlockFound(wk.height)
				log.Printf("pool: BLOCK %d found via miner %s", wk.height, miner[:12])
			} else {
				log.Printf("pool: block forward not accepted: %s", rr.Error)
			}
		}
	}
	writeJSON(w, 200, map[string]any{"result": "share", "block": block})
}

// onBlockFound splits this block's reward (minus fee) across the round's shares.
func onBlockFound(height uint64) {
	reward := core.BlockSubsidy(height)
	pot := reward - reward*feePermil/1000
	st.mu.Lock()
	total := st.RoundShares
	if total > 0 {
		for m, s := range st.Shares {
			st.Owed[m] += uint64(float64(pot) * (s / total))
		}
	}
	st.Shares = map[string]float64{}
	st.RoundShares = 0
	st.Found++
	st.mu.Unlock()
	st.save()
}

// ------------------------------------------------------------------ payouts

func payoutLoop() {
	for {
		time.Sleep(60 * time.Second)
		st.mu.Lock()
		var due []string
		for m, owed := range st.Owed {
			if owed >= minPayout {
				due = append(due, m)
			}
		}
		st.mu.Unlock()
		for _, m := range due {
			st.mu.Lock()
			amt := st.Owed[m]
			st.mu.Unlock()
			txid, err := send(m, amt)
			if err != nil {
				log.Printf("pool: payout to %s failed: %v", m[:12], err)
				continue
			}
			st.mu.Lock()
			st.Owed[m] = 0
			st.Paid[m] += amt
			st.mu.Unlock()
			st.save()
			log.Printf("pool: paid %s -> %s (%s)", crb(amt), m[:12], txid[:12])
		}
	}
}

var sendMu sync.Mutex
var nextNonce uint64 // local nonce counter (covers pending mempool txs)

func send(to string, amount uint64) (string, error) {
	sendMu.Lock()
	defer sendMu.Unlock()
	var status struct {
		Height uint64 `json:"height"`
		Fee    uint64 `json:"fee_suggested"`
	}
	if err := nodeGet("/status", &status); err != nil {
		return "", err
	}
	var acc struct {
		Balance uint64 `json:"balance"`
		Nonce   uint64 `json:"nonce"`
	}
	if err := nodeGet("/balance?addr="+poolAddr, &acc); err != nil {
		return "", err
	}
	fee := status.Fee
	if fee == 0 {
		fee = 1000
	}
	if amount <= fee {
		return "", errors.New("amount below fee")
	}
	netAmt := amount - fee // miner covers the tx fee out of their payout
	if acc.Balance < netAmt+fee {
		return "", errors.New("pool wallet has no spendable balance yet")
	}
	nonce := acc.Nonce
	if nextNonce > nonce {
		nonce = nextNonce
	}
	tx := &core.Tx{To: to, Amount: netAmt, Fee: fee, Nonce: nonce}
	core.SignTxAt(tx, priv, status.Height+1)
	body, _ := json.Marshal(tx)
	resp, err := http.Post(nodeAPI+"/tx", "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var rr struct{ TxID, Error string }
	_ = json.Unmarshal(raw, &rr)
	if rr.Error != "" {
		if strings.Contains(rr.Error, "nonce") {
			nextNonce = 0
		}
		return "", errors.New(rr.Error)
	}
	nextNonce = nonce + 1
	return rr.TxID, nil
}

func crb(v uint64) string { return strconv.FormatFloat(float64(v)/float64(core.CoinUnit), 'f', -1, 64) + " CRB" }

// --------------------------------------------------------------------- stats

func statsHandler(w http.ResponseWriter, r *http.Request) {
	st.mu.Lock()
	miners := map[string]any{}
	for m := range st.Shares {
		miners[m] = map[string]any{"shares": st.Shares[m], "owed": st.Owed[m], "paid": st.Paid[m]}
	}
	for m := range st.Owed {
		if _, ok := miners[m]; !ok {
			miners[m] = map[string]any{"shares": 0.0, "owed": st.Owed[m], "paid": st.Paid[m]}
		}
	}
	out := map[string]any{
		"pool_address":  poolAddr,
		"fee_permil":    feePermil,
		"blocks_found":  st.Found,
		"round_shares":  st.RoundShares,
		"min_payout":    minPayout,
		"active_miners": len(st.Shares),
		"miners":        miners,
	}
	st.mu.Unlock()
	writeJSON(w, 200, out)
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18754", "listen address")
	flag.StringVar(&nodeAPI, "node", "http://127.0.0.1:18751/api", "node API base")
	keyfile := flag.String("keyfile", "/opt/cerebra/faucet-wallet.txt", "pool wallet file with PRIVATE KEY line")
	fee := flag.Float64("fee", 1.0, "pool fee percent")
	shift := flag.Uint("shareshift", 8, "share target = netTarget << shift (bigger = easier shares)")
	minp := flag.Float64("minpayout", 0.05, "minimum CRB before a payout is sent")
	flag.StringVar(&statePath, "state", "/var/lib/cerebra/pool.json", "state file")
	flag.Parse()

	feePermil = uint64(*fee * 10)
	shareShift = *shift
	minPayout = uint64(*minp * float64(core.CoinUnit))

	raw, err := os.ReadFile(*keyfile)
	if err != nil {
		log.Fatalf("read keyfile: %v", err)
	}
	var skHex string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "PRIVATE KEY") {
			f := strings.Fields(line)
			skHex = f[len(f)-1]
		}
	}
	sk, err := hex.DecodeString(strings.TrimSpace(skHex))
	if err != nil || len(sk) != ed25519.PrivateKeySize {
		log.Fatalf("bad private key in keyfile")
	}
	priv = ed25519.PrivateKey(sk)
	poolAddr = core.AddrFromPub(priv.Public().(ed25519.PublicKey))
	st.load()
	log.Printf("pool: addr %s fee %.1f%% shareshift %d minpayout %s listen %s",
		poolAddr, *fee, shareShift, crb(minPayout), *listen)

	go payoutLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/getwork", getworkHandler)
	mux.HandleFunc("/api/submitwork", submitworkHandler)
	mux.HandleFunc("/api/poolstats", statsHandler)
	log.Fatal(http.ListenAndServe(*listen, mux))
}
