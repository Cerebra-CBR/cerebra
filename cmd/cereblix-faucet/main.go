// cereblix-faucet: a small CRB faucet. Gives a tiny amount once per 24h per
// address AND per IP, gated by a self-hosted proof-of-work captcha (no third
// party, no keys, on-theme for a CPU-mined coin). Listens on localhost and is
// meant to sit behind the Apache reverse proxy.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"cereblix/core"
)

const cooldown = 3 * time.Hour

var (
	nodeAPI                    string
	amtBase, amtMiner, amtWhale uint64
	priv                       ed25519.PrivateKey
	from                       string
	powBits                    uint
	sendMu                     sync.Mutex
	nextNonce                  uint64 // local nonce counter (covers pending mempool txs)
	store                      *limitStore
	chMu                       sync.Mutex
	challenges                 = map[string]int64{} // challenge -> expiry unix
)

// amountFor tiers the payout by how many blocks the address has mined:
// 0 blocks -> base, >=1 -> miner, >100 -> whale.
func amountFor(addr string) (uint64, int) {
	var r struct {
		Blocks int `json:"blocks"`
	}
	_ = nodeGet("/mined?addr="+addr, &r)
	switch {
	case r.Blocks > 100:
		return amtWhale, r.Blocks
	case r.Blocks >= 1:
		return amtMiner, r.Blocks
	default:
		return amtBase, r.Blocks
	}
}

// ----------------------------------------------------------- rate-limit store

type limitStore struct {
	mu   sync.Mutex
	path string
	Addr map[string]int64 `json:"addr"`
	IP   map[string]int64 `json:"ip"`
}

func loadStore(path string) *limitStore {
	s := &limitStore{path: path, Addr: map[string]int64{}, IP: map[string]int64{}}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, s)
	}
	return s
}

func (s *limitStore) save() {
	raw, _ := json.Marshal(s)
	_ = os.WriteFile(s.path, raw, 0o600)
}

// remaining returns the cooldown left for addr or ip (0 if allowed). Prunes old.
func (s *limitStore) remaining(addr, ip string, now int64) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := now - int64(cooldown.Seconds())
	for k, v := range s.Addr {
		if v < cut {
			delete(s.Addr, k)
		}
	}
	for k, v := range s.IP {
		if v < cut {
			delete(s.IP, k)
		}
	}
	var last int64
	if v, ok := s.Addr[addr]; ok && v > last {
		last = v
	}
	if v, ok := s.IP[ip]; ok && v > last {
		last = v
	}
	if last == 0 {
		return 0
	}
	left := time.Duration(last+int64(cooldown.Seconds())-now) * time.Second
	if left < 0 {
		return 0
	}
	return left
}

func (s *limitStore) record(addr, ip string, now int64) {
	s.mu.Lock()
	s.Addr[addr] = now
	s.IP[ip] = now
	s.mu.Unlock()
	s.save()
}

// --------------------------------------------------------------- pow captcha

func leadingZeroBits(h []byte) uint {
	var n uint
	for _, b := range h {
		if b == 0 {
			n += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) == 0 {
				n++
			} else {
				return n
			}
		}
	}
	return n
}

func newChallenge() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	c := hex.EncodeToString(b)
	now := time.Now().Unix()
	chMu.Lock()
	// prune expired + bound memory
	if len(challenges) > 5000 {
		challenges = map[string]int64{}
	}
	for k, exp := range challenges {
		if exp < now {
			delete(challenges, k)
		}
	}
	challenges[c] = now + 300 // valid 5 min
	chMu.Unlock()
	return c
}

// consumeChallenge verifies the challenge is live and the PoW solves it, then
// burns it (one-time use).
func consumeChallenge(c, nonce string) error {
	now := time.Now().Unix()
	chMu.Lock()
	exp, ok := challenges[c]
	if ok {
		delete(challenges, c)
	}
	chMu.Unlock()
	if !ok || exp < now {
		return errors.New("captcha expired - refresh and try again")
	}
	h := sha256.Sum256([]byte(c + ":" + nonce))
	if leadingZeroBits(h[:]) < powBits {
		return errors.New("captcha not solved")
	}
	return nil
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

func sendCRB(to string, amount uint64) (string, error) {
	sendMu.Lock()
	defer sendMu.Unlock()
	var st struct {
		Height uint64 `json:"height"`
		Fee    uint64 `json:"fee_suggested"`
	}
	if err := nodeGet("/status", &st); err != nil {
		return "", fmt.Errorf("node unreachable")
	}
	var acc struct {
		Balance uint64 `json:"balance"`
		Nonce   uint64 `json:"nonce"`
	}
	if err := nodeGet("/balance?addr="+from, &acc); err != nil {
		return "", fmt.Errorf("node unreachable")
	}
	fee := st.Fee
	if fee == 0 {
		fee = 1000
	}
	if acc.Balance < amount+fee {
		return "", fmt.Errorf("faucet is empty right now, try later")
	}
	// Use the higher of the confirmed nonce and our local counter so back-to-back
	// sends don't reuse a nonce that's still pending in the mempool.
	nonce := acc.Nonce
	if nextNonce > nonce {
		nonce = nextNonce
	}
	tx := &core.Tx{To: to, Amount: amount, Fee: fee, Nonce: nonce}
	core.SignTxAt(tx, priv, st.Height+1)
	body, _ := json.Marshal(tx)
	resp, err := http.Post(nodeAPI+"/tx", "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("node unreachable")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var r struct {
		TxID  string `json:"txid"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &r)
	if r.Error != "" {
		// On a nonce mismatch, resync to the chain's confirmed nonce next time.
		if strings.Contains(r.Error, "nonce") {
			nextNonce = 0
		}
		return "", fmt.Errorf("rejected: %s", r.Error)
	}
	nextNonce = nonce + 1
	return r.TxID, nil
}

// ------------------------------------------------------------------- handlers

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Use the LAST hop - the entry our own Apache appended is the real client.
		// The earlier entries are client-supplied and spoofable (would let an
		// attacker dodge the per-IP limit).
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18753", "listen address")
	flag.StringVar(&nodeAPI, "node", "http://127.0.0.1:18751/api", "node API base")
	keyfile := flag.String("keyfile", "/opt/cerebra/NETWORK_WALLET.txt", "wallet file with PRIVATE KEY line")
	base := flag.Float64("base", 0.001, "CRB for addresses that mined 0 blocks")
	miner := flag.Float64("miner", 0.01, "CRB for addresses that mined >=1 block")
	whale := flag.Float64("whale", 0.1, "CRB for addresses that mined >100 blocks")
	bits := flag.Uint("bits", 18, "PoW captcha difficulty (leading zero bits)")
	datadir := flag.String("datadir", "/var/lib/cerebra", "where to store rate-limit state")
	flag.Parse()

	amtBase = uint64(*base * float64(core.CoinUnit))
	amtMiner = uint64(*miner * float64(core.CoinUnit))
	amtWhale = uint64(*whale * float64(core.CoinUnit))
	powBits = *bits

	// Load the spending key (PRIVATE KEY line, 64-byte ed25519 hex).
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
		log.Fatalf("bad private key in keyfile (need %d-byte hex)", ed25519.PrivateKeySize)
	}
	priv = ed25519.PrivateKey(sk)
	from = core.AddrFromPub(priv.Public().(ed25519.PublicKey))
	store = loadStore(*datadir + "/faucet.json")
	log.Printf("faucet: from %s tiers base/miner/whale=%d/%d/%d synapses, 3h cooldown, pow=%d bits, listen %s",
		from, amtBase, amtMiner, amtWhale, powBits, *listen)

	mux := http.NewServeMux()
	mux.HandleFunc("/faucet/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"from": from, "bits": powBits, "cooldown_h": 3,
			"base": amtBase, "miner": amtMiner, "whale": amtWhale})
	})
	mux.HandleFunc("/faucet/challenge", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"challenge": newChallenge(), "bits": powBits})
	})
	mux.HandleFunc("/faucet/claim", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeJSON(w, 405, map[string]string{"error": "POST only"})
			return
		}
		var req struct {
			Addr      string `json:"addr"`
			Challenge string `json:"challenge"`
			Nonce     string `json:"nonce"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		req.Addr = strings.TrimSpace(req.Addr)
		if !core.ValidAddr(req.Addr) {
			writeJSON(w, 400, map[string]string{"error": "enter a valid crb1 address"})
			return
		}
		if err := consumeChallenge(req.Challenge, req.Nonce); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		ip := clientIP(r)
		now := time.Now().Unix()
		if left := store.remaining(req.Addr, ip, now); left > 0 {
			h := int(left.Hours())
			m := int(left.Minutes()) % 60
			writeJSON(w, 429, map[string]string{"error": fmt.Sprintf("already claimed - try again in %dh %dm", h, m)})
			return
		}
		amt, mined := amountFor(req.Addr)
		txid, err := sendCRB(req.Addr, amt)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		store.record(req.Addr, ip, now)
		writeJSON(w, 200, map[string]any{"result": "sent", "txid": txid,
			"amount": float64(amt) / float64(core.CoinUnit), "mined": mined})
	})

	log.Fatal(http.ListenAndServe(*listen, mux))
}
