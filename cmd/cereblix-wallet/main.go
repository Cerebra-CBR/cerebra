// cereblix-wallet is the standalone Cereblix wallet: a local key store plus a
// thin RPC client and block explorer. Like bitcoin-cli it needs a node to talk
// to (the public seed by default, or your own with -node), but the keys live
// only on your machine - it does not depend on the website.
//
// Run with no command for an interactive shell, or pass a one-shot command for
// scripting:
//
//	cereblix-wallet                      # interactive shell
//	cereblix-wallet new main             # create address labelled "main"
//	cereblix-wallet list                 # addresses + balances
//	cereblix-wallet send crb1... 12.5    # sign locally and broadcast
//	cereblix-wallet tx <txid>            # explorer: look up a transaction
//	cereblix-wallet block 42             # explorer: show a block
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cereblix/core"
)

const kdfIters = 200_000

var (
	nodeURL    string
	walletPath string
	store      *Store
	in         = bufio.NewReader(os.Stdin)
)

// ------------------------------------------------------------- wallet store

type KeyEntry struct {
	Label string `json:"label"`
	Priv  string `json:"priv"` // 128-hex ed25519 private key
	Addr  string `json:"addr"`
}

// fileFormat is what lands on disk. When Encrypted, Keys is empty and the key
// array lives AES-GCM-encrypted in Cipher.
type fileFormat struct {
	Version   int        `json:"version"`
	Encrypted bool       `json:"encrypted"`
	KDF       string     `json:"kdf,omitempty"`
	Iter      int        `json:"iter,omitempty"`
	Salt      string     `json:"salt,omitempty"`
	Nonce     string     `json:"nonce,omitempty"`
	Cipher    string     `json:"cipher,omitempty"`
	Keys      []KeyEntry `json:"keys,omitempty"`
}

type Store struct {
	path       string
	keys       []KeyEntry
	encrypted  bool
	passphrase []byte // cached for the session once unlocked
}

func defaultWalletPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	return filepath.Join(home, ".cereblix", "wallet.json")
}

func loadStore(path string) (*Store, error) {
	s := &Store{path: path}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil // empty wallet, not yet saved
	}
	if err != nil {
		return nil, err
	}
	var ff fileFormat
	if err := json.Unmarshal(raw, &ff); err != nil {
		return nil, fmt.Errorf("corrupt wallet file: %w", err)
	}
	s.encrypted = ff.Encrypted
	if !ff.Encrypted {
		s.keys = ff.Keys
		return s, nil
	}
	// Encrypted: prompt for passphrase and decrypt.
	pass := getPassphrase("Wallet passphrase: ")
	keys, err := decryptKeys(&ff, pass)
	if err != nil {
		return nil, err
	}
	s.keys = keys
	s.passphrase = pass
	return s, nil
}

func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	var ff fileFormat
	ff.Version = 1
	if s.encrypted {
		salt := make([]byte, 16)
		nonce := make([]byte, 12)
		rand.Read(salt)
		rand.Read(nonce)
		plain, _ := json.Marshal(s.keys)
		key := pbkdf2(s.passphrase, salt, kdfIters, 32)
		blk, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(blk)
		ct := gcm.Seal(nil, nonce, plain, nil)
		ff.Encrypted = true
		ff.KDF = "pbkdf2-sha256"
		ff.Iter = kdfIters
		ff.Salt = hex.EncodeToString(salt)
		ff.Nonce = hex.EncodeToString(nonce)
		ff.Cipher = hex.EncodeToString(ct)
	} else {
		ff.Keys = s.keys
	}
	raw, _ := json.MarshalIndent(&ff, "", "  ")
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func decryptKeys(ff *fileFormat, pass []byte) ([]KeyEntry, error) {
	salt, _ := hex.DecodeString(ff.Salt)
	nonce, _ := hex.DecodeString(ff.Nonce)
	ct, _ := hex.DecodeString(ff.Cipher)
	iter := ff.Iter
	if iter == 0 {
		iter = kdfIters
	}
	key := pbkdf2(pass, salt, iter, 32)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(blk)
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("wrong passphrase or corrupt wallet")
	}
	var keys []KeyEntry
	if err := json.Unmarshal(plain, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func (s *Store) find(addrOrLabel string) *KeyEntry {
	for i := range s.keys {
		if s.keys[i].Addr == addrOrLabel || s.keys[i].Label == addrOrLabel {
			return &s.keys[i]
		}
	}
	return nil
}

func (s *Store) add(label string) (*KeyEntry, error) {
	if label == "" {
		label = fmt.Sprintf("addr-%d", len(s.keys)+1)
	}
	if s.find(label) != nil {
		return nil, fmt.Errorf("label %q already exists", label)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	e := KeyEntry{
		Label: label,
		Priv:  hex.EncodeToString(priv),
		Addr:  core.AddrFromPub(priv.Public().(ed25519.PublicKey)),
	}
	s.keys = append(s.keys, e)
	return &s.keys[len(s.keys)-1], s.save()
}

// ----------------------------------------------------------- crypto: PBKDF2

// pbkdf2 implements PBKDF2-HMAC-SHA256 (RFC 2898) using only the stdlib, so the
// wallet keeps the project's zero-dependency promise.
func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, numBlocks*hashLen)
	var blockIdx [4]byte
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(blockIdx[:], uint32(block))
		prf.Write(blockIdx[:])
		T := prf.Sum(nil)
		U := make([]byte, len(T))
		copy(U, T)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = prf.Sum(U[:0])
			for x := range T {
				T[x] ^= U[x]
			}
		}
		dk = append(dk, T...)
	}
	return dk[:keyLen]
}

// ------------------------------------------------------------ node RPC client

func apiGet(path string, out any) error {
	resp, err := http.Get(nodeURL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var probe map[string]json.RawMessage
	body, _ := io.ReadAll(resp.Body)
	if json.Unmarshal(body, &probe) == nil {
		if e, ok := probe["error"]; ok {
			var msg string
			json.Unmarshal(e, &msg)
			return errors.New(msg)
		}
	}
	return json.Unmarshal(body, out)
}

func apiPost(path string, body any, out any) error {
	raw, _ := json.Marshal(body)
	resp, err := http.Post(nodeURL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var generic map[string]json.RawMessage
	if json.Unmarshal(data, &generic) == nil {
		if e, ok := generic["error"]; ok {
			var msg string
			json.Unmarshal(e, &msg)
			return errors.New(msg)
		}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// -------------------------------------------------------------------- helpers

const unit = float64(core.CoinUnit)

func crb(v uint64) string { return fmt.Sprintf("%.8f CRB", float64(v)/unit) }

func toAmount(s string) (uint64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f < 0 {
		return 0, errors.New("bad amount")
	}
	return uint64(f*unit + 0.5), nil
}

func getPassphrase(prompt string) []byte {
	if env := os.Getenv("CEREBRA_PASSPHRASE"); env != "" {
		return []byte(env)
	}
	fmt.Print(prompt)
	line, _ := in.ReadString('\n')
	return []byte(strings.TrimRight(line, "\r\n"))
}

func ask(prompt string) string {
	fmt.Print(prompt)
	line, _ := in.ReadString('\n')
	return strings.TrimSpace(line)
}

// --------------------------------------------------------------------- main

func main() {
	flag.StringVar(&nodeURL, "node", "https://cereblix.com/api", "node RPC base URL")
	flag.StringVar(&walletPath, "wallet", "", "wallet file path (default ~/.cereblix/wallet.json)")
	flag.Parse()
	if walletPath == "" {
		walletPath = defaultWalletPath()
	}
	var err error
	store, err = loadStore(walletPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wallet error:", err)
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) == 0 {
		interactive()
		return
	}
	if err := dispatch(args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func interactive() {
	fmt.Println("Cereblix wallet - interactive shell. Type 'help' for commands, 'quit' to exit.")
	fmt.Printf("wallet: %s | node: %s | %d address(es)\n", walletPath, nodeURL, len(store.keys))
	if len(store.keys) == 0 {
		fmt.Println("No addresses yet. Run 'new' to create one.")
	}
	for {
		fmt.Print("cereblix> ")
		line, err := in.ReadString('\n')
		if err != nil {
			fmt.Println()
			return
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "quit" || fields[0] == "exit" {
			return
		}
		if err := dispatch(fields); err != nil {
			fmt.Println("error:", err)
		}
	}
}

func dispatch(args []string) error {
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help":
		printHelp()
	case "new":
		label := ""
		if len(rest) > 0 {
			label = rest[0]
		}
		e, err := store.add(label)
		if err != nil {
			return err
		}
		fmt.Printf("created %q\n  address: %s\n", e.Label, e.Addr)
	case "list", "addresses":
		return cmdList()
	case "balance":
		return cmdBalance(rest)
	case "receive":
		return cmdReceive()
	case "send":
		return cmdSend(rest)
	case "history":
		return cmdHistory(rest)
	case "import":
		return cmdImport(rest)
	case "export":
		return cmdExport(rest)
	case "encrypt":
		return cmdEncrypt()
	case "status":
		return cmdStatus()
	case "latest":
		return cmdLatest(rest)
	case "block":
		return cmdBlock(rest)
	case "tx":
		return cmdTx(rest)
	case "address":
		return cmdAddress(rest)
	case "richlist":
		return cmdRichlist(rest)
	case "mempool":
		return cmdMempool()
	case "search":
		return cmdSearch(rest)
	case "node":
		if len(rest) > 0 {
			nodeURL = strings.TrimRight(rest[0], "/")
		}
		fmt.Println("node:", nodeURL)
	default:
		return fmt.Errorf("unknown command %q (try 'help')", cmd)
	}
	return nil
}

func printHelp() {
	fmt.Print(`Wallet commands:
  new [label]              create a new address
  list                     list addresses with balances
  balance [addr|label]     total balance, or one address
  receive                  show an address to receive CRB
  send <to> <amount> [fee] [from]   sign locally and broadcast
  history [addr|label]     recent transactions
  import <privkey> [label] import an existing 128-hex private key
  export <addr|label>      reveal a private key
  encrypt                  passphrase-encrypt the wallet file

Explorer commands:
  status                   network status (height, hashrate, supply...)
  latest [n]               latest n blocks
  block <height|hash>      show a block and its transactions
  tx <txid>                look up a transaction (with confirmations)
  address <crb1...>        balance + totals + history of any address
  richlist [n]             top addresses by balance
  mempool                  unconfirmed transactions
  search <query>           classify height/hash/txid/address

  node [url]               show or switch the node URL
  help / quit
`)
}

// ------------------------------------------------------------- wallet cmds

func cmdList() error {
	if len(store.keys) == 0 {
		fmt.Println("(no addresses - run 'new')")
		return nil
	}
	var total uint64
	for _, k := range store.keys {
		var b struct {
			Balance uint64 `json:"balance"`
		}
		_ = apiGet("/balance?addr="+k.Addr, &b)
		total += b.Balance
		fmt.Printf("  %-14s %s  %s\n", k.Label, k.Addr, crb(b.Balance))
	}
	fmt.Printf("  %-14s %s\n", "TOTAL", crb(total))
	return nil
}

func cmdBalance(rest []string) error {
	if len(rest) > 0 {
		addr := resolveAddr(rest[0])
		var b struct {
			Balance uint64 `json:"balance"`
			Nonce   uint64 `json:"nonce"`
		}
		if err := apiGet("/balance?addr="+addr, &b); err != nil {
			return err
		}
		fmt.Printf("%s\n  balance: %s\n  nonce:   %d\n", addr, crb(b.Balance), b.Nonce)
		return nil
	}
	var total uint64
	for _, k := range store.keys {
		var b struct {
			Balance uint64 `json:"balance"`
		}
		_ = apiGet("/balance?addr="+k.Addr, &b)
		total += b.Balance
	}
	fmt.Println("total wallet balance:", crb(total))
	return nil
}

func cmdReceive() error {
	if len(store.keys) == 0 {
		e, err := store.add("main")
		if err != nil {
			return err
		}
		fmt.Println("created your first address:")
		fmt.Println("  ", e.Addr)
		return nil
	}
	fmt.Println("send CRB to any of your addresses:")
	for _, k := range store.keys {
		fmt.Printf("  %-14s %s\n", k.Label, k.Addr)
	}
	return nil
}

func cmdSend(rest []string) error {
	if len(rest) < 2 {
		return errors.New("usage: send <to> <amount> [fee] [from-addr|label]")
	}
	to := rest[0]
	if !core.ValidAddr(to) {
		return errors.New("bad destination address")
	}
	amount, err := toAmount(rest[1])
	if err != nil {
		return err
	}
	fee := suggestedFee() // cheap, self-adjusting default
	if len(rest) >= 3 {
		if fee, err = toAmount(rest[2]); err != nil {
			return err
		}
	}
	var from *KeyEntry
	if len(rest) >= 4 {
		from = store.find(rest[3])
		if from == nil {
			return fmt.Errorf("no such address/label %q in wallet", rest[3])
		}
	} else {
		from, err = pickFundedAddr(amount + fee)
		if err != nil {
			return err
		}
	}
	priv, _ := hex.DecodeString(from.Priv)
	var acc struct {
		Nonce uint64 `json:"nonce"`
	}
	if err := apiGet("/balance?addr="+from.Addr, &acc); err != nil {
		return err
	}
	tx := &core.Tx{To: to, Amount: amount, Fee: fee, Nonce: acc.Nonce}
	core.SignTxAt(tx, ed25519.PrivateKey(priv), nextBlockHeight())
	var out struct {
		TxID string `json:"txid"`
	}
	if err := apiPost("/tx", tx, &out); err != nil {
		return err
	}
	fmt.Printf("sent %s (fee %s) from %s\n  txid: %s\n",
		crb(amount), crb(fee), from.Label, out.TxID)
	return nil
}

func pickFundedAddr(need uint64) (*KeyEntry, error) {
	for i := range store.keys {
		var b struct {
			Balance uint64 `json:"balance"`
		}
		_ = apiGet("/balance?addr="+store.keys[i].Addr, &b)
		if b.Balance >= need {
			return &store.keys[i], nil
		}
	}
	return nil, errors.New("no single address has enough balance (specify one or top up)")
}

func cmdHistory(rest []string) error {
	addrs := []string{}
	if len(rest) > 0 {
		addrs = append(addrs, resolveAddr(rest[0]))
	} else {
		for _, k := range store.keys {
			addrs = append(addrs, k.Addr)
		}
	}
	if len(addrs) == 0 {
		return errors.New("no address")
	}
	for _, addr := range addrs {
		var hist []core.HistoryItem
		if err := apiGet("/history?addr="+addr+"&limit=20", &hist); err != nil {
			return err
		}
		if len(addrs) > 1 {
			fmt.Println(addr)
		}
		if len(hist) == 0 {
			fmt.Println("  (no transactions)")
			continue
		}
		for _, h := range hist {
			dir := "recv"
			peer := h.From
			if h.From == addr {
				dir, peer = "send", h.To
			}
			fmt.Printf("  #%-7d %s  %-4s %s  %s\n",
				h.Height, time.Unix(int64(h.Time), 0).Format("01-02 15:04"),
				dir, crb(h.Amount), peer)
		}
	}
	return nil
}

func cmdImport(rest []string) error {
	if len(rest) < 1 {
		return errors.New("usage: import <128-hex-privkey> [label]")
	}
	raw, err := hex.DecodeString(rest[0])
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return errors.New("private key must be 128 hex characters")
	}
	label := "imported"
	if len(rest) > 1 {
		label = rest[1]
	}
	if store.find(label) != nil {
		label = fmt.Sprintf("%s-%d", label, len(store.keys)+1)
	}
	priv := ed25519.PrivateKey(raw)
	addr := core.AddrFromPub(priv.Public().(ed25519.PublicKey))
	if store.find(addr) != nil {
		return errors.New("address already in wallet")
	}
	store.keys = append(store.keys, KeyEntry{Label: label, Priv: rest[0], Addr: addr})
	if err := store.save(); err != nil {
		return err
	}
	fmt.Printf("imported %q -> %s\n", label, addr)
	return nil
}

func cmdExport(rest []string) error {
	if len(rest) < 1 {
		return errors.New("usage: export <addr|label>")
	}
	e := store.find(rest[0])
	if e == nil {
		return errors.New("no such address/label in wallet")
	}
	if ask("Reveal private key? Make sure nobody sees the screen. [y/N]: ") != "y" {
		fmt.Println("cancelled")
		return nil
	}
	fmt.Printf("%s\n  address: %s\n  private: %s\n", e.Label, e.Addr, e.Priv)
	return nil
}

func cmdEncrypt() error {
	if store.encrypted {
		return errors.New("wallet is already encrypted")
	}
	if len(store.keys) == 0 {
		return errors.New("nothing to encrypt - create an address first")
	}
	p1 := getPassphrase("New passphrase: ")
	p2 := getPassphrase("Repeat passphrase: ")
	if string(p1) != string(p2) {
		return errors.New("passphrases do not match")
	}
	if len(p1) < 6 {
		return errors.New("passphrase too short (min 6)")
	}
	store.encrypted = true
	store.passphrase = p1
	if err := store.save(); err != nil {
		return err
	}
	fmt.Println("wallet encrypted. You'll need this passphrase to open it next time.")
	return nil
}

// resolveAddr maps a wallet label to its address, or passes through an address.
func resolveAddr(s string) string {
	if e := store.find(s); e != nil {
		return e.Addr
	}
	return s
}

// ------------------------------------------------------------- explorer cmds

func cmdStatus() error {
	var s map[string]any
	if err := apiGet("/status", &s); err != nil {
		return err
	}
	f := func(k string) float64 { v, _ := s[k].(float64); return v }
	fmt.Printf("height:    %.0f\n", f("height"))
	fmt.Printf("tip:       %v\n", s["tip"])
	fmt.Printf("epoch:     %.0f (NeuroMorph)\n", f("epoch"))
	fmt.Printf("hashrate:  %.0f H/s\n", f("hashrate"))
	fmt.Printf("supply:    %s\n", crb(uint64(f("supply"))))
	fmt.Printf("reward:    %s\n", crb(uint64(f("reward"))))
	fmt.Printf("mempool:   %.0f tx\n", f("mempool"))
	fmt.Printf("peers:     %.0f\n", f("peers"))
	return nil
}

func cmdLatest(rest []string) error {
	n := 10
	if len(rest) > 0 {
		if v, err := strconv.Atoi(rest[0]); err == nil && v > 0 {
			n = v
		}
	}
	var blocks []map[string]any
	if err := apiGet(fmt.Sprintf("/blocks?last=%d", n), &blocks); err != nil {
		return err
	}
	for _, b := range blocks {
		h, _ := b["height"].(float64)
		t, _ := b["time"].(float64)
		txs, _ := b["txs"].(float64)
		fmt.Printf("  #%-7.0f %s  %.0f tx  %v\n",
			h, time.Unix(int64(t), 0).Format("01-02 15:04:05"), txs, b["hash"])
	}
	return nil
}

func cmdBlock(rest []string) error {
	if len(rest) < 1 {
		return errors.New("usage: block <height|hash>")
	}
	q := "h=" + rest[0]
	if len(rest[0]) == 64 {
		q = "hash=" + rest[0]
	}
	var b core.Block
	if err := apiGet("/block?"+q, &b); err != nil {
		return err
	}
	var fees, out uint64
	for _, t := range b.Txs {
		out += t.Amount
		if !t.IsCoinbase() {
			fees += t.Fee
		}
	}
	fmt.Printf("block #%d\n", b.Height)
	fmt.Printf("  hash:   %s\n", b.Hash())
	fmt.Printf("  prev:   %s\n", b.PrevHash)
	fmt.Printf("  time:   %s\n", time.Unix(int64(b.Time), 0).Format("2006-01-02 15:04:05"))
	fmt.Printf("  target: %s\n", b.Target)
	fmt.Printf("  nonce:  %d\n", b.Nonce)
	fmt.Printf("  txs:    %d  (outputs %s, fees %s)\n", len(b.Txs), crb(out), crb(fees))
	for i, t := range b.Txs {
		from := "coinbase"
		if !t.IsCoinbase() {
			from, _ = t.FromAddr()
		}
		fmt.Printf("   [%d] %s -> %s  %s  (fee %s)\n", i, short(from), short(t.To), crb(t.Amount), crb(t.Fee))
	}
	return nil
}

func netHeight() uint64 {
	var s struct {
		Height uint64 `json:"height"`
	}
	_ = apiGet("/status", &s)
	return s.Height
}

// suggestedFee fetches the node's cheap, self-adjusting fee (in synapses).
func suggestedFee() uint64 {
	var s struct {
		Fee uint64 `json:"fee_suggested"`
	}
	if apiGet("/status", &s) == nil && s.Fee > 0 {
		return s.Fee
	}
	return 1000 // fallback floor (0.00001 CRB)
}

// nextBlockHeight returns the height of the block a new tx would be mined into
// (tip + 1). The signing payload is chosen from this height (ChainID binding
// activates at ChainIDHeight).
func nextBlockHeight() uint64 {
	var s struct {
		Height uint64 `json:"height"`
	}
	if apiGet("/status", &s) == nil {
		return s.Height + 1
	}
	return 0
}

func cmdTx(rest []string) error {
	if len(rest) < 1 {
		return errors.New("usage: tx <txid>")
	}
	var loc core.TxLocation
	if err := apiGet("/tx?id="+rest[0], &loc); err != nil {
		return err
	}
	fmt.Printf("tx %s\n", loc.TxID)
	if loc.Pending {
		fmt.Println("  status: PENDING (in mempool, 0 confirmations)")
	} else {
		conf := netHeight() - loc.Height + 1
		fmt.Printf("  status: confirmed in block #%d (%d confirmations)\n", loc.Height, conf)
		fmt.Printf("  block:  %s\n", loc.BlockHash)
		fmt.Printf("  time:   %s\n", time.Unix(int64(loc.Time), 0).Format("2006-01-02 15:04:05"))
	}
	if loc.Coinbase {
		fmt.Printf("  from:   coinbase (block reward)\n")
	} else {
		fmt.Printf("  from:   %s\n", loc.From)
	}
	fmt.Printf("  to:     %s\n", loc.To)
	fmt.Printf("  amount: %s\n", crb(loc.Amount))
	fmt.Printf("  fee:    %s\n", crb(loc.Fee))
	fmt.Printf("  nonce:  %d\n", loc.Nonce)
	return nil
}

func cmdMempool() error {
	var txs []core.Tx
	if err := apiGet("/mempool", &txs); err != nil {
		return err
	}
	if len(txs) == 0 {
		fmt.Println("mempool is empty - all transactions confirmed")
		return nil
	}
	fmt.Printf("%d unconfirmed transaction(s):\n", len(txs))
	for _, t := range txs {
		from, _ := t.FromAddr()
		fmt.Printf("  %s  %s -> %s  %s (fee %s)\n",
			short(t.ID()), short(from), short(t.To), crb(t.Amount), crb(t.Fee))
	}
	return nil
}

func cmdAddress(rest []string) error {
	if len(rest) < 1 {
		return errors.New("usage: address <crb1...>")
	}
	addr := resolveAddr(rest[0])
	if !core.ValidAddr(addr) {
		return errors.New("bad address")
	}
	var b struct {
		Balance uint64 `json:"balance"`
		Nonce   uint64 `json:"nonce"`
	}
	if err := apiGet("/balance?addr="+addr, &b); err != nil {
		return err
	}
	fmt.Printf("%s\n  balance: %s\n  nonce:   %d\n", addr, crb(b.Balance), b.Nonce)
	return cmdHistory([]string{addr})
}

func cmdRichlist(rest []string) error {
	n := 25
	if len(rest) > 0 {
		if v, err := strconv.Atoi(rest[0]); err == nil && v > 0 {
			n = v
		}
	}
	var list []core.RichEntry
	if err := apiGet(fmt.Sprintf("/richlist?n=%d", n), &list); err != nil {
		return err
	}
	mine := map[string]bool{}
	for _, k := range store.keys {
		mine[k.Addr] = true
	}
	for i, e := range list {
		tag := ""
		if mine[e.Address] {
			tag = "  <- you"
		}
		fmt.Printf("  %2d. %s  %s%s\n", i+1, e.Address, crb(e.Balance), tag)
	}
	return nil
}

func cmdSearch(rest []string) error {
	if len(rest) < 1 {
		return errors.New("usage: search <height|hash|txid|address>")
	}
	var res map[string]any
	if err := apiGet("/search?q="+rest[0], &res); err != nil {
		return err
	}
	switch res["type"] {
	case "address":
		return cmdAddress([]string{fmt.Sprint(res["value"])})
	case "tx":
		return cmdTx([]string{fmt.Sprint(res["value"])})
	case "block":
		return cmdBlock([]string{fmt.Sprintf("%.0f", res["height"].(float64))})
	}
	fmt.Printf("%v\n", res)
	return nil
}

func short(addr string) string {
	if len(addr) <= 16 {
		return addr
	}
	return addr[:12] + "…"
}
