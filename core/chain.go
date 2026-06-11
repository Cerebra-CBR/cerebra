package core

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	nm "cereblix/neuromorph"
)

type Account struct {
	Balance uint64 `json:"balance"`
	Nonce   uint64 `json:"nonce"`
}

type State map[string]*Account

func (s State) get(addr string) *Account {
	a := s[addr]
	if a == nil {
		a = &Account{}
		s[addr] = a
	}
	return a
}

// Chain is the consensus engine: main chain, account state and mempool.
type Chain struct {
	mu      sync.RWMutex
	dir     string
	blocks  []*Block
	state   State
	cumWork *big.Int

	mempool     map[string]*Tx
	verifiedPow map[string]bool

	paramsCache map[uint64]*nm.Params // epoch -> params
	vmCache     map[uint64]*nm.VM     // epoch -> validation VM

	// 51%-resistance knobs (decentralized, no trusted party).
	// MaxReorgDepth rejects any reorg that would replace more than this many
	// of our own blocks; 0 disables the cap. ReorgPenaltyPermille makes deep
	// reorgs cost disproportionately more work: a candidate must exceed our
	// work by (depth * permille / 1000); 0 disables the penalty.
	MaxReorgDepth        uint64
	ReorgPenaltyPermille uint64

	// Checkpoints is an OPTIONAL, off-by-default break-glass against deep
	// attacks: height -> block hash. Empty = fully decentralized. When set,
	// the chain refuses any history that conflicts with a checkpoint.
	Checkpoints map[uint64]string

	OnNewBlock func(b *Block) // called outside lock after a block is adopted
}

func NewChain(dir string) (*Chain, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	c := &Chain{
		dir:         dir,
		state:       State{},
		cumWork:     new(big.Int),
		mempool:     map[string]*Tx{},
		verifiedPow: map[string]bool{},
		paramsCache: map[uint64]*nm.Params{},
		vmCache:     map[uint64]*nm.VM{},
		// Sane defaults: cap deep rewrites at 100 blocks (~1h40m at 60s),
		// no work penalty, no checkpoints. All overridable by the node.
		MaxReorgDepth:        100,
		ReorgPenaltyPermille: 0,
		Checkpoints:          map[uint64]string{},
	}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

// ------------------------------------------------------------- persistence

func (c *Chain) blocksFile() string { return filepath.Join(c.dir, "blocks.jsonl") }

func (c *Chain) load() error {
	f, err := os.Open(c.blocksFile())
	if errors.Is(err, os.ErrNotExist) {
		g := GenesisBlock()
		c.blocks = []*Block{g}
		c.verifiedPow[g.Hash()] = true
		c.rebuildDerived()
		return c.saveAll()
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var b Block
		if err := json.Unmarshal(sc.Bytes(), &b); err != nil {
			return fmt.Errorf("corrupt block store: %w", err)
		}
		c.blocks = append(c.blocks, &b)
		c.verifiedPow[b.Hash()] = true // trusted: we validated before writing
	}
	if len(c.blocks) == 0 {
		g := GenesisBlock()
		c.blocks = []*Block{g}
		c.verifiedPow[g.Hash()] = true
	}
	if c.blocks[0].Hash() != GenesisBlock().Hash() {
		return errors.New("block store has wrong genesis")
	}
	c.rebuildDerived()
	return nil
}

func (c *Chain) saveAll() error {
	tmp := c.blocksFile() + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, b := range c.blocks {
		raw, _ := json.Marshal(b)
		w.Write(raw)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, c.blocksFile())
}

func (c *Chain) appendToDisk(b *Block) error {
	f, err := os.OpenFile(c.blocksFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, _ := json.Marshal(b)
	raw = append(raw, '\n')
	_, err = f.Write(raw)
	return err
}

// rebuildDerived recomputes state and cumulative work from c.blocks.
func (c *Chain) rebuildDerived() {
	st := State{}
	work := new(big.Int)
	for _, b := range c.blocks {
		applyBlockToState(st, b)
		t, _ := b.TargetInt()
		work.Add(work, WorkOf(t))
	}
	c.state = st
	c.cumWork = work
}

// ------------------------------------------------------------ state rules

// validateTxAgainstState checks a non-coinbase tx against a state snapshot.
func validateTxAgainstState(st State, t *Tx) error {
	if err := t.CheckSig(); err != nil {
		return err
	}
	from, _ := t.FromAddr()
	acc := st.get(from)
	if t.Nonce != acc.Nonce {
		return fmt.Errorf("bad nonce: want %d got %d", acc.Nonce, t.Nonce)
	}
	total := t.Amount + t.Fee
	if total < t.Amount { // overflow
		return errors.New("amount overflow")
	}
	if acc.Balance < total {
		return errors.New("insufficient balance")
	}
	return nil
}

func applyBlockToState(st State, b *Block) {
	for _, t := range b.Txs {
		if t.IsCoinbase() {
			st.get(t.To).Balance += t.Amount
			continue
		}
		from, _ := t.FromAddr()
		acc := st.get(from)
		acc.Balance -= t.Amount + t.Fee
		acc.Nonce++
		st.get(t.To).Balance += t.Amount
	}
}

// ---------------------------------------------------------------- targets

// expectedTarget computes the required target for the block at height
// len(blocks), given the current chain prefix.
func expectedTarget(blocks []*Block) *big.Int {
	h := len(blocks)
	if h < 2 {
		return new(big.Int).Set(GenesisTarget)
	}
	window := RetargetWindow
	if h-1 < window {
		window = h - 1
	}
	first := blocks[h-1-window]
	last := blocks[h-1]
	expected := int64(window * BlockTargetSpacing)
	actual := int64(last.Time) - int64(first.Time)
	if actual < expected/4 {
		actual = expected / 4
	}
	if actual > expected*4 {
		actual = expected * 4
	}
	sum := new(big.Int)
	for i := h - window; i < h; i++ {
		t, _ := blocks[i].TargetInt()
		sum.Add(sum, t)
	}
	avg := sum.Div(sum, big.NewInt(int64(window)))
	next := avg.Mul(avg, big.NewInt(actual))
	next.Div(next, big.NewInt(expected))
	if next.Cmp(MaxTarget) > 0 {
		next.Set(MaxTarget)
	}
	if next.Sign() <= 0 {
		next.SetInt64(1)
	}
	return next
}

func medianTime(blocks []*Block) uint64 {
	n := 11
	if len(blocks) < n {
		n = len(blocks)
	}
	times := make([]uint64, 0, n)
	for _, b := range blocks[len(blocks)-n:] {
		times = append(times, b.Time)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	return times[len(times)/2]
}

// ----------------------------------------------------------------- epochs

// epochSeedFor returns the NeuroMorph seed for a block at `height`, taken
// from the supplied chain prefix (which must reach the epoch boundary).
func epochSeedFor(blocks []*Block, height uint64) ([]byte, uint64) {
	epoch := height / EpochLength
	if epoch == 0 {
		return nm.EpochSeed0(), 0
	}
	boundary := epoch*EpochLength - 1
	raw, _ := hex.DecodeString(blocks[boundary].Hash())
	return raw, epoch
}

func (c *Chain) vmFor(blocks []*Block, height uint64) *nm.VM {
	seed, epoch := epochSeedFor(blocks, height)
	if vm, ok := c.vmCache[epoch]; ok {
		return vm
	}
	p := nm.DeriveParams(seed)
	vm := nm.NewVM(p)
	c.paramsCache[epoch] = p
	c.vmCache[epoch] = vm
	if len(c.vmCache) > 3 { // keep only recent epochs
		for e := range c.vmCache {
			if e+2 < epoch {
				delete(c.vmCache, e)
				delete(c.paramsCache, e)
			}
		}
	}
	return vm
}

// EpochSeedForNext returns seed bytes + epoch for the next block (mining).
func (c *Chain) EpochSeedForNext() ([]byte, uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return epochSeedFor(c.blocks, uint64(len(c.blocks)))
}

// ------------------------------------------------------------- validation

// validateBlock fully validates b as the next block of `prefix`.
// st must be the state after applying `prefix`. PoW is skipped for hashes
// already in verifiedPow.
func (c *Chain) validateBlock(prefix []*Block, st State, b *Block) error {
	prev := prefix[len(prefix)-1]
	if b.Version != 1 {
		return errors.New("bad version")
	}
	if b.Height != uint64(len(prefix)) {
		return fmt.Errorf("bad height %d, want %d", b.Height, len(prefix))
	}
	if b.PrevHash != prev.Hash() {
		return errors.New("prev hash mismatch")
	}
	if b.Time <= medianTime(prefix) {
		return errors.New("timestamp too old")
	}
	if b.Time > uint64(time.Now().Unix()+MaxFutureDrift) {
		return errors.New("timestamp too far in future")
	}
	want := expectedTarget(prefix)
	got, err := b.TargetInt()
	if err != nil {
		return err
	}
	if want.Cmp(got) != 0 {
		return errors.New("wrong difficulty target")
	}
	if len(b.Txs) == 0 || len(b.Txs) > MaxBlockTxs {
		return errors.New("bad tx count")
	}
	if !b.Txs[0].IsCoinbase() {
		return errors.New("first tx must be coinbase")
	}
	if b.TxRoot != ComputeTxRoot(b.Txs) {
		return errors.New("tx root mismatch")
	}
	// Coinbase rules.
	cb := b.Txs[0]
	if cb.Nonce != b.Height {
		return errors.New("coinbase nonce must equal height")
	}
	if !ValidAddr(cb.To) {
		return errors.New("bad coinbase address")
	}
	if cb.Amount != BlockSubsidy(b.Height)+b.TotalFees() {
		return errors.New("bad coinbase amount")
	}
	// Body txs against a state copy.
	work := State{}
	for k, v := range st {
		cp := *v
		work[k] = &cp
	}
	seen := map[string]bool{}
	for _, t := range b.Txs[1:] {
		if t.IsCoinbase() {
			return errors.New("extra coinbase")
		}
		if seen[t.ID()] {
			return errors.New("duplicate tx in block")
		}
		seen[t.ID()] = true
		if err := validateTxAgainstState(work, t); err != nil {
			return fmt.Errorf("tx %s: %w", t.ID()[:16], err)
		}
		from, _ := t.FromAddr()
		acc := work.get(from)
		acc.Balance -= t.Amount + t.Fee
		acc.Nonce++
		work.get(t.To).Balance += t.Amount
	}
	// Proof of work.
	if !c.verifiedPow[b.Hash()] {
		vm := c.vmFor(prefix, b.Height)
		pow := vm.Hash(b.HeaderBytes(), b.Height)
		if !HashMeetsTarget(pow, got) {
			return errors.New("insufficient proof of work")
		}
		c.verifiedPow[b.Hash()] = true
	}
	return nil
}

// AddBlock validates and appends a block extending the current tip.
func (c *Chain) AddBlock(b *Block) error {
	c.mu.Lock()
	if b.PrevHash != c.blocks[len(c.blocks)-1].Hash() {
		c.mu.Unlock()
		return errors.New("not extending tip")
	}
	if err := c.validateBlock(c.blocks, c.state, b); err != nil {
		c.mu.Unlock()
		return err
	}
	c.blocks = append(c.blocks, b)
	applyBlockToState(c.state, b)
	t, _ := b.TargetInt()
	c.cumWork.Add(c.cumWork, WorkOf(t))
	for _, tx := range b.Txs {
		delete(c.mempool, tx.ID())
	}
	c.pruneMempoolLocked()
	err := c.appendToDisk(b)
	cb := c.OnNewBlock
	c.mu.Unlock()
	if cb != nil {
		cb(b)
	}
	return err
}

// TryAdoptChain attempts a reorg: candidate blocks start at startHeight and
// must connect to our chain there. Adopts only if cumulative work is higher.
func (c *Chain) TryAdoptChain(startHeight uint64, newBlocks []*Block) error {
	if len(newBlocks) == 0 {
		return errors.New("empty candidate")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if startHeight == 0 || startHeight > uint64(len(c.blocks)) {
		return errors.New("bad fork point")
	}

	// Decentralized 51% guard #1: reject reorgs that rewrite too much history.
	// depth = how many of our own blocks would be discarded.
	depth := uint64(len(c.blocks)) - startHeight
	if c.MaxReorgDepth > 0 && depth > c.MaxReorgDepth {
		return fmt.Errorf("reorg too deep: %d blocks (cap %d)", depth, c.MaxReorgDepth)
	}

	// Break-glass guard: never reorg below or across a configured checkpoint.
	if len(c.Checkpoints) > 0 {
		for h := range c.Checkpoints {
			if h >= startHeight {
				return fmt.Errorf("reorg conflicts with checkpoint at height %d", h)
			}
		}
	}

	candidate := make([]*Block, startHeight, startHeight+uint64(len(newBlocks)))
	copy(candidate, c.blocks[:startHeight])

	// Replay state up to the fork point.
	st := State{}
	work := new(big.Int)
	for _, b := range candidate {
		applyBlockToState(st, b)
		t, _ := b.TargetInt()
		work.Add(work, WorkOf(t))
	}
	for _, b := range newBlocks {
		if err := c.validateBlock(candidate, st, b); err != nil {
			return fmt.Errorf("candidate block %d: %w", b.Height, err)
		}
		candidate = append(candidate, b)
		applyBlockToState(st, b)
		t, _ := b.TargetInt()
		work.Add(work, WorkOf(t))
	}
	// Decentralized 51% guard #2: a candidate must always have more work, and
	// for deeper reorgs it must have *disproportionately* more (penalty), so a
	// brief 51% burst can't cheaply rewrite many confirmed blocks.
	threshold := new(big.Int).Set(c.cumWork)
	if c.ReorgPenaltyPermille > 0 && depth > 1 {
		extra := new(big.Int).Mul(c.cumWork, big.NewInt(int64(depth*c.ReorgPenaltyPermille)))
		extra.Div(extra, big.NewInt(1000))
		threshold.Add(threshold, extra)
	}
	if work.Cmp(threshold) <= 0 {
		return errors.New("candidate chain lacks sufficient work for its reorg depth")
	}
	c.blocks = candidate
	c.state = st
	c.cumWork = work
	c.vmCache = map[uint64]*nm.VM{}
	c.paramsCache = map[uint64]*nm.Params{}
	c.pruneMempoolLocked()
	return c.saveAll()
}

// ---------------------------------------------------------------- mempool

func (c *Chain) AddTx(t *Tx) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t.IsCoinbase() {
		return errors.New("coinbase not allowed in mempool")
	}
	if _, ok := c.mempool[t.ID()]; ok {
		return errors.New("already in mempool")
	}
	if len(c.mempool) > 10000 {
		return errors.New("mempool full")
	}
	if err := c.validateMempoolTxLocked(t); err != nil {
		return err
	}
	c.mempool[t.ID()] = t
	return nil
}

// validateMempoolTxLocked checks t against state plus queued txs from the
// same sender (allows nonce chains in the mempool).
func (c *Chain) validateMempoolTxLocked(t *Tx) error {
	if err := t.CheckSig(); err != nil {
		return err
	}
	from, _ := t.FromAddr()
	acc := c.state.get(from)
	nonce := acc.Nonce
	spent := uint64(0)
	for _, m := range c.sortedMempoolLocked() {
		mf, _ := m.FromAddr()
		if mf == from {
			if m.Nonce == nonce {
				nonce++
				spent += m.Amount + m.Fee
			}
		}
	}
	if t.Nonce != nonce {
		return fmt.Errorf("bad nonce: want %d got %d", nonce, t.Nonce)
	}
	if acc.Balance < spent+t.Amount+t.Fee {
		return errors.New("insufficient balance (incl. pending)")
	}
	return nil
}

func (c *Chain) sortedMempoolLocked() []*Tx {
	txs := make([]*Tx, 0, len(c.mempool))
	for _, t := range c.mempool {
		txs = append(txs, t)
	}
	sort.Slice(txs, func(i, j int) bool {
		if txs[i].Nonce != txs[j].Nonce {
			return txs[i].Nonce < txs[j].Nonce
		}
		if txs[i].Fee != txs[j].Fee {
			return txs[i].Fee > txs[j].Fee
		}
		return txs[i].ID() < txs[j].ID()
	})
	return txs
}

func (c *Chain) pruneMempoolLocked() {
	for id, t := range c.mempool {
		from, err := t.FromAddr()
		if err != nil {
			delete(c.mempool, id)
			continue
		}
		acc := c.state.get(from)
		if t.Nonce < acc.Nonce || acc.Balance < t.Amount+t.Fee {
			delete(c.mempool, id)
		}
	}
}

// --------------------------------------------------------------- building

// BuildTemplate assembles an unmined block paying to `coinbase`.
func (c *Chain) BuildTemplate(coinbase string) (*Block, error) {
	if !ValidAddr(coinbase) {
		return nil, errors.New("bad coinbase address")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	height := uint64(len(c.blocks))
	prev := c.blocks[len(c.blocks)-1]

	// Pick mempool txs greedily, respecting per-sender nonce order.
	st := State{}
	for k, v := range c.state {
		cp := *v
		st[k] = &cp
	}
	var picked []*Tx
	for _, t := range c.sortedMempoolLocked() {
		if len(picked) >= MaxBlockTxs-1 {
			break
		}
		if validateTxAgainstState(st, t) != nil {
			continue
		}
		from, _ := t.FromAddr()
		acc := st.get(from)
		acc.Balance -= t.Amount + t.Fee
		acc.Nonce++
		st.get(t.To).Balance += t.Amount
		picked = append(picked, t)
	}
	var fees uint64
	for _, t := range picked {
		fees += t.Fee
	}
	cb := &Tx{To: coinbase, Amount: BlockSubsidy(height) + fees, Nonce: height}
	txs := append([]*Tx{cb}, picked...)

	now := uint64(time.Now().Unix())
	if mt := medianTime(c.blocks); now <= mt {
		now = mt + 1
	}
	b := &Block{
		Version:  1,
		Height:   height,
		Time:     now,
		PrevHash: prev.Hash(),
		TxRoot:   ComputeTxRoot(txs),
		Target:   TargetToHex(expectedTarget(c.blocks)),
		Nonce:    0,
		Txs:      txs,
	}
	return b, nil
}

// ----------------------------------------------------------------- views

func (c *Chain) Height() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return uint64(len(c.blocks)) - 1
}

func (c *Chain) Tip() *Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blocks[len(c.blocks)-1]
}

func (c *Chain) CumWork() *big.Int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return new(big.Int).Set(c.cumWork)
}

func (c *Chain) BlockAt(h uint64) *Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if h >= uint64(len(c.blocks)) {
		return nil
	}
	return c.blocks[h]
}

func (c *Chain) Blocks(from uint64, count int) []*Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if from >= uint64(len(c.blocks)) {
		return nil
	}
	end := from + uint64(count)
	if end > uint64(len(c.blocks)) {
		end = uint64(len(c.blocks))
	}
	out := make([]*Block, end-from)
	copy(out, c.blocks[from:end])
	return out
}

func (c *Chain) Account(addr string) Account {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if a := c.state[addr]; a != nil {
		return *a
	}
	return Account{}
}

func (c *Chain) MempoolTxs() []*Tx {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sortedMempoolLocked()
}

func (c *Chain) Supply() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var s uint64
	for _, a := range c.state {
		s += a.Balance
	}
	return s
}

// HistoryItem is a wallet-facing view of a confirmed transaction.
type HistoryItem struct {
	TxID    string `json:"txid"`
	Height  uint64 `json:"height"`
	Time    uint64 `json:"time"`
	From    string `json:"from"` // "coinbase" for block rewards
	To      string `json:"to"`
	Amount  uint64 `json:"amount"`
	Fee     uint64 `json:"fee"`
}

func (c *Chain) History(addr string, limit int) []HistoryItem {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []HistoryItem
	for i := len(c.blocks) - 1; i >= 0 && len(out) < limit; i-- {
		b := c.blocks[i]
		for _, t := range b.Txs {
			from := "coinbase"
			if !t.IsCoinbase() {
				from, _ = t.FromAddr()
			}
			if from == addr || t.To == addr {
				out = append(out, HistoryItem{
					TxID: t.ID(), Height: b.Height, Time: b.Time,
					From: from, To: t.To, Amount: t.Amount, Fee: t.Fee,
				})
				if len(out) >= limit {
					break
				}
			}
		}
	}
	return out
}

// TxLocation is an explorer-facing view of a single transaction.
type TxLocation struct {
	Found     bool   `json:"found"`
	Pending   bool   `json:"pending"` // in mempool, not yet in a block
	TxID      string `json:"txid"`
	Height    uint64 `json:"height"`
	BlockHash string `json:"block_hash"`
	Time      uint64 `json:"time"`
	From      string `json:"from"` // "coinbase" for block rewards
	To        string `json:"to"`
	Amount    uint64 `json:"amount"`
	Fee       uint64 `json:"fee"`
	Nonce     uint64 `json:"nonce"`
	Coinbase  bool   `json:"coinbase"`
}

func txToLocation(t *Tx) TxLocation {
	from := "coinbase"
	if !t.IsCoinbase() {
		from, _ = t.FromAddr()
	}
	return TxLocation{
		Found: true, TxID: t.ID(), From: from, To: t.To,
		Amount: t.Amount, Fee: t.Fee, Nonce: t.Nonce, Coinbase: t.IsCoinbase(),
	}
}

// FindTx locates a transaction by id in the chain or mempool.
func (c *Chain) FindTx(id string) TxLocation {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.blocks) - 1; i >= 0; i-- {
		b := c.blocks[i]
		for _, t := range b.Txs {
			if t.ID() == id {
				loc := txToLocation(t)
				loc.Height = b.Height
				loc.BlockHash = b.Hash()
				loc.Time = b.Time
				return loc
			}
		}
	}
	if t, ok := c.mempool[id]; ok {
		loc := txToLocation(t)
		loc.Pending = true
		return loc
	}
	return TxLocation{Found: false, TxID: id}
}

// RichEntry is one row of the rich list.
type RichEntry struct {
	Address string `json:"address"`
	Balance uint64 `json:"balance"`
	Nonce   uint64 `json:"nonce"`
}

// RichList returns the top-n addresses by balance.
func (c *Chain) RichList(n int) []RichEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	list := make([]RichEntry, 0, len(c.state))
	for addr, a := range c.state {
		if a.Balance == 0 {
			continue
		}
		list = append(list, RichEntry{Address: addr, Balance: a.Balance, Nonce: a.Nonce})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Balance != list[j].Balance {
			return list[i].Balance > list[j].Balance
		}
		return list[i].Address < list[j].Address
	})
	if n > 0 && len(list) > n {
		list = list[:n]
	}
	return list
}

// BlockByHash returns a block by its id hash, or nil.
func (c *Chain) BlockByHash(hash string) *Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, b := range c.blocks {
		if b.Hash() == hash {
			return b
		}
	}
	return nil
}
