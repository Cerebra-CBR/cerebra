# Cereblix (CRB) - Architecture

> Complete technical specification of Cereblix: the NeuroMorph proof-of-work,
> the blockchain core, the node, miner and wallets.
>
> Document version: 3.0 - Network launched 2026-06-11 - Code license: MIT.
> A free, open-source project. No premine, no fund, no fundraising.
>
> v3 adds: mining pool, free faucet with a proof-of-useful-work captcha,
> coinbase maturity, a height-activated minimum fee, chain-id replay protection,
> and authority checkpoints for the bootstrap phase.

---

## 1. Overview & philosophy

Cereblix is a Proof-of-Work cryptocurrency written from scratch in Go (standard
library only, zero external dependencies). The core idea: **mining is possible
only on a general-purpose CPU**, with lifelong ASIC resistance and GPU
unprofitability.

The name encodes the design: **Cereb** (from *cerebrum*, the brain - your
processor does the thinking) + **lix** (from *helix*, the DNA spiral - the
algorithm rewrites its own "DNA" every epoch). The ticker reads out of it:
**C**e**R**e**B**lix.

Resistance rests on **two independent levers**:

1. **Computational diversity (the self-mutating VM).** Each nonce runs a unique
   random program on a virtual machine that mirrors a CPU (integer, float, AES,
   data-dependent branches). Optimal hardware for that workload converges to a
   processor. On top of it, the VM's *semantics* are reborn every epoch from
   chain entropy, so fixed-function hardware for "next epoch's algorithm" cannot
   be designed in advance.
2. **Memory-hardness (the dataset).** A 64 MiB epoch dataset is read by a chain
   of data-dependent random accesses in every hash, binding the work to DRAM
   latency. A cheap ASIC cannot fit that on-die (SRAM is far too expensive at
   64 MiB) and must use external DRAM - which erases its cost/latency edge.

Motto: **one CPU = one vote.**

### What CPU mining gives - and doesn't
- **Gives:** fair distribution (entry cost is an ordinary PC), decentralization
  (hashrate spread across many machines, not concentrated in ASIC operators),
  an egalitarian network.
- **Doesn't give:** value. A coin's price comes only from demand (use,
  liquidity, community), which a freshly launched network has none of. Mining
  fairness is about honest distribution, not worth.

---

## 2. Repository layout

```
neuromorph/   NeuroMorph PoW virtual machine + 64 MiB dataset
core/         chain, account state, mempool, consensus rules, checkpoints
node/         P2P sync, JSON RPC, getwork/submitwork, built-in miner
cmd/          cereblixd (node) · cereblix-miner · cereblix-wallet ·
              cereblix-pool · cereblix-faucet · cereblix-checkpoint · cereblix-wasm
web/          project site, block explorer, web wallet, browser miner
deploy/       systemd unit template
```

Everything is pure-Go standard library, zero external dependencies.

---

## 3. NeuroMorph proof of work

File: `neuromorph/neuromorph.go`. A virtual machine that executes a unique
random program for each block candidate (nonce).

### 3.1. Per-epoch parameters (`Params`)
Derived from the "epoch seed" by `DeriveParams(epochSeed)`:

| Field        | Range / meaning                                                  |
|--------------|------------------------------------------------------------------|
| `ProgSize`   | 384..768 instructions per program                                |
| `Loops`      | 32..64 outer execution loops per hash                            |
| `BranchMask` | condition mask for CBRANCH (8 bits at a varying position)        |
| `RotSalt`    | per-epoch rotation/xor salt                                      |
| `OpTable`    | 256-entry value->opcode table; opcode weights 1..8, re-rolled each epoch |
| `AesKey`     | 16-byte per-epoch AES key                                        |
| `DatasetKey` | 16-byte key seeding the 64 MiB epoch dataset                     |

All of it is pseudo-randomly expanded from `epochSeed` via SHA-256 with distinct
prefixes (`nm-params|`, `nm-weights|`, `nm-dataset|`).

### 3.2. Instruction set (15 opcodes)
- **Integer:** `IADD`, `IMUL`, `IMULH` (high half of the product), `IXOR`,
  `IROTR` (rotate), `INEG`.
- **Float (IEEE-754 float64):** `FADD`, `FMUL`, `FDIV`, `FSQRT`.
- **Memory:** `LOAD`, `STORE` - random access to the scratchpad.
- **Control:** `CBRANCH` - data-dependent backward branch, bounded to 8 takes
  per instruction to guarantee halting.
- **Crypto:** `AESR` - one hardware AES round over a scratchpad word.
- **Cross-domain:** `XDOM` - moves bits between integer and float registers, so
  the two domains cannot be split onto separate hardware.

Registers: 16 integer (`uint64`) + 8 float (`float64`).

### 3.3. Scratchpad
- **2 MiB** (`ScratchBytes = 2<<20`), sized for the CPU's L2/L3 cache. Random
  access makes cheap external memory useless for this part.
- Filled with an AES-CTR keystream seeded by the block-header hash.

### 3.4. The 64 MiB dataset (memory-hardness)
- A read-only **64 MiB** buffer (`DatasetBytes = 64<<20`), regenerated each epoch
  from `DatasetKey` (AES-CTR) and **shared across all threads** (memory cost is
  64 MiB total, not per core). Generated lazily on first use.
- Every outer loop performs a chain of **data-dependent random reads**: each
  address depends on the previously read value, so the walk cannot be prefetched
  and the hash is bound to memory latency.
- **Why 64 MiB and not 2 GB:** the goal is to force an ASIC off-die. On-die SRAM
  is prohibitively expensive well below 64 MiB, so even 64 MiB pushes an ASIC to
  external DRAM, while still fitting in the RAM of a phone, a Raspberry Pi, or a
  small VPS. (CryptoNight's 2 MiB scratchpad with no dataset was ASIC'd in 2018;
  that is the lesson this closes.)
- **Activation:** the dataset turns on at block height `DatasetHeight` (240 on
  the launched network). Below it, hashing is byte-identical to the
  dataset-free algorithm, so pre-activation blocks stay valid - the feature was
  added by height activation, without restarting the chain.

### 3.5. One Hash(header, height) pass
1. `seed = sha256("nm-seed|" + header)`.
2. Fill the scratchpad (`fillScratch`).
3. Generate the `ProgSize`-instruction program (`genProgram`): the AES-CTR stream
   is consumed 8 bytes per instruction - `byte0` -> opcode via `OpTable`,
   `byte1` -> destination register, `byte2` -> source register, `bytes4..7` ->
   a 32-bit immediate.
4. Initialize registers from the seed and scratchpad head.
5. Run `Loops` execution loops. After each loop (when `height >= DatasetHeight`)
   perform the dependent dataset-read chain, then fold registers back into the
   scratchpad so no loop can be skipped.
6. XOR-fold the whole scratchpad into 8 words.
7. Final digest: `SHA-256("NMv1" + seed + registers + floats + fold)`.

The 32-byte result is compared against the difficulty target as a big-endian
number.

### 3.6. Determinism (consensus-critical)
- Every float expression is a **single binary operation** (no fused
  multiply-add), so results are identical across machines.
- After each float instruction the value is normalized (no NaN/Inf/zero).
- **The consensus platform is amd64.** `TestDeterminism` pins a reference hash;
  `go test ./neuromorph` must pass.
- Measured: ~4 ms/hash, i.e. **~240 H/s per core** on a server CPU; desktop
  Ryzen/Core are comparable or faster (cache-dependent).

### 3.7. Epoch mutation (anti-ASIC)
- Epoch = `height / EpochLength` (4096 blocks, ~2.8 days).
- The epoch-N seed is the hash of the last block of epoch N-1 (`epochSeedFor`);
  epoch 0 uses a fixed constant.
- At each boundary `DeriveParams` yields new opcode weights, program length, loop
  count, masks, AES key and dataset -> the VM's rules change. An ASIC shipped
  today runs a "different" algorithm one epoch later.

### 3.8. Why GPUs are unprofitable
Data-dependent branches (`CBRANCH`) every few instructions cause warp
divergence: a GPU runs at the speed of one or two of its scalar cores, i.e.
slower than a laptop.

### 3.9. What drives hashrate
- **Core count / frequency** - near-linear (the `-threads` flag).
- **L2/L3 cache size and speed** - the scratchpad lives there.
- **Dataset locality** - on commodity CPUs the 64 MiB dataset spills to DRAM
  (memory-latency bound); CPUs with very large L3 cache it.
- **AES-NI** - required for speed (present on any CPU since ~2011).

---

## 4. Blockchain core (`core`)

### 4.1. Economic parameters (`core/types.go`)
| Parameter            | Value                                              |
|----------------------|----------------------------------------------------|
| Ticker               | CRB (1 CRB = 10^8 synapses)                         |
| Algorithm            | NeuroMorph - self-mutating, memory-hard PoW VM     |
| Block time           | 60 s, retarget every 20 blocks                     |
| Reward               | 50 CRB, halving every 1,051,200 blocks (~2 years)  |
| Max supply           | ~105,120,000 CRB                                    |
| VM mutation epoch    | 4096 blocks (~2.8 days)                             |
| Premine              | **0** - empty genesis                              |
| Signatures / addrs   | ed25519, `crb1` + SHA-256(pubkey)[:20]             |

### 4.2. Difficulty & work
- The target is a 256-bit number; a hash is valid if `hash <= target`.
- Retarget over a 20-block window: average target x (actual time / expected
  time), clamped to a [1/4 .. 4x] band against time-warp.
- Fork choice is by **most cumulative work** (`WorkOf(target) = 2^256 /
  (target+1)`), not by length.

### 4.3. Addresses & transactions
- Keys: ed25519. Address: `crb1` + hex(SHA-256(pubkey)[:20]).
- Account/nonce model (not UTXO): each account has a balance and a monotonic
  nonce; replay protection is via the nonce.
- Signing payload: `cerebra-tx-v1|<from_pub>|<to>|<amount>|<fee>|<nonce>`
  (a protocol constant; not the brand). From height `ChainIDHeight` (700) it also
  binds the genesis hash (chain-id): `cerebra-tx-v1|<chain-id>|<from_pub>|...`, so
  a signature cannot be replayed onto a fork or any other chain sharing the
  `crb1` address format.
- **Fees** are cheap and self-adjusting: a floor of 0.00001 CRB that rises with
  recent block fullness, enforced as a consensus minimum from height 450 (no
  free-transaction bypass).

### 4.4. Blocks
- Fixed 124-byte header (version, height, time, prev-hash, tx-root, target,
  nonce). The block id is `SHA-256(header)`; the PoW is the NeuroMorph hash of
  the same header. The nonce occupies the last 8 header bytes.
- The chain is stored as human-readable JSONL (one block per line) - auditable by
  eye.

### 4.5. Consensus rules
Block validation checks version, height, prev-hash, timestamp (> median of last
11 blocks, < now + 300 s), correct retarget target, coinbase rules (reward =
subsidy + fees, exactly), coinbase maturity (mined rewards become spendable only
100 blocks deep), the height-activated minimum fee, chain-id-bound signatures,
unique signed transactions, balance/nonce correctness, authority checkpoints
(§5), and finally the proof of work.

**Height-activated upgrades** (each turned on at a block height so the existing
chain stays valid - no restart, no hard fork of history): 64 MiB dataset (240),
enforced minimum fee (450), coinbase maturity (500), chain-id signature binding
(700).

### 4.6. Genesis
Empty coinbase to an unspendable address, timestamp 2026-06-11 00:00:00 UTC.
Coins exist only from mining.

---

## 5. 51% resistance (decentralized)

A day-old PoW chain cannot be cryptographically final against a >50% attacker -
real security comes from accumulated hashrate over time. Cereblix ships layered
mitigations - **decentralized by default, plus an authority checkpoint for the
bootstrap phase** - that kill the cheap catastrophic attack and buy time:

- **Max reorg depth** (`-maxreorg`, default 100): any reorg that would rewrite
  more than N blocks is rejected outright, killing rewrite-from-genesis attacks.
- **Reorg-cost penalty** (`-reorg-penalty`, optional): deeper reorgs must carry
  disproportionately more work.
- **Authority checkpoints** (bootstrap phase): an authority key signs the
  canonical tip; every node pulls signed checkpoints from peers (`/p2p/checkpoint`),
  verifies them against a public key compiled into the binary, and refuses any
  chain that conflicts with one (no reorg may cross a checkpoint; a block at a
  checkpointed height must match it). New nodes trust the key from first run, so
  the network follows the canonical chain even against a higher-hashrate fork.
  This is a **deliberate, transparent centralization for the early phase** -
  removable (sign nothing, or ship a binary without the key) as independent
  nodes and hashrate grow into real finality. The signer is the standalone
  `cmd/cereblix-checkpoint` tool; the authority private key is held off the
  network. It does NOT prevent anyone forking the open-source code into a
  separate coin - it only protects this chain's history from rewrites.

Honest limit: these make deep rewrites impractical and raise the cost of shallow
double-spends, but pure-hashrate finality still requires time and a distributed
miner base.

---

## 6. Node (`node` + `cmd/cereblixd`)

A single dependency-free binary running two HTTP servers (P2P, RPC) and an
optional built-in CPU miner.

### 6.1. P2P (HTTP, default `:18750`)
`GET /p2p/tip`, `GET /p2p/hash?h=`, `GET /p2p/blocks?from=&count=`,
`POST /p2p/block`, `POST /p2p/tx`, `GET /p2p/peers`, `GET /p2p/checkpoint`. Sync
(every 10 s) finds the common ancestor by binary search, downloads in batches,
adopts the higher-work chain, and pulls/enforces the authority checkpoint. The
P2P port is per-IP rate-limited and `addPeer` rejects loopback/private/link-local
URLs (SSRF guard).

### 6.2. RPC (HTTP, default `127.0.0.1:18751`, JSON, CORS)
`status`, `balance` (total, `spendable` and nonce), `history`, `blocks`,
`block?h=|hash=`, `tx` (GET lookup / POST submit), `mempool`, `mined?addr=`
(blocks mined to an address), `getwork`, `submitwork`, `checkpoint` (GET serve /
POST from the authority signer), `params`, `richlist`, `search`. `status` reports
network hashrate (8-block window), block age, the suggested fee, and the chain-id
and its activation height.

### 6.3. getwork / submitwork
External miners pull a header template + epoch seed via `getwork` and submit a
nonce via `submitwork`; templates are cached briefly and tied to the current tip.

### 6.4. Built-in miner
`-mine -threads N -coinbase crb1...` runs N worker goroutines, rebuilding the VM
at epoch boundaries.

### 6.5. Hardening
- Run as an unprivileged user inside a systemd sandbox (a node compromise does
  not become a host compromise).
- HTTP request body-size cap, read/write/idle timeouts (anti slow-loris),
  per-request panic recovery, and panic recovery in miner/sync goroutines.
- RPC binds localhost; only P2P (and the reverse-proxied API) is public.

### 6.6. Mining pool (`cmd/cereblix-pool`)
A pool so small CPUs earn a steady trickle instead of a rare lottery win. It
speaks the **same getwork/submitwork protocol as the node**, so the stock
`cereblix-miner` works against it unchanged - only the `-node` URL differs. The
pool hands out work paying its own wallet at an **easier "share" target**;
every submitted share is re-verified (a real NeuroMorph hash). When a share also
meets the network target the pool forwards the block. Block rewards are split
among miners proportional to their shares (PROP, with a small pool fee) and paid
out automatically once a miner crosses a threshold - paying only the *matured*
(spendable) balance and in partial amounts as more coinbase matures.

### 6.7. Faucet with a proof-of-useful-work captcha (`cmd/cereblix-faucet`)
A faucet that lets newcomers try the wallet without mining first. Its anti-bot
captcha is **a real NeuroMorph share**: the browser mines one share (via the
WebAssembly hasher) against a template paying a dedicated faucet wallet - so the
"captcha" is genuine work in the coin's own algorithm (a bot must actually mine),
and occasionally a share is also a full block. The faucet then sends a tiered
amount, rate-limited per address and per IP (real client IP taken from the last
`X-Forwarded-For` hop, so the limit can't be header-spoofed).

### 6.8. Authority checkpoint signer (`cmd/cereblix-checkpoint`)
The operator-only tool that periodically signs a block a few behind the tip with
the authority key and pushes it to the node (`POST /api/checkpoint`), which
serves it to peers. See §5. The private key is kept off the network.

---

## 7. Standalone miner (`cmd/cereblix-miner`)

CPU miner for amd64 (Intel/AMD), Windows & Linux. Pulls work from any node over
HTTP and submits shares. Uses all cores by default (`-threads` to limit). On a
double-click with no address it prompts for one instead of exiting.

```
cereblix-miner -addr crb1YOURADDRESS
cereblix-miner -addr crb1YOURADDRESS -threads 4
```

> Antivirus tools often flag unsigned CPU miners as PUA - add an exclusion for
> the miner file rather than disabling protection.

---

## 8. Standalone CLI wallet (`cmd/cereblix-wallet`)

A local key store + RPC client + block explorer, independent of the website
(like `bitcoin-cli` - it needs a node, but keys live only on your machine).

- Keys in `~/.cereblix/wallet.json`, optionally passphrase-encrypted with
  PBKDF2-HMAC-SHA256 + AES-GCM (all standard library).
- Interactive shell or one-shot commands: `new`, `list`, `balance`, `send`,
  `receive`, `history`, `import`, `export`, `encrypt`, plus explorer commands
  `status`, `block`, `tx`, `address`, `richlist`, `mempool`, `search`.

---

## 9. Web wallet, site & explorer (`web/`)

- **Web wallet:** static page; keys are generated and **signed in the browser**
  (ed25519 via tweetnacl). The private key never reaches the server. Addresses
  are computed with a pure-JS SHA-256 (WebCrypto is unavailable over plain HTTP).
- **Site:** landing with live network stats, the naming/DNA rationale, mining
  guide, parameters, FAQ. English/Russian with auto-detect + a manual switch.
- **Explorer:** blocks, transactions with confirmations, address pages with
  paginated history, rich list, mempool, and a height/hash/txid/address search.

---

## 10. Build from source

Requires Go 1.21+. Zero external dependencies.

```sh
git clone https://github.com/Cerebra-CBR/cereblix.git
cd cereblix
go build ./...

# cross-compile, e.g. Windows from Linux:
GOOS=windows GOARCH=amd64 go build -o cereblix-miner.exe ./cmd/cereblix-miner
```

`go test ./neuromorph` validates VM determinism.

---

## 11. Security model

- **Keys:** custody is the user's; the web and CLI wallets sign locally and never
  transmit private keys. CLI wallets can be passphrase-encrypted at rest.
- **Node:** runs unprivileged and sandboxed; input is size-limited and
  timeout-bounded; handlers and background goroutines recover from panics.
- **Consensus:** ed25519 signatures, PoW, account-nonce replay protection, and
  the 51% mitigations of section 5.
- **Honest framing:** "unhackable" is not a thing. Security is layered risk
  reduction. The biggest real risk to a new coin is a 51% attack while hashrate
  is small, not an ASIC years away.

---

## 12. Known limitations & deliberate trade-offs

- **Chain & state are in RAM**; reorgs rewrite the JSONL store. Fine for a young
  chain; a serious size would need an on-disk DB and state snapshots.
- **Transparent ledger, by design** - addresses and amounts are public; Cereblix
  does not attempt Monero-style privacy. This is deliberate: privacy coins face
  exchange delisting, while a transparent chain is auditable and
  compliance-friendly.
- **Early-phase authority checkpoint** - a deliberate, removable centralization
  while the network bootstraps (§5).
- **P2P is HTTP polling**, not a gossip overlay - simplicity over latency.
- **64 MiB dataset** forces DRAM on ASICs and commodity CPUs, but fits in the L3
  of very large server CPUs (raising the size would close that gap at some cost
  to low-end devices).
- **Unsigned binaries** - antivirus tools may warn.

---

## 13. About

Cereblix is a free, open-source project with zero premine, zero fund and no
fundraising. The code is MIT-licensed - mine it, fork it, run your own node.
