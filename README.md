# Cereblix (CRB)

**A CPU-only cryptocurrency built from scratch on the self-mutating NeuroMorph
proof-of-work algorithm.** No GPU, no ASIC - ever. One CPU, one vote.

- 🌐 Site & explorer: http://188.34.181.191/cereblix/
- 💼 Web wallet: http://188.34.181.191/cereblix/wallet/
- 🚰 Free faucet: http://188.34.181.191/cereblix/faucet.html
- ⛏️ Pool: `-node http://188.34.181.191/cereblix/pool/api`
- 📖 Full design: [ARCHITECTURE.md](ARCHITECTURE.md)

> A free, open-source project with **zero premine, zero fund, no fundraising**.
> Mine it, fork it, run your own node - the code is all yours.

---

## Why Cereblix

- **🧬 Self-mutating algorithm.** Every 4096 blocks (~2.8 days) NeuroMorph
  rebuilds its own VM semantics from chain entropy - opcode weights, program
  length, constants, AES keys all change. Fixed-function hardware for an
  algorithm that doesn't exist yet is impossible. That is lifelong ASIC
  resistance by construction, not by promise.
- **⚖️ 1 CPU = 1 vote.** Random programs with data-dependent branches starve
  GPUs (warp divergence) - any laptop competes. No farms.
- **🤝 Fair launch.** Empty genesis block, coins exist only from mining.
- **📡 Lightweight node.** One dependency-free Go binary; the chain is
  human-readable JSONL.

## Coin parameters

| | |
|---|---|
| Ticker | CRB (1 CRB = 10⁸ synapses) |
| Algorithm | NeuroMorph v1 - self-mutating PoW VM, CPU-only |
| Block time | 60 s, retarget every 20 blocks |
| Reward | 50 CRB, halving every 1,051,200 blocks (~2 years) |
| Max supply | ~105,120,000 CRB |
| VM mutation epoch | 4096 blocks |
| Premine | **0** |
| Signatures / addresses | ed25519 · `crb1` + SHA-256(pubkey)[:20] |

## Build

Requires Go 1.21+. Zero external dependencies (standard library only).

```sh
git clone https://github.com/Cerebra-CBR/cerebra.git
cd cereblix
go build ./...

# or build each tool:
go build -o cereblixd        ./cmd/cereblixd
go build -o cereblix-miner   ./cmd/cereblix-miner
go build -o cereblix-wallet  ./cmd/cereblix-wallet
```

Cross-compile (e.g. Windows from Linux):

```sh
GOOS=windows GOARCH=amd64 go build -o cereblix-miner.exe ./cmd/cereblix-miner
```

## Mine

```sh
# 1. create a wallet address
cereblix-wallet new main

# 2. point the miner at any node (the public seed by default)
cereblix-miner -addr crb1YOURADDRESS            # uses all cores
cereblix-miner -addr crb1YOURADDRESS -threads 4 # limit cores
```

> Antivirus software often flags unsigned CPU miners as PUA - add an exclusion
> for the miner file rather than disabling protection.

### Mine in a browser (phone / iOS / Android / desktop)

The NeuroMorph hasher also compiles to WebAssembly, so the coin can be mined in
any browser with no install and no signing - including iOS Safari and Android.
It is much slower than the native miner (a phone does a few to a few dozen H/s)
but runs anywhere. Open `mine.html` on the site, enter your address, start.

Build the wasm module:

```sh
GOOS=js GOARCH=wasm go build -o web/site/cereblix.wasm ./cmd/cereblix-wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/site/wasm_exec.js
```

Hashing is verified byte-identical across amd64, arm64 and wasm
(`TestCrossPlatformHash`), so browser/phone-found blocks are accepted.

### Mine in a pool (steady rewards)

Solo mining is a lottery; a pool pays a steady trickle proportional to your work.
The stock miner works against the pool unchanged - just point `-node` at it:

```sh
cereblix-miner -addr crb1YOURADDRESS -node http://188.34.181.191/cereblix/pool/api
```

On the pool the miner logs frequent "block found" - those are *shares*; your real
reward arrives as automatic pool payouts to your address.

### Free faucet

No coins yet? Grab a little from the faucet to try the wallet. The anti-bot check
is a real in-browser NeuroMorph **share** (your CPU mines for a moment), so it
doubles as a tiny mining onramp: http://188.34.181.191/cereblix/faucet.html

## Run a full node

```sh
cereblixd -datadir ./data                       # follow the chain
cereblixd -datadir ./data -mine -threads 2 -coinbase crb1YOURADDRESS  # node + miner
```

Your own node's RPC is at `http://127.0.0.1:18751/api`. Point the wallet/miner
at it with `-node http://127.0.0.1:18751/api`.

## Standalone CLI wallet

A local key store + RPC client + block explorer, independent of the website
(like `bitcoin-cli`). Keys live only on your machine in `~/.cereblix/wallet.json`
(optionally passphrase-encrypted with PBKDF2 + AES-GCM).

```sh
cereblix-wallet                      # interactive shell
cereblix-wallet new main             # create address
cereblix-wallet list                 # addresses + balances
cereblix-wallet send crb1... 12.5    # sign locally, broadcast
cereblix-wallet encrypt              # passphrase-protect the wallet
cereblix-wallet tx <txid>            # explorer: look up a transaction
cereblix-wallet block 42             # explorer: show a block
cereblix-wallet richlist             # top addresses
```

## Repository layout

```
neuromorph/   NeuroMorph PoW virtual machine
core/         chain, state, mempool, consensus rules, checkpoints
node/         P2P sync, JSON RPC, getwork/submitwork, built-in miner
cmd/          cereblixd · cereblix-miner · cereblix-wallet · cereblix-pool ·
              cereblix-faucet · cereblix-checkpoint · cereblix-wasm
web/          project site + block explorer + web wallet + browser miner
deploy/       systemd unit
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the complete technical specification.

## License

[MIT](LICENSE). Mine it, fork it, mirror it.
