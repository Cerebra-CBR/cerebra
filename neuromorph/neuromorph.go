// Package neuromorph implements NeuroMorph PoW v1 — a CPU-only proof of work.
//
// Core ideas:
//   - Per-nonce random programs executed by a register VM (16 int regs,
//     8 float regs) with data-dependent branches, mixed int/float math,
//     hardware AES rounds and random access to a 2 MiB scratchpad.
//   - Per-epoch semantic mutation: every EpochLength blocks the opcode
//     frequency table, program length, loop count, rotation salt and the
//     AES key are re-derived from chain entropy, so fixed-function
//     hardware cannot be designed ahead of time.
//
// Consensus-critical platform: IEEE-754 float64 on amd64/arm64 without
// fused operations (all float expressions are single binary ops).
package neuromorph

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/bits"
	"sync"
)

const (
	ScratchBytes = 2 << 20 // 2 MiB scratchpad, cache-resident on modern CPUs
	scratchWords = ScratchBytes / 8
	scratchMask  = uint64(ScratchBytes - 8) // 8-byte aligned addressing
	numOps       = 15

	// Memory-hardness (activated at DatasetHeight). A 64 MiB read-only dataset,
	// regenerated each epoch from the epoch seed and shared across all threads,
	// is touched by a chain of data-dependent random reads in every hash. The
	// address chain depends on the values read, so accesses cannot be
	// prefetched — the hash is bound to DRAM latency, forcing any ASIC to carry
	// 64 MiB of real random-access memory (it cannot fit cheap on-die SRAM).
	DatasetBytes        = 64 << 20 // 64 MiB
	datasetWords        = DatasetBytes / 8
	datasetMask         = uint64(DatasetBytes - 8)
	datasetReadsPerLoop = 64

	// DatasetHeight is the block height at which the dataset turns on. Blocks
	// below it hash exactly as before (so all pre-activation blocks stay valid);
	// blocks at/above it must include the memory-hard step. Give nodes/miners
	// time to update before this height.
	DatasetHeight = 1000
)

// Op codes.
const (
	opIADD = iota
	opIMUL
	opIMULH
	opIXOR
	opIROTR
	opINEG
	opFADD
	opFMUL
	opFDIV
	opFSQRT
	opLOAD
	opSTORE
	opCBRANCH
	opAESR
	opXDOM // cross-domain: couples int and float registers
)

// Params are the per-epoch VM semantics derived from chain entropy.
type Params struct {
	ProgSize   int        // instructions per program: 384..768
	Loops      int        // outer loops per hash: 32..64
	BranchMask uint64     // condition mask for CBRANCH
	RotSalt    uint64     // per-epoch rotation/xor salt
	OpTable    [256]uint8 // weighted opcode lookup table
	AesKey     [16]byte   // per-epoch AES round key
	DatasetKey [16]byte   // per-epoch key seeding the 64 MiB dataset
}

// EpochSeed0 is the seed for epoch 0 (before any chain entropy exists).
func EpochSeed0() []byte {
	h := sha256.Sum256([]byte("cerebra/neuromorph/v1/epoch0/2026-06-11"))
	return h[:]
}

// DeriveParams expands an epoch seed into concrete VM semantics.
func DeriveParams(epochSeed []byte) *Params {
	h := sha256.Sum256(append([]byte("nm-params|"), epochSeed...))
	p := &Params{}
	p.ProgSize = 384 + int(binary.LittleEndian.Uint16(h[0:2]))%385 // 384..768
	p.Loops = 32 + int(h[2])%33                                    // 32..64
	p.BranchMask = uint64(0xFF) << (h[3] % 24)                     // 8 condition bits, varying position
	p.RotSalt = binary.LittleEndian.Uint64(h[4:12])
	copy(p.AesKey[:], h[12:28])
	dk := sha256.Sum256(append([]byte("nm-dataset|"), epochSeed...))
	copy(p.DatasetKey[:], dk[:16])

	// Weighted opcode table: weights 1..8 per op, re-rolled every epoch.
	wh := sha256.Sum256(append([]byte("nm-weights|"), epochSeed...))
	weights := make([]int, numOps)
	total := 0
	for i := 0; i < numOps; i++ {
		weights[i] = 1 + int(wh[i])%8
		total += weights[i]
	}
	idx := 0
	for op := 0; op < numOps; op++ {
		n := weights[op] * 256 / total
		if op == numOps-1 {
			n = 256 - idx
		}
		for j := 0; j < n && idx < 256; j++ {
			p.OpTable[idx] = uint8(op)
			idx++
		}
	}
	for idx < 256 {
		p.OpTable[idx] = uint8(wh[idx%32]) % numOps
		idx++
	}
	return p
}

type instr struct {
	op  uint8
	dst uint8
	src uint8
	imm uint32
}

// datasetCache holds the per-epoch 64 MiB dataset, shared read-only across all
// VMs/threads of an epoch so memory use is 64 MiB total, not per thread.
var (
	dsMu    sync.Mutex
	dsCache = map[[16]byte][]uint64{}
)

// getDataset returns the shared 64 MiB dataset for the given epoch key,
// generating it (AES-CTR keystream) on first use. Deterministic across nodes.
func getDataset(key [16]byte) []uint64 {
	dsMu.Lock()
	defer dsMu.Unlock()
	if d, ok := dsCache[key]; ok {
		return d
	}
	d := make([]uint64, datasetWords)
	blk, _ := aes.NewCipher(key[:])
	var in, out [16]byte
	for i := 0; i < datasetWords; i += 2 {
		binary.LittleEndian.PutUint64(in[0:8], uint64(i))
		blk.Encrypt(out[:], in[:])
		d[i] = binary.LittleEndian.Uint64(out[0:8])
		d[i+1] = binary.LittleEndian.Uint64(out[8:16])
	}
	if len(dsCache) >= 2 { // keep only the most recent epochs resident
		for k := range dsCache {
			delete(dsCache, k)
			break
		}
	}
	dsCache[key] = d
	return d
}

// VM holds reusable buffers so miners can hash without per-hash allocation.
type VM struct {
	params  *Params
	aes     cipher.Block
	scratch []uint64
	prog    []instr
	taken   []uint8
	dataset []uint64 // shared per-epoch 64 MiB dataset; nil until first needed
}

func NewVM(p *Params) *VM {
	blk, err := aes.NewCipher(p.AesKey[:])
	if err != nil {
		panic(err)
	}
	return &VM{
		params:  p,
		aes:     blk,
		scratch: make([]uint64, scratchWords),
		prog:    make([]instr, p.ProgSize),
		taken:   make([]uint8, p.ProgSize),
	}
}

// fillScratch fills the scratchpad with AES-CTR keystream seeded by `seed`.
func (vm *VM) fillScratch(seed [32]byte) {
	key := sha256.Sum256(append(seed[:], 0x53))
	blk, _ := aes.NewCipher(key[:16])
	var ctr, out [16]byte
	copy(ctr[:], key[16:32])
	buf := make([]byte, 16)
	for i := 0; i < scratchWords; i += 2 {
		binary.LittleEndian.PutUint64(buf[0:8], uint64(i))
		copy(buf[8:16], ctr[8:16])
		blk.Encrypt(out[:], buf)
		vm.scratch[i] = binary.LittleEndian.Uint64(out[0:8])
		vm.scratch[i+1] = binary.LittleEndian.Uint64(out[8:16])
	}
}

// genProgram generates the per-nonce instruction stream.
func (vm *VM) genProgram(seed [32]byte) {
	key := sha256.Sum256(append(seed[:], 0x50))
	blk, _ := aes.NewCipher(key[:16])
	var in, out [16]byte
	copy(in[:], key[16:32])
	stream := make([]byte, 0, vm.params.ProgSize*8)
	for len(stream) < vm.params.ProgSize*8 {
		blk.Encrypt(out[:], in[:])
		stream = append(stream, out[:]...)
		copy(in[:], out[:])
		binary.LittleEndian.PutUint64(in[0:8], binary.LittleEndian.Uint64(in[0:8])+1)
	}
	for i := 0; i < vm.params.ProgSize; i++ {
		b := stream[i*8 : i*8+8]
		vm.prog[i] = instr{
			op:  vm.params.OpTable[b[0]],
			dst: b[1],
			src: b[2],
			imm: binary.LittleEndian.Uint32(b[4:8]),
		}
	}
}

// normFloat forces a float into a finite, well-conditioned range while
// keeping its mantissa entropy (similar in spirit to RandomX masking).
func normFloat(x uint64) float64 {
	mant := x & 0x000FFFFFFFFFFFFF
	exp := uint64(1023) << 52 // exponent fixed -> value in [1,2)
	return math.Float64frombits(exp | mant)
}

// Hash computes the NeuroMorph hash of `header` at block `height` under epoch
// params. The header must already contain the nonce being tried. From
// DatasetHeight onward the memory-hard dataset step is included; below it the
// computation is byte-identical to v1 so pre-activation blocks stay valid.
func (vm *VM) Hash(header []byte, height uint64) [32]byte {
	p := vm.params
	seed := sha256.Sum256(append([]byte("nm-seed|"), header...))

	useDS := height >= DatasetHeight
	if useDS && vm.dataset == nil {
		vm.dataset = getDataset(p.DatasetKey)
	}

	vm.fillScratch(seed)
	vm.genProgram(seed)

	// Init registers from the seed and the scratchpad head.
	var r [16]uint64
	var f [8]float64
	for i := 0; i < 4; i++ {
		r[i] = binary.LittleEndian.Uint64(seed[i*8 : i*8+8])
	}
	for i := 4; i < 16; i++ {
		r[i] = vm.scratch[i] ^ p.RotSalt
	}
	for i := 0; i < 8; i++ {
		f[i] = normFloat(vm.scratch[16+i])
	}

	var aesIn, aesOut [16]byte
	for loop := 0; loop < p.Loops; loop++ {
		for i := range vm.taken {
			vm.taken[i] = 0
		}
		pc := 0
		for pc < p.ProgSize {
			ins := &vm.prog[pc]
			d := ins.dst & 15
			s := ins.src & 15
			switch ins.op {
			case opIADD:
				r[d] += r[s] + uint64(ins.imm)
			case opIMUL:
				r[d] *= r[s] | 1
			case opIMULH:
				hi, _ := bits.Mul64(r[d], r[s])
				r[d] = hi ^ uint64(ins.imm)
			case opIXOR:
				r[d] ^= r[s] + p.RotSalt
			case opIROTR:
				r[d] = bits.RotateLeft64(r[d], -int((r[s]^uint64(ins.imm))&63))
			case opINEG:
				r[d] = ^r[d] + uint64(ins.imm)
			case opFADD:
				f[d&7] = f[d&7] + f[s&7]
			case opFMUL:
				f[d&7] = f[d&7] * f[s&7]
			case opFDIV:
				f[d&7] = f[d&7] / normFloat(math.Float64bits(f[s&7]))
			case opFSQRT:
				f[d&7] = math.Sqrt(math.Abs(f[d&7]))
			case opLOAD:
				addr := (r[s] + uint64(ins.imm)) & scratchMask
				r[d] ^= vm.scratch[addr>>3]
			case opSTORE:
				addr := (r[d] + uint64(ins.imm)) & scratchMask
				vm.scratch[addr>>3] ^= r[s] + uint64(loop)
			case opCBRANCH:
				// Data-dependent backward branch, bounded to guarantee halt.
				if (r[d]+uint64(ins.imm))&p.BranchMask == 0 && vm.taken[pc] < 8 {
					vm.taken[pc]++
					back := int(ins.imm%31) + 1
					pc -= back
					if pc < 0 {
						pc = 0
					}
					continue
				}
			case opAESR:
				addr := (r[s] + uint64(ins.imm)) & scratchMask & ^uint64(15)
				w := addr >> 3
				binary.LittleEndian.PutUint64(aesIn[0:8], vm.scratch[w])
				binary.LittleEndian.PutUint64(aesIn[8:16], vm.scratch[w+1])
				vm.aes.Encrypt(aesOut[:], aesIn[:])
				vm.scratch[w] = binary.LittleEndian.Uint64(aesOut[0:8])
				vm.scratch[w+1] = binary.LittleEndian.Uint64(aesOut[8:16])
				r[d] ^= vm.scratch[w]
			case opXDOM:
				if ins.imm&1 == 0 {
					r[d] ^= math.Float64bits(f[s&7])
				} else {
					f[d&7] = f[d&7] * normFloat(r[s])
				}
			}
			// Keep floats finite without branching on hardware flags.
			if ins.op >= opFADD && ins.op <= opFSQRT {
				v := f[d&7]
				if math.IsNaN(v) || math.IsInf(v, 0) || v == 0 {
					f[d&7] = normFloat(r[d] | 1)
				}
			}
			pc++
		}
		// Memory-hard step (post-activation): a chain of data-dependent random
		// reads from the 64 MiB dataset. Each address depends on the previous
		// read, so the walk is latency-bound and cannot be prefetched.
		if useDS {
			addr := (r[1] ^ p.RotSalt) & datasetMask
			for k := 0; k < datasetReadsPerLoop; k++ {
				v := vm.dataset[addr>>3]
				r[k&15] ^= v
				addr = (v + r[(k+1)&15] + uint64(loop)) & datasetMask
			}
		}
		// Fold registers back into the scratchpad so loops cannot be skipped.
		base := (r[0] ^ uint64(loop)*0x9E3779B97F4A7C15) & scratchMask >> 3
		for i := 0; i < 16; i++ {
			vm.scratch[(base+uint64(i))%scratchWords] ^= r[i]
		}
		for i := 0; i < 8; i++ {
			r[i+8] ^= math.Float64bits(f[i])
		}
	}

	// Final digest: registers + XOR-fold of the whole scratchpad.
	var fold [8]uint64
	for i := 0; i < scratchWords; i += 8 {
		fold[0] ^= vm.scratch[i]
		fold[1] ^= vm.scratch[i+1]
		fold[2] ^= vm.scratch[i+2]
		fold[3] ^= vm.scratch[i+3]
		fold[4] ^= vm.scratch[i+4]
		fold[5] ^= vm.scratch[i+5]
		fold[6] ^= vm.scratch[i+6]
		fold[7] ^= vm.scratch[i+7]
	}
	out := make([]byte, 0, 4+32+16*8+8*8+8*8)
	out = append(out, []byte("NMv1")...)
	out = append(out, seed[:]...)
	var tmp [8]byte
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint64(tmp[:], r[i])
		out = append(out, tmp[:]...)
	}
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(tmp[:], math.Float64bits(f[i]))
		out = append(out, tmp[:]...)
	}
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(tmp[:], fold[i])
		out = append(out, tmp[:]...)
	}
	return sha256.Sum256(out)
}
