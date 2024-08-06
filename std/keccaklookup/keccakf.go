package keccaklookup

import (
	"fmt"
	"math"
	"math/big"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/limbs"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

var rotc = [24]int{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
}

var piln = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

type KeccakfAPI struct {
	api                frontend.API
	la                 *limbs.API
	rc                 [24]limbs.Limbs
	k                  int
	xorTable, chiTable *logderivlookup.Table
}

// NewKeccakfAPI creates KeccakfAPI. k value is word size for the xor and chi tables.
// e.g. if k = 4, then xor table would have 2^(4*2) rows and chi table would have 2^(4*3) rows.
func NewKeccakfAPI(api frontend.API, k int) *KeccakfAPI {
	rc := [24]limbs.Limbs{
		constLimbs(0x0000000000000001, k),
		constLimbs(0x0000000000008082, k),
		constLimbs(0x800000000000808A, k),
		constLimbs(0x8000000080008000, k),
		constLimbs(0x000000000000808B, k),
		constLimbs(0x0000000080000001, k),
		constLimbs(0x8000000080008081, k),
		constLimbs(0x8000000000008009, k),
		constLimbs(0x000000000000008A, k),
		constLimbs(0x0000000000000088, k),
		constLimbs(0x0000000080008009, k),
		constLimbs(0x000000008000000A, k),
		constLimbs(0x000000008000808B, k),
		constLimbs(0x800000000000008B, k),
		constLimbs(0x8000000000008089, k),
		constLimbs(0x8000000000008003, k),
		constLimbs(0x8000000000008002, k),
		constLimbs(0x8000000000000080, k),
		constLimbs(0x000000000000800A, k),
		constLimbs(0x800000008000000A, k),
		constLimbs(0x8000000080008081, k),
		constLimbs(0x8000000000008080, k),
		constLimbs(0x0000000080000001, k),
		constLimbs(0x8000000080008008, k),
	}
	return &KeccakfAPI{
		api:      api,
		la:       limbs.NewAPI(api),
		k:        k,
		rc:       rc,
		xorTable: newXorTable(api, k),
		chiTable: newChiTable(api, k),
	}
}

func constLimbs(in uint64, k int) limbs.Limbs {
	var reversed uint64
	for i := 0; i < 64; i++ {
		d := ((in >> (63 - i)) & 1) << i
		reversed += d
	}
	num := new(big.Int).SetUint64(reversed)
	return split(num, 64, k)
}

func split(in *big.Int, inputSize, limbSize int) limbs.Limbs {
	var outputs limbs.Limbs
	rem := new(big.Int).Set(in)
	remSize := inputSize
	nbLimbs := inputSize / limbSize
	for i := 0; i < nbLimbs; i++ {
		remSize -= limbSize
		zeros := exp2(remSize)
		quo := new(big.Int).Div(rem, zeros)
		outputs = append(outputs, limbs.Limb{Val: quo, Size: limbSize})
		rem = new(big.Int).Sub(rem, new(big.Int).Mul(quo, zeros))
	}
	if remSize > 0 {
		outputs = append(outputs, limbs.Limb{Val: rem, Size: remSize})
	}
	return outputs
}

func (ka *KeccakfAPI) Permute(st [25]limbs.Limbs) [25]limbs.Limbs {
	var bc [5]limbs.Limbs
	var t limbs.Limbs
	for round := 0; round < 24; round++ {
		// theta
		for i := 0; i < 5; i++ {
			bc[i] = ka.xor(st[i], st[i+5], st[i+10], st[i+15], st[i+20])
		}
		for i := 0; i < 5; i++ {
			rotated := ka.la.Lrot(bc[(i+1)%5], 64-1, ka.k)
			t = ka.xor(bc[(i+4)%5], rotated)
			for j := 0; j < 25; j += 5 {
				st[j+i] = ka.xor(st[j+i], t)
			}
		}
		// rho pi
		t = st[1]
		for i := 0; i < 24; i++ {
			j := piln[i]
			bc[0] = st[j]
			st[j] = ka.la.Lrot(t, 64-rotc[i], ka.k)
			t = bc[0]
		}
		// chi
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = st[j+i]
			}
			for i := 0; i < 5; i++ {
				st[j+i] = ka.chi(bc[(i+1)%5], bc[(i+2)%5], st[j+i])
			}
		}
		// iota
		st[0] = ka.xor(st[0], ka.rc[round])
	}
	return st
}

func (k *KeccakfAPI) chi(a, b, c limbs.Limbs) limbs.Limbs {
	if len(a) != len(b) || len(a) != len(c) {
		panic(fmt.Sprintf("chi words len mismatch: a %d, b %d, c %d", a, b, c))
	}
	var ret limbs.Limbs
	for i := range a {
		// Note: for now if the size of the word a, b, and c are not equal to k, the lookup would
		// give wrong result. TODO: check and pad a, b, c to correct size before lookup.
		merged := k.la.Merge(limbs.Limbs{a[i], b[i], c[i]})
		res := k.chiTable.Lookup(merged.Val)
		ret = append(ret, limbs.Limb{Val: res[0], Size: a[i].Size})
	}
	return ret
}

func (k *KeccakfAPI) xor(ins ...limbs.Limbs) limbs.Limbs {
	if len(ins) < 2 {
		panic("xor input length < 2")
	}
	xored := ins[0]
	for i := 1; i < len(ins); i++ {
		xored = k.xor2(xored, ins[i])
	}
	return xored
}

func (k *KeccakfAPI) xor2(a, b limbs.Limbs) limbs.Limbs {
	if len(a) != len(b) {
		log.Panicf("cannot xor2: a len %d, b len %d", len(a), len(b))
	}
	var ret limbs.Limbs
	for i := range a {
		if a[i].Size != b[i].Size {
			log.Panicf("cannot xor: a[%d].size (%d) != b[%d].size (%d)", i, a[i].Size, i, b[i].Size)
		}
		merged := k.la.Merge(limbs.Limbs{a[i], b[i]})
		xored := k.xorTable.Lookup(merged.Val)
		ret = append(ret, limbs.Limb{Val: xored[0], Size: a[i].Size})
	}
	return ret
}

func newXorTable(api frontend.API, k int) *logderivlookup.Table {
	var vals []frontend.Variable
	count := int(math.Pow(2, float64(k)))
	for i := 0; i < count; i++ {
		for j := 0; j < count; j++ {
			vals = append(vals, i^j)
		}
	}
	table := logderivlookup.New(api)
	for _, val := range vals {
		table.Insert(val)
	}
	log.Infof("inserted %d items into xor table", len(vals))
	return table
}

func newChiTable(api frontend.API, k int) *logderivlookup.Table {
	var vals []frontend.Variable
	count := int(math.Pow(2, float64(k)))
	for a := 0; a < count; a++ {
		for b := 0; b < count; b++ {
			for c := 0; c < count; c++ {
				vals = append(vals, ((^a)&b)^c)
			}
		}
	}
	table := logderivlookup.New(api)
	for _, val := range vals {
		table.Insert(val)
	}
	log.Infof("inserted %d items into chi table", len(vals))
	return table
}
