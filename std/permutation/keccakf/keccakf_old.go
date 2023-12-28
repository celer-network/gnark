// Package keccakf implements the KeccakF-1600 permutation function.
//
// This package exposes only the permutation primitive. For SHA3, SHAKE3 etc.
// functions it is necessary to apply the sponge construction. The constructions
// will be implemented in future in [github.com/consensys/gnark/std/hash/sha3]
// package.
//
// The cost for a single application of permutation is:
//   - 193650 constraints in Groth16
//   - 292032 constraints in Plonk
package keccakf

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

var rc_old = [24]xuint64{
	constUint64(0x0000000000000001),
	constUint64(0x0000000000008082),
	constUint64(0x800000000000808A),
	constUint64(0x8000000080008000),
	constUint64(0x000000000000808B),
	constUint64(0x0000000080000001),
	constUint64(0x8000000080008081),
	constUint64(0x8000000000008009),
	constUint64(0x000000000000008A),
	constUint64(0x0000000000000088),
	constUint64(0x0000000080008009),
	constUint64(0x000000008000000A),
	constUint64(0x000000008000808B),
	constUint64(0x800000000000008B),
	constUint64(0x8000000000008089),
	constUint64(0x8000000000008003),
	constUint64(0x8000000000008002),
	constUint64(0x8000000000000080),
	constUint64(0x000000000000800A),
	constUint64(0x800000008000000A),
	constUint64(0x8000000080008081),
	constUint64(0x8000000000008080),
	constUint64(0x0000000080000001),
	constUint64(0x8000000080008008),
}

// Permute applies Keccak-F permutation on the input a and returns the permuted
// vector. The input array must consist of 64-bit (unsigned) integers. The
// returned array also contains 64-bit unsigned integers.
func PermuteOld(api frontend.API, a [25]frontend.Variable) [25]frontend.Variable {
	var in [25]xuint64
	uapi := newUint64API(api)
	for i := range a {
		in[i] = uapi.asUint64(a[i])
	}
	res := permuteOld(api, in)
	var out [25]frontend.Variable
	for i := range out {
		out[i] = uapi.fromUint64(res[i])
	}
	return out
}

func permuteOld(api frontend.API, st [25]xuint64) [25]xuint64 {
	uapi := newUint64API(api)
	var t xuint64
	var bc [5]xuint64
	for r := 0; r < 24; r++ {
		// theta
		for i := 0; i < 5; i++ {
			bc[i] = uapi.xor(st[i], st[i+5], st[i+10], st[i+15], st[i+20])
		}
		for i := 0; i < 5; i++ {
			t = uapi.xor(bc[(i+4)%5], uapi.lrot(bc[(i+1)%5], 1))
			for j := 0; j < 25; j += 5 {
				st[j+i] = uapi.xor(st[j+i], t)
			}
		}
		// rho pi
		t = st[1]
		for i := 0; i < 24; i++ {
			j := piln[i]
			bc[0] = st[j]
			st[j] = uapi.lrot(t, rotc[i])
			t = bc[0]
		}

		// chi
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = st[j+i]
			}
			for i := 0; i < 5; i++ {
				st[j+i] = uapi.xor(st[j+i], uapi.and(uapi.not(bc[(i+1)%5]), bc[(i+2)%5]))
			}
		}
		// iota
		st[0] = uapi.xor(st[0], rc_old[r])
	}
	return st
}

// uint64api performs binary operations on xuint64 variables. In the
// future possibly using lookup tables.
//
// TODO: we could possibly optimise using hints if working over many inputs. For
// example, if we OR many bits, then the result is 0 if the sum of the bits is
// larger than 1. And AND is 1 if the sum of bits is the number of inputs. BUt
// this probably helps only if we have a lot of similar operations in a row
// (more than 4). We could probably unroll the whole permutation and expand all
// the formulas to see. But long term tables are still better.
type uint64api struct {
	api frontend.API
}

func newUint64API(api frontend.API) *uint64api {
	return &uint64api{
		api: api,
	}
}

// varUint64 represents 64-bit unsigned integer. We use this type to ensure that
// we work over constrained bits. Do not initialize directly, use [wideBinaryOpsApi.asUint64].
type xuint64 [64]frontend.Variable

func constUint64(a uint64) xuint64 {
	var res xuint64
	for i := 0; i < 64; i++ {
		res[i] = (a >> i) & 1
	}
	return res
}

func (w *uint64api) asUint64(in frontend.Variable) xuint64 {
	bits := bits.ToBinary(w.api, in, bits.WithNbDigits(64))
	var res xuint64
	copy(res[:], bits)
	return res
}

func (w *uint64api) fromUint64(in xuint64) frontend.Variable {
	return bits.FromBinary(w.api, in[:], bits.WithUnconstrainedInputs())
}

func (w *uint64api) and(in ...xuint64) xuint64 {
	var res xuint64
	for i := range res {
		res[i] = 1
	}
	for i := range res {
		for _, v := range in {
			res[i] = w.api.And(res[i], v[i])
		}
	}
	return res
}

func (w *uint64api) xor(in ...xuint64) xuint64 {
	var res xuint64
	for i := range res {
		res[i] = 0
	}
	for i := range res {
		for _, v := range in {
			res[i] = w.api.Xor(res[i], v[i])
		}
	}
	return res
}

func (w *uint64api) lrot(in xuint64, shift int) xuint64 {
	var res xuint64
	for i := range res {
		res[i] = in[(i-shift+64)%64]
	}
	return res
}

func (w *uint64api) not(in xuint64) xuint64 {
	// TODO: it would be better to have separate method for it. If we have
	// native API support, then in R1CS would be free (1-X) and in PLONK 1
	// constraint (1-X). But if we do XOR, then we always have a constraint with
	// R1CS (not sure if 1-2 with PLONK). If we do 1-X ourselves, then compiler
	// marks as binary which is 1-2 (R1CS-PLONK).
	var res xuint64
	for i := range res {
		res[i] = w.api.Xor(in[i], 1)
	}
	return res
}

func (w *uint64api) assertEq(a, b xuint64) {
	for i := range a {
		w.api.AssertIsEqual(a[i], b[i])
	}
}
