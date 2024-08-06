package keccaklookup

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/std/limbs"
)

func require(cond bool, format string, args ...interface{}) {
	if !cond {
		m := fmt.Sprintf(format, args...)
		panic(fmt.Sprintf("assert failed: %s", m))
	}
}

func checkLen[T any](arr []T, length int) {
	if len(arr) != length {
		panic(fmt.Sprintf("arr len %d, expected %d", len(arr), length))
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func exp2(num int) *big.Int {
	base := big.NewInt(2)
	exp := big.NewInt(int64(num))
	return new(big.Int).Exp(base, exp, nil)
}

func parseBinary(bs string) limbs.Limb {
	var sum uint64 = 0
	for i, c := range bs {
		var d uint64 = 0
		if c == '1' {
			d = 1
		}
		sum += d << (len(bs) - 1 - i)
	}
	return limbs.Limb{Val: sum, Size: len(bs)}
}
