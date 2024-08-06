package limbs

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestLimbAPI(t *testing.T) {
	assert := test.NewAssert(t)
	c := &TestCircuit{
		Limbs: Limbs{
			parseBinary("10001001"),
			parseBinary("01010100"),
			parseBinary("11001101"),
		},
	}
	w := &TestCircuit{
		Limbs: Limbs{
			parseBinary("10001001"),
			parseBinary("01010100"),
			parseBinary("11001101"),
		},
	}
	assert.ProverSucceeded(
		c, w,
		test.WithSolverOpts(solver.WithHints(SplitHint)),
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

type TestCircuit struct {
	Limbs Limbs
}

func (c *TestCircuit) Define(api frontend.API) error {
	la := NewAPI(api)
	w := c.Limbs[0]
	split := la.Split(w, 8)
	checkLen(split, 1)
	api.AssertIsEqual(split.totalSize(), w.Size)
	api.AssertIsEqual(split[0].Val, parseBinary("10001001").Val)

	split = la.Split(w, 4)
	checkLen(split, 2)
	api.AssertIsEqual(split.totalSize(), w.Size)
	api.AssertIsEqual(split[0].Val, parseBinary("1000").Val)
	api.AssertIsEqual(split[0].Size, 4)
	api.AssertIsEqual(split[1].Val, parseBinary("1001").Val)
	api.AssertIsEqual(split[1].Size, 4)

	split = la.Split(w, 2, 2)
	checkLen(split, 3)
	api.AssertIsEqual(split.totalSize(), w.Size)
	api.AssertIsEqual(split[0].Val, parseBinary("10").Val)
	api.AssertIsEqual(split[0].Size, 2)
	api.AssertIsEqual(split[1].Val, parseBinary("00").Val)
	api.AssertIsEqual(split[1].Size, 2)
	api.AssertIsEqual(split[2].Val, parseBinary("1001").Val)
	api.AssertIsEqual(split[2].Size, 4)

	rotated := la.LrotMerge(c.Limbs, 1)
	api.AssertIsEqual(rotated.Size, 24)
	api.AssertIsEqual(rotated.Val, parseBinary("000100101010100110011011").Val)

	rs := la.Lrot(c.Limbs, 1, 8)
	checkLen(rs, 3)
	api.AssertIsEqual(rs.totalSize(), 24)
	api.AssertIsEqual(rs[0].Val, parseBinary("00010010").Val)
	api.AssertIsEqual(rs[0].Size, 8)
	api.AssertIsEqual(rs[1].Val, parseBinary("10101001").Val)
	api.AssertIsEqual(rs[1].Size, 8)
	api.AssertIsEqual(rs[2].Val, parseBinary("10011011").Val)
	api.AssertIsEqual(rs[2].Size, 8)

	m := la.Merge(c.Limbs)
	api.AssertIsEqual(m.Size, 24)
	api.AssertIsEqual(m.Val, parseBinary("100010010101010011001101").Val)
	return nil
}
