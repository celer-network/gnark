package bw6761test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bw6761 "github.com/consensys/gnark/constraint/bw6-761"
	"github.com/consensys/gnark/test"
	"os"
	"testing"
)

func TestBw6761Reload(t *testing.T) {
	filename := "agg_with_mimc_20"
	assert := test.NewAssert(t)
	ccs := LoadOrGenCcsBW6761ForTest(assert, filename)
	pk, vk := LoadOrGenPkVkForTest(assert, ecc.BW6_761, filename)
	w := LoadWitness(assert, filename)
	wPub, err := w.Public()
	assert.NoError(err)
	proof, err := groth16.Prove(ccs, pk, w)
	assert.NoError(err)
	err = groth16.Verify(proof, vk, wPub)
	assert.NoError(err)
}

func LoadWitness(assert *test.Assert, filename string) witness.Witness {
	f, err := os.Open(fmt.Sprintf("%s.witness", filename))
	assert.NoError(err)

	defer f.Close()
	var w witness.Witness
	w, err = witness.New(ecc.BW6_761.ScalarField())
	assert.NoError(err)
	_, err = w.ReadFrom(f)
	assert.NoError(err)
	return w
}

func LoadOrGenPkVkForTest(assert *test.Assert, curveID ecc.ID, name string) (groth16.ProvingKey, groth16.VerifyingKey) {
	var err error
	pkFileName := fmt.Sprintf("%s.pk", name)
	vkFileName := fmt.Sprintf("%s.vk", name)
	var pk = groth16.NewProvingKey(curveID)
	var vk = groth16.NewVerifyingKey(curveID)
	err = ReadProvingKey(pkFileName, pk)
	assert.NoError(err)
	err = ReadVerifyingKey(vkFileName, vk)
	assert.NoError(err)
	return pk, vk
}

func ReadProvingKey(filename string, pk groth16.ProvingKey) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = pk.UnsafeReadFrom(f)
	return err
}

func ReadVerifyingKey(filename string, vk groth16.VerifyingKey) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = vk.UnsafeReadFrom(f)
	return err
}

func LoadOrGenCcsBW6761ForTest(assert *test.Assert, filename string) *cs_bw6761.R1CS {
	filename = fmt.Sprintf("%s.ccs", filename)
	loadCcs := new(cs_bw6761.R1CS)
	err := ReadCcs(filename, loadCcs)
	assert.NoError(err)
	return loadCcs
}

func ReadCcs(filename string, ccs constraint.ConstraintSystem) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = ccs.ReadFrom(f)
	return err
}
