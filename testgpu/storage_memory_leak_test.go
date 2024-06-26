package testgpu

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_12377 "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/logger"
	groth162 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"

	"os"
	"testing"
)

func TestStorageMemoryLeakCircuitInGpuOnBls12377(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	fileName := "storage_with_mimc"

	assert := test.NewAssert(t)
	circuitWitness, err := witness.New(ecc.BLS12_377.ScalarField())
	assert.NoError(err)

	err = ReadWitness(fmt.Sprintf("%s.witness", fileName), circuitWitness)
	assert.NoError(err)

	pubW, err := circuitWitness.Public()
	assert.NoError(err)
	ccs := LoadOrGenCcsBLS12377ForTest(assert, fileName)

	pk, vk := LoadOrGenPkVkForTest(assert, ecc.BLS12_377, fileName)

	nativeProver := groth162.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())

	pf, err := groth16.Prove(ccs, pk, circuitWitness, nativeProver,
		/*backend.WithIcicleAcceleration(), backend.WithMultiGpuSelect([]int{4, 5, 5, 6, 6})*/)
	assert.NoError(err)

	nativeVerifierOptions := groth162.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	err = groth16.Verify(pf, vk, pubW, nativeVerifierOptions)
	assert.NoError(err)
}

func ReadWitness(filename string, witness witness.Witness) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = witness.ReadFrom(f)
	return err
}

func LoadOrGenCcsBLS12377ForTest(assert *test.Assert, filename string) *cs_12377.R1CS {
	filename = fmt.Sprintf("%s.ccs", filename)
	loadCcs := new(cs_12377.R1CS)
	err := ReadCcs(filename, loadCcs)
	assert.NoError(err)
	return loadCcs
}

func LoadOrGenPkVkForTest(assert *test.Assert, curveID ecc.ID, name string) (groth16.ProvingKey, groth16.VerifyingKey) {
	pkFileName := fmt.Sprintf("%s.pk", name)
	vkFileName := fmt.Sprintf("%s.vk", name)
	var pk = groth16.NewProvingKey(curveID)
	var vk = groth16.NewVerifyingKey(curveID)
	err := ReadProvingKey(pkFileName, pk)
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

func ReadCcs(filename string, ccs constraint.ConstraintSystem) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = ccs.ReadFrom(f)
	return err
}
