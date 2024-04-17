package testnebra

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"
	"os"
	"testing"
)

func TestVerifyBrevisInNebra(t *testing.T) {
	assert := test.NewAssert(t)

	w, err := witness.New(ecc.BN254.ScalarField())
	assert.NoError(err)

	err = ReadWitness("emulated_bn254.witness", w)
	assert.NoError(err)

	vk, err := LoadVk(ecc.BN254, "emulated_bn254.vk")
	assert.NoError(err)

	proof, err := LoadProof(ecc.BN254, "emulated_bn254.proof")
	assert.NoError(err)

	err = groth16.Verify(proof, vk, w, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
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

func LoadVk(curveID ecc.ID, filename string) (groth16.VerifyingKey, error) {
	var vk = groth16.NewVerifyingKey(curveID)
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	_, err = vk.UnsafeReadFrom(f)
	return vk, nil
}

func LoadProof(curveID ecc.ID, filename string) (groth16.Proof, error) {
	proof := groth16.NewProof(curveID)
	f, err := os.Open(filename)
	if err != nil {
		return proof, err
	}
	defer f.Close()

	_, err = proof.ReadFrom(f)
	return proof, err
}
