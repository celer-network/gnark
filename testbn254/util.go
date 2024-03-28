package testbn254

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	bn254_cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"os"
)

type InnerBN254Circuit struct {
	Proof        regroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey regroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	InnerWitness regroth16.Witness[sw_bn254.ScalarField]
}

func (c *InnerBN254Circuit) Define(api frontend.API) error {
	verifier, err := regroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
}

func WriteCcs(assert *test.Assert, filename string, ccs constraint.ConstraintSystem) {
	f, err := os.Create(filename)
	assert.NoError(err)
	defer f.Close()
	_, err = ccs.WriteTo(f)
	assert.NoError(err)
}

func ReadCcs(assert *test.Assert, filename string, ccs constraint.ConstraintSystem) {
	f, err := os.Open(filename)
	assert.NoError(err)
	defer f.Close()
	_, err = ccs.ReadFrom(f)
	assert.NoError(err)
}

func ReadVerifyingKey(assert *test.Assert, filename string, vk groth16.VerifyingKey) {
	f, err := os.Open(filename)
	assert.NoError(err)
	defer f.Close()

	_, err = vk.UnsafeReadFrom(f)
	assert.NoError(err)
}

func WriteVerifyingKey(assert *test.Assert, filename string, vk groth16.VerifyingKey) {
	f, err := os.Create(filename)
	assert.NoError(err)
	_, err = vk.WriteTo(f)
	assert.NoError(err)
}

func ReadProofFromLocalFile(assert *test.Assert, filename string, proof groth16.Proof) {
	f, err := os.Open(filename)
	assert.NoError(err)
	defer f.Close()

	_, err = proof.ReadFrom(f)
	assert.NoError(err)
}

func WriteProofIntoLocalFile(assert *test.Assert, filename string, proof groth16.Proof) {
	f, err := os.Create(filename)
	assert.NoError(err)
	defer f.Close()

	_, err = proof.WriteRawTo(f)
	assert.NoError(err)
}

func ReadWitness(assert *test.Assert, filename string, witness witness.Witness) {
	f, err := os.Open(filename)
	assert.NoError(err)
	defer f.Close()
	_, err = witness.ReadFrom(f)
	assert.NoError(err)
}

func WriteWitness(assert *test.Assert, filename string, witness witness.Witness) {
	f, err := os.Create(filename)
	assert.NoError(err)
	_, err = witness.WriteTo(f)
	assert.NoError(err)
}

func LoadProofData(assert *test.Assert, fileName string) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	pubW, err := witness.New(ecc.BN254.ScalarField())
	assert.NoError(err)
	ReadWitness(assert, fmt.Sprintf("%s.witness", fileName), pubW)

	vk := groth16.NewVerifyingKey(ecc.BN254)
	ReadVerifyingKey(assert, fmt.Sprintf("%s.vk", fileName), vk)
	assert.NoError(err)

	proof := groth16.NewProof(ecc.BN254)
	ReadProofFromLocalFile(assert, fmt.Sprintf("%s.proof", fileName), proof)

	ccs := new(bn254_cs.R1CS)
	ReadCcs(assert, fmt.Sprintf("%s.ccs", fileName), ccs)

	return ccs, vk, pubW, proof
}

func WriteProofData(assert *test.Assert, fileName string, ccs constraint.ConstraintSystem, vk groth16.VerifyingKey, pubW witness.Witness, proof groth16.Proof) {
	WriteCcs(assert, fmt.Sprintf("%s.ccs", fileName), ccs)
	WriteWitness(assert, fmt.Sprintf("%s.witness", fileName), pubW)
	WriteProofIntoLocalFile(assert, fmt.Sprintf("%s.proof", fileName), proof)
	WriteVerifyingKey(assert, fmt.Sprintf("%s.vk", fileName), vk)
}
