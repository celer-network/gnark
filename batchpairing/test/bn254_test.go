package test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
)

func TestInnerBn254(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, vk, pubW, proof := getSecondInner(assert)

	circuitVk, err := regroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
	assert.NoError(err)
	circuitWitness, err := regroth16.ValueOfWitness[sw_bn254.ScalarField](pubW)
	assert.NoError(err)
	circuitProof, err := regroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](proof)
	assert.NoError(err)

	outerCircuit := &InnerSecondCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:        regroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](ccs),
		InnerWitness: regroth16.PlaceholderWitness[sw_bn254.ScalarField](ccs),
		VerifyingKey: regroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](ccs),
	}
	outerAssignment := &InnerSecondCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}

	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func getSecondInner(assert *test.Assert) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BN254.ScalarField())
	// outer proof
	circuitVk, err := regroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := regroth16.ValueOfWitness[sw_bn254.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := regroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &InnerSecondCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:        regroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		InnerWitness: regroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		VerifyingKey: regroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
	}
	outerAssignment := &InnerSecondCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	w, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	pubW, err := w.Public()
	assert.NoError(err)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outerCircuit)
	assert.NoError(err)

	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)

	proof, err := groth16.Prove(ccs, pk, w)
	assert.NoError(err)

	err = groth16.Verify(proof, vk, pubW)
	assert.NoError(err)

	return ccs, vk, pubW, proof
}

func getInner(assert *test.Assert, field *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerBN254Circuit{})
	assert.NoError(err)
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerBN254Circuit{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness)
	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = groth16.Verify(innerProof, innerVK, innerPubWitness)
	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}

type InnerBN254Circuit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerBN254Circuit) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	return nil
}

type InnerSecondCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        regroth16.Proof[G1El, G2El]
	VerifyingKey regroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness regroth16.Witness[FR]
}

func (c *InnerSecondCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := regroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
}
