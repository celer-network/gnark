package groth16

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth163 "github.com/consensys/gnark/backend/groth16/bw6-761"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/test"
	"log"
	"testing"
)

func TestBLS377ToBW6761(t *testing.T) {
	assert := test.NewAssert(t)
	getBLS12InBW6_WithCommitment(assert)
	getBLS12InBW6_WithoutCommitment(assert)
}

func getBLS12InBW6_WithCommitment(assert *test.Assert) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	field := ecc.BW6_761.ScalarField()

	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BLS12_377.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit2[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerCcs),
		N:            1,
		Q:            2,
	}

	outerAssignment := &OuterCircuit2[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
		N:            1,
		Q:            2,
	}

	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
	if err != nil {
		log.Fatalln(err)
	}

	aggWitness, err := frontend.NewWitness(outerAssignment, field)
	assert.NoError(err)
	aggCcs, err := frontend.Compile(field, r1cs.NewBuilder, outerCircuit)
	assert.NoError(err)
	fmt.Printf("bw761 constraints: %d \n", aggCcs.GetNbConstraints())
	aggPubWitness, err := aggWitness.Public()
	assert.NoError(err)

	pk, vk, err := groth16.Setup(aggCcs)
	if err != nil {
		log.Fatalln(err)
	}

	aggProof, err := groth16.Prove(aggCcs, pk, aggWitness)
	assert.NoError(err)
	err = groth16.Verify(aggProof, vk, aggPubWitness)
	assert.NoError(err)
	fmt.Printf("bw761 commitment: %d \n", len(aggProof.(*groth163.Proof).Commitments))
	return aggCcs, vk, aggPubWitness, aggProof
}

func getBLS12InBW6_WithoutCommitment(assert *test.Assert) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	field := ecc.BW6_761.ScalarField()

	_, innerVK, innerWitness, innerProof := getInner(assert, ecc.BLS12_377.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerAssignment := &OuterCircuit2[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
		N:            1,
		Q:            2,
	}

	err = test.IsSolved(outerAssignment, outerAssignment, ecc.BW6_761.ScalarField())
	if err != nil {
		log.Fatalln(err)
	}

	aggWitness, err := frontend.NewWitness(outerAssignment, field)
	assert.NoError(err)
	aggCcs, err := frontend.Compile(field, r1cs.NewBuilder, outerAssignment)
	assert.NoError(err)
	fmt.Printf("bw761 constraints: %d \n", aggCcs.GetNbConstraints())
	aggPubWitness, err := aggWitness.Public()
	assert.NoError(err)

	pk, vk, err := groth16.Setup(aggCcs)
	if err != nil {
		log.Fatalln(err)
	}

	aggProof, err := groth16.Prove(aggCcs, pk, aggWitness)
	assert.NoError(err)
	err = groth16.Verify(aggProof, vk, aggPubWitness)
	assert.NoError(err)
	fmt.Printf("bw761 commitment: %d \n", len(aggProof.(*groth163.Proof).Commitments))
	return aggCcs, vk, aggPubWitness, aggProof
}
