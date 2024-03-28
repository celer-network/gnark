package testbn254

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestBrevisBn254(t *testing.T) {
	assert := test.NewAssert(t)

	subWitness, err := witness.New(ecc.BN254.ScalarField())
	assert.NoError(err)
	ReadWitness(assert, "emulated_bn254.witness", subWitness)
	assert.NoError(err)

	subVk := groth16.NewVerifyingKey(ecc.BN254)
	ReadVerifyingKey(assert, "emulated_bn254.vk", subVk)
	assert.NoError(err)

	subProof := groth16.NewProof(ecc.BN254)
	ReadProofFromLocalFile(assert, "emulated_bn254_mimc.proof", subProof)
	assert.NoError(err)
	err = groth16.Verify(subProof, subVk, subWitness, regroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	nbPublicVariables := 8
	commitmentsLen := 1
	publicAndCommitmentCommitted := [][]int{{}}

	circuit := &InnerBN254Circuit{
		Proof:        regroth16.PlaceholderProofWithParam[sw_bn254.G1Affine, sw_bn254.G2Affine](commitmentsLen),
		VerifyingKey: regroth16.PlaceholderVerifyingKeyWithParam[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](nbPublicVariables, commitmentsLen, publicAndCommitmentCommitted),
		InnerWitness: regroth16.PlaceholderWitnessWithParam[sw_bn254.ScalarField](nbPublicVariables),
	}

	assigment := &InnerBN254Circuit{}
	assigment.Proof, err = regroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](subProof)
	assert.NoError(err)
	assigment.VerifyingKey, err = regroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](subVk)
	assert.NoError(err)
	assigment.InnerWitness, err = regroth16.ValueOfWitness[sw_bn254.ScalarField](subWitness)
	assert.NoError(err)

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestInnerBn254(t *testing.T) {
	assert := test.NewAssert(t)

	subWitness, err := witness.New(ecc.BN254.ScalarField())
	assert.NoError(err)
	ReadWitness(assert, "inner_emulated_bn254.witness", subWitness)
	assert.NoError(err)

	subVk := groth16.NewVerifyingKey(ecc.BN254)
	ReadVerifyingKey(assert, "inner_emulated_bn254.vk", subVk)
	assert.NoError(err)

	subProof := groth16.NewProof(ecc.BN254)
	ReadProofFromLocalFile(assert, "inner_emulated_bn254.proof", subProof)
	assert.NoError(err)
	err = groth16.Verify(subProof, subVk, subWitness, regroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	nbPublicVariables := 1
	commitmentsLen := 1
	publicAndCommitmentCommitted := [][]int{{}}

	circuit := &InnerBN254Circuit{
		Proof:        regroth16.PlaceholderProofWithParam[sw_bn254.G1Affine, sw_bn254.G2Affine](commitmentsLen),
		VerifyingKey: regroth16.PlaceholderVerifyingKeyWithParam[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](nbPublicVariables, commitmentsLen, publicAndCommitmentCommitted),
		InnerWitness: regroth16.PlaceholderWitnessWithParam[sw_bn254.ScalarField](nbPublicVariables),
	}

	assigment := &InnerBN254Circuit{}
	assigment.Proof, err = regroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](subProof)
	assert.NoError(err)
	assigment.VerifyingKey, err = regroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](subVk)
	assert.NoError(err)
	assigment.InnerWitness, err = regroth16.ValueOfWitness[sw_bn254.ScalarField](subWitness)
	assert.NoError(err)
	
	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
