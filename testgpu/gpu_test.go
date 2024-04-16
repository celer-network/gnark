package testgpu

import (
	"fmt"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	cs_254 "github.com/consensys/gnark/constraint/bn254"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
)

func ReadProvingKey(filename string, pk groth16.ProvingKey) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = pk.UnsafeReadFrom(f)
	return err
}

func WriteProvingKey(pk groth16.ProvingKey, filename string) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Errorf("pk writing open failed... ")
	}
	_, err = pk.WriteTo(f)
	if err != nil {
		fmt.Errorf("pk writing failed... ")
	}
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

func WriteVerifyingKey(vk groth16.VerifyingKey, filename string) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Errorf("vk writing failed... ")
	}

	_, err = vk.WriteTo(f)
	if err != nil {
		fmt.Errorf("vk writing failed... ")
	}
}

func WriteCcs(ccs constraint.ConstraintSystem, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = ccs.WriteTo(f)
	if err != nil {
		return err
	}
	return nil
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

func LoadOrGenPkVkForTest(ccs constraint.ConstraintSystem, curveID ecc.ID, name string) (groth16.ProvingKey, groth16.VerifyingKey) {
	fmt.Printf("Start to setup pk \n")
	var err error
	pkFileName := fmt.Sprintf("%s.pk", name)
	vkFileName := fmt.Sprintf("%s.vk", name)
	var pk = groth16.NewProvingKey(curveID)
	var vk = groth16.NewVerifyingKey(curveID)
	err1 := ReadProvingKey(pkFileName, pk)
	err2 := ReadVerifyingKey(vkFileName, vk)
	if err1 != nil || err2 != nil {
		fmt.Printf("Failed to read pk and vk, and try create, %v, %v \n", err1, err2)
		pk, vk, err = groth16.Setup(ccs)
		if err != nil {
			fmt.Errorf("e: %v", err)
		}
		WriteProvingKey(pk, pkFileName)
		WriteVerifyingKey(vk, vkFileName)
	}
	return pk, vk
}

func LoadOrGenCcsBN254ForTest(filename string, circuit frontend.Circuit) *cs_254.R1CS {
	filename = fmt.Sprintf("%s.ccs", filename)
	loadCcs := new(cs_254.R1CS)
	err := ReadCcs(filename, loadCcs)
	if err == nil {
		fmt.Printf("load 254 ccs success: %s \n", filename)
		return loadCcs
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Errorf("e: %v", err)
	}

	err = WriteCcs(ccs, filename)
	if err != nil {
		fmt.Errorf("e: %v", err)
	}

	err = ReadCcs(filename, loadCcs)
	if err != nil {
		fmt.Errorf("e: %v", err)
	}
	return loadCcs
}

func TestBn254Gpu(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)
	getInner(assert, ecc.BN254.ScalarField())
	getInnerCommitment(assert, ecc.BN254.ScalarField(), ecc.BN254.ScalarField())
}

func TestBls12377Gpu(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)
	getInner(assert, ecc.BLS12_377.ScalarField())
	getInnerCommitment(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())
}

func TestBw6761Gpu(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)
	getInner(assert, ecc.BW6_761.ScalarField())
	getInnerCommitment(assert, ecc.BW6_761.ScalarField(), ecc.BN254.ScalarField())
}

func TestBn254VerifyBw6761(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)
	ccs, vk, pubW, proof := getInnerCommitment(assert, ecc.BW6_761.ScalarField(), ecc.BN254.ScalarField())

	circuit := &OuterBN254Circuit{
		P:            3,
		Q:            5,
		N:            15,
		Proof:        regroth16.PlaceholderProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](ccs),
		VerifyingKey: regroth16.PlaceholderVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](ccs),
		InnerWitness: regroth16.PlaceholderWitness[sw_bw6761.ScalarField](ccs),
	}

	p, err := regroth16.ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](proof)
	assert.NoError(err)
	v, err := regroth16.ValueOfVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](vk)
	assert.NoError(err)
	w, err := regroth16.ValueOfWitness[sw_bw6761.ScalarField](pubW)
	assert.NoError(err)

	assigment := &OuterBN254Circuit{
		P:            3,
		Q:            5,
		N:            15,
		Proof:        p,
		VerifyingKey: v,
		InnerWitness: w,
	}

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	assert.NoError(err)

	fileName := "outer_circuit"

	outerCcs := LoadOrGenCcsBN254ForTest(fileName, circuit)
	outerPK, outerVK := LoadOrGenPkVkForTest(outerCcs, ecc.BN254, fileName)
	outerWitness, err := frontend.NewWitness(assigment, ecc.BN254.ScalarField())
	assert.NoError(err)
	outerProof, err := groth16.Prove(outerCcs, outerPK, outerWitness, backend.WithIcicleAcceleration())
	assert.NoError(err)
	outerPubWitness, err := outerWitness.Public()
	assert.NoError(err)
	err = groth16.Verify(outerProof, outerVK, outerPubWitness)
	assert.NoError(err)
}

type InnerCircuit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuit) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	return nil
}

func getInner(assert *test.Assert, field *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuit{})
	assert.NoError(err)
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuit{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness, backend.WithIcicleAcceleration())
	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = groth16.Verify(innerProof, innerVK, innerPubWitness)
	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}

type InnerCircuitCommitment struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitCommitment) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)

	commitment, err := api.Compiler().(frontend.Committer).Commit(c.P, c.Q, c.N)
	if err != nil {
		return err
	}

	api.AssertIsDifferent(commitment, 0)

	return nil
}

func getInnerCommitment(assert *test.Assert, field, outer *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuitCommitment{})
	assert.NoError(err)
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitCommitment{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness, backend.WithIcicleAcceleration(), regroth16.GetNativeProverOptions(outer, field))
	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = groth16.Verify(innerProof, innerVK, innerPubWitness, regroth16.GetNativeVerifierOptions(outer, field))
	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}

type OuterBN254Circuit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`

	Proof        regroth16.Proof[sw_bw6761.G1Affine, sw_bw6761.G2Affine]
	VerifyingKey regroth16.VerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]
	InnerWitness regroth16.Witness[sw_bw6761.ScalarField]
}

func (c *OuterBN254Circuit) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	verifier, err := regroth16.NewVerifier[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	err = verifier.AssertProofBrevis(c.VerifyingKey, c.Proof, c.InnerWitness)
	if err != nil {
		return err
	}
	return verifier.AssertProofBrevis(c.VerifyingKey, c.Proof, c.InnerWitness)
}
