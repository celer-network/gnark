package groth16

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth162 "github.com/consensys/gnark/backend/groth16/bw6-761"
	groth16_bw6761 "github.com/consensys/gnark/backend/groth16/bw6-761"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	plonk2 "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/rs/zerolog"
	"log"
	"os"
	"testing"
	"time"
)

func Test377To761To254(t *testing.T) {
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}
	lo := zerolog.New(output).With().Timestamp().Logger()
	logger.Set(lo)
	assert := test.NewAssert(t)
	computeBn254(assert)
}

func computeBn254(assert *test.Assert) {
	_, innerVK, innerWitness, innerProof, commitPubFr := getBLS12InBW6(assert)
	// outer proof
	fmt.Printf("getBLS12InBW6 done \n")
	circuitVk, err := ValueOfVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bw6761.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof)
	assert.NoError(err)

	circuitCommitment, err := ValueOfProofCommitment[sw_bw6761.G1Affine](innerProof)
	assert.NoError(err)

	circuitWitness.Public = append(circuitWitness.Public, sw_bw6761.NewScalar(commitPubFr))

	/*outerCircuit := &OuterCircuit3[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: circuitWitness,
		VerifyingKey: circuitVk,
		Commitment:   circuitCommitment,
		N:            1,
		Q:            2,
	}*/
	outerAssignment := &OuterCircuit3[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
		Commitment:   circuitCommitment,
		N:            1,
		Q:            2,
	}

	pWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	fmt.Printf("witness done")

	err = test.IsSolved(outerAssignment, outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatalln(err)
	}

	// test plonk
	pccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, outerAssignment)
	assert.NoError(err)
	fmt.Printf("ccs: %d", pccs.GetNbConstraints())

	srs, srsLagrange, err := unsafekzg.NewSRS(pccs)
	assert.NoError(err)

	ppk, pvk, err := plonk.Setup(pccs, srs, srsLagrange)
	assert.NoError(err)

	fmt.Printf("start prove %v", time.Now())
	pProof, err := plonk.Prove(pccs, ppk, pWitness, plonk2.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField()))
	fmt.Printf("end prove %v", time.Now())
	assert.NoError(err)
	pPubWitness, err := pWitness.Public()
	assert.NoError(err)
	err = plonk.Verify(pProof, pvk, pPubWitness, plonk2.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField()))
	assert.NoError(err)
	//assert.CheckCircuit(outerCircuit, test.WithValidAssignment(outerAssignment), test.WithCurves(ecc.BN254))
}

func getBLS12InBW6(assert *test.Assert) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof, fr_bw6761.Element) {
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

	//assert.CheckCircuit(outerCircuit, test.WithValidAssignment(outerAssignment), test.WithCurves(ecc.BW6_761))

	aggWitness, err := frontend.NewWitness(outerAssignment, field)
	assert.NoError(err)
	aggCcs, err := frontend.Compile(field, r1cs.NewBuilder, outerCircuit)
	assert.NoError(err)
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

	w, ok := aggPubWitness.Vector().(fr_bw6761.Vector)
	if !ok {
		log.Fatalln(err)
	}
	commitPub, err := groth162.VerifyBW761ExportCommitPub(aggProof.(*groth16_bw6761.Proof), vk.(*groth16_bw6761.VerifyingKey), w)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("%+v", commitPub)

	//aggPubWitness = append(aggPubWitness, commitPub)

	return aggCcs, vk, aggPubWitness, aggProof, commitPub
}

type OuterCircuit2[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        Proof[G1El, G2El]
	VerifyingKey VerifyingKey[G1El, G2El, GtEl]
	InnerWitness Witness[FR]
	N            frontend.Variable `gnark:",public"`
	Q            frontend.Variable `gnark:",public"`
}

func (c *OuterCircuit2[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	verifier := NewVerifier(curve, pairing)
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	//err = verifier.AssertProof(c.VerifyingKey, c.Proof[1], c.InnerWitness[1])
	api.AssertIsEqual(c.N, 1)
	api.AssertIsEqual(c.Q, 2)
	return err
}

/*func TestBN254ToBN254Sol(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BN254.ScalarField())
	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bn254.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit2[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		VerifyingKey: PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
		N:            1,
		Q:            2,
	}
	outerAssignment := &OuterCircuit2[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
		N:            1,
		Q:            2,
	}

	field := ecc.BN254.ScalarField()
	outerCcs, err := frontend.Compile(field, r1cs.NewBuilder, outerCircuit)
	assert.NoError(err)

	fmt.Printf("nb cs: %d \n", outerCcs.GetNbConstraints())

	outerWitness, err := frontend.NewWitness(outerAssignment, field)
	assert.NoError(err)
	outerPubWitness, err := outerWitness.Public()
	assert.NoError(err)

	fmt.Printf("Start to setup pk \n")
	var pk = groth16.NewProvingKey(ecc.BN254)
	var vk = groth16.NewVerifyingKey(ecc.BN254)
	err1 := ReadVerifyingKey("test_bn254_em_circuit.vk", vk)
	err2 := ReadProvingKey("test_bn254_em_circuit.pk", pk)
	if err1 != nil || err2 != nil {
		fmt.Printf("Failed to read pk and vk, and try create, %v, %v \n", err1, err2)
		pk, vk, err = groth16.Setup(outerCcs)
		if err != nil {
			log.Fatalln(err)
		}
		err = WriteProvingKey(pk, "test_bn254_em_circuit.pk")
		if err != nil {
			log.Fatalln(err)
		}
		err = WriteVerifyingKey(vk, "test_bn254_em_circuit.vk")
		if err != nil {
			log.Fatalln(err)
		}
	}

	outerProof, err := groth16.Prove(outerCcs, pk, outerWitness)
	assert.NoError(err)
	err = groth16.Verify(outerProof, vk, outerPubWitness)
	assert.NoError(err)

	f, err := os.Create("test_bn254_em_circuit.sol")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	vk.ExportSolidity(f)
}*/

func ReadVerifyingKey(filename string, vk groth16.VerifyingKey) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = vk.UnsafeReadFrom(f)
	return err
}

func ReadProofFromLocalFile(filename string, proof groth16.Proof) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = proof.ReadFrom(f)
	return err
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

func WriteProvingKey(pk groth16.ProvingKey, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	_, err = pk.WriteTo(f)
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}

func WriteVerifyingKey(vk groth16.VerifyingKey, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	_, err = vk.WriteTo(f)
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}

func WriteProof(proof groth16.Proof, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = proof.WriteRawTo(f)
	if err != nil {
		return err
	}
	return nil
}

// for emulated outer circuit
type OuterCircuit3[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        Proof[G1El, G2El]
	Commitment   G1El
	VerifyingKey VerifyingKey[G1El, G2El, GtEl]
	InnerWitness Witness[FR]
	N            frontend.Variable `gnark:",public"`
	Q            frontend.Variable `gnark:",public"`
}

func (c *OuterCircuit3[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	verifier := NewVerifier(curve, pairing)
	err = verifier.AssertProofWithCommitment(c.VerifyingKey, c.Proof, c.Commitment, c.InnerWitness)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.N, 1)
	api.AssertIsEqual(c.Q, 2)
	return err
}
