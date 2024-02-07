package mimc

import (
	"math/big"
	"os"
	"testing"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	bw6761_mimc "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
)

func TestUnstableConstraint(t *testing.T) {
	assert := test.NewAssert(t)
	InitDmW()
	ProcessOne(assert, 20, true)
	ProcessOne(assert, 20, false)

	ProcessOne(assert, 60, true)
	ProcessOne(assert, 60, false)
}

func ProcessOne(assert *test.Assert, maxBatchSize int, useSameWitness bool) {
	var inputToggles []frontend.Variable
	var testWitness []regroth16.Witness[sw_bls12377.ScalarField]
	var hashData []byte

	data_dummy := common.Hex2Bytes("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001")
	data_0 := common.Hex2Bytes("000000000000000000000000000000000d18664e5d81ae189691059eb11c8130d4c30a3dfd73455c368036162f6a0e10")
	dm := GetW0(assert)
	for i := 0; i < maxBatchSize; i++ {
		if i == 0 || i == 1 {
			inputToggles = append(inputToggles, 1)
			testWitness = append(testWitness, GetW0(assert))
			hashData = append(hashData, data_0...)
		} else {
			inputToggles = append(inputToggles, 0)
			if useSameWitness {
				testWitness = append(testWitness, dm)
			} else {
				testWitness = append(testWitness, GetW0(assert))
			}
			hashData = append(hashData, data_dummy...)
		}
	}

	hash := bw6761_mimc.NewMiMC()
	hash.Write(hashData)

	commitHash := hash.Sum(nil)

	circuit := &BatchCircuit{
		maxBatchSize: maxBatchSize,
		InnerWitness: testWitness,
		InputToggles: inputToggles,
		CommitHash:   commitHash,
	}

	assigment := &BatchCircuit{
		maxBatchSize: maxBatchSize,
		InnerWitness: testWitness,
		InputToggles: inputToggles,
		CommitHash:   commitHash,
	}

	err := test.IsSolved(circuit, assigment, ecc.BW6_761.ScalarField())
	assert.NoError(err)

	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, circuit)
	assert.NoError(err)

	log.Infof("maxBatchSize %d, useSameWitness: %v, ccs GetNbConstraints: %d", maxBatchSize, useSameWitness, ccs.GetNbConstraints())
}

func GetW0(assert *test.Assert) regroth16.Witness[sw_bls12377.ScalarField] {
	witness0, err := witness.New(ecc.BLS12_377.ScalarField())
	assert.NoError(err)

	err = ReadWitness("./dummy_proof/0x0d18664e5d81ae189691059eb11c8130d4c30a3dfd73455c368036162f6a0e10_pi", witness0)
	assert.NoError(err)

	w0, err := regroth16.ValueOfWitness[sw_bls12377.ScalarField](witness0)
	assert.NoError(err)

	return w0
}

var dmW regroth16.Witness[sw_bls12377.ScalarField]

func InitDmW() {
	dummyWitness, err := witness.New(ecc.BLS12_377.ScalarField())
	if err != nil {
		log.Fatalln(err)
	}

	err = ReadWitness("./dummy_proof/dummy.witness", dummyWitness)
	if err != nil {
		log.Fatalln(err)
	}

	dmW, err = regroth16.ValueOfWitness[sw_bls12377.ScalarField](dummyWitness)
	if err != nil {
		log.Fatalln(err)
	}
}

func SelectDummyProof(
	api frontend.API,
	isDummy frontend.Variable,
	realWitness regroth16.Witness[sw_bls12377.ScalarField],
) (
	w regroth16.Witness[sw_bls12377.ScalarField], err error) {
	var pbs []emulated.Element[sw_bls12377.ScalarField]

	for i := 0; i < len(realWitness.Public); i++ {
		var limbs []frontend.Variable
		for j := 0; j < len(realWitness.Public[i].Limbs); j++ {
			selectLimb := api.Select(isDummy, dmW.Public[i].Limbs[j], realWitness.Public[i].Limbs[j])
			limbs = append(limbs, selectLimb)
		}
		em := emulated.Element[sw_bls12377.ScalarField]{
			Limbs: limbs,
		}
		pbs = append(pbs, em)
	}

	w = regroth16.Witness[sw_bls12377.ScalarField]{
		Public: pbs,
	}
	return
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

type BatchCircuit struct {
	maxBatchSize int
	InnerWitness []regroth16.Witness[sw_bls12377.ScalarField]
	InputToggles []frontend.Variable
	CommitHash   frontend.Variable `gnark:",public"`
}

func (c *BatchCircuit) Define(api frontend.API) error {
	return c.AssertSubProofs(api)
}

func (c *BatchCircuit) AssertSubProofs(api frontend.API) error {
	var innerWitnesses []regroth16.Witness[sw_bls12377.ScalarField]
	for i := 0; i < c.maxBatchSize; i++ {
		innerWitness, selectErr := SelectDummyProof(api, api.Select(c.InputToggles[i], 0, 1), c.InnerWitness[i])
		if selectErr != nil {
			return selectErr
		}
		innerWitnesses = append(innerWitnesses, innerWitness)
	}

	// verify agg hash
	mimcHash, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	for _, cm := range innerWitnesses {
		h0 := cm.Public[0].Limbs[3]
		h1 := cm.Public[0].Limbs[2]
		h2 := cm.Public[0].Limbs[1]
		h3 := cm.Public[0].Limbs[0]

		h0 = api.Mul(h0, big.NewInt(1).Lsh(big.NewInt(1), 192))
		h1 = api.Mul(h1, big.NewInt(1).Lsh(big.NewInt(1), 128))
		h2 = api.Mul(h2, big.NewInt(1).Lsh(big.NewInt(1), 64))
		res := api.Add(h0, h1, h2, h3)

		mimcHash.Write(res)
	}

	commitMimc := mimcHash.Sum()
	api.AssertIsEqual(commitMimc, c.CommitHash)

	return nil
}
