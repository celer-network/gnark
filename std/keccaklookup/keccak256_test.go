package keccaklookup

import (
	"bytes"
	"fmt"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend/cs/scs"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/limbs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type TestKeccak256Circuit struct {
	Data []frontend.Variable
	Out  []frontend.Variable
	k    int
}

func (c *TestKeccak256Circuit) Define(api frontend.API) error {
	ka := NewAPI(api, c.k)
	res := ka.Keccak256(1, 1, 1, 0, c.Data)
	api.AssertIsEqual(len(res), len(c.Out))
	for i := range res {
		api.AssertIsEqual(res[i], c.Out[i])
	}
	return nil
}

func genTestDdata() ([]frontend.Variable, []frontend.Variable) {
	data, _ := hexutil.Decode("0xff00000000000000000000000000000000000000000000000000000000000010ff")
	hash, _ := hexutil.Decode("0x746cc57064795780b008312042c24f949ad9dc0ee2dce9f4828f5a8869ccecca")

	padded := Pad101Bytes(data)
	paddedBits := Bytes2BlockBits(padded)
	out := Bytes2Bits(hash)
	if len(out) != 256 {
		panic(fmt.Sprintf("out len %d", len(out)))
	}
	var outVars []frontend.Variable
	for _, v := range out {
		outVars = append(outVars, frontend.Variable(v))
	}
	var dataBits []frontend.Variable
	// convert int array to frontend.Variable array
	for _, b := range paddedBits {
		dataBits = append(dataBits, b)
	}
	// fill the rest with 0s
	zerosToPad := 1088 - len(dataBits)
	for i := 0; i < zerosToPad; i++ {
		dataBits = append(dataBits, 0)
	}
	return dataBits, outVars
}

func TestKeccak256(t *testing.T) {
	assert := test.NewAssert(t)
	dataBits, outVars := genTestDdata()
	_dataBits := make([]frontend.Variable, len(dataBits))
	copy(_dataBits, dataBits)
	_outVars := make([]frontend.Variable, len(outVars))
	copy(_outVars, outVars)
	c := &TestKeccak256Circuit{
		Data: _dataBits,
		Out:  _outVars,
		k:    4,
	}
	w := &TestKeccak256Circuit{
		Data: dataBits,
		Out:  outVars,
		k:    4,
	}

	err := test.IsSolved(c, w, ecc.BN254.ScalarField())
	assert.NoError(err)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, c)
	assert.NoError(err)
	log.Infof("ccs: %d", ccs.GetNbConstraints())

	//assert.ProverSucceeded(
	//	c, w,
	//	test.WithSolverOpts(solver.WithHints(limbs.SplitHint)),
	//	test.WithCurves(ecc.BN254),
	//	test.WithBackends(backend.GROTH16),
	//)
}

func TestSolidityExport(t *testing.T) {
	assert := test.NewAssert(t)
	dataBits, outVars := genTestDdata()
	circuit := &TestKeccak256Circuit{
		Data: make([]frontend.Variable, len(dataBits)),
		Out:  make([]frontend.Variable, len(outVars)),
		k:    4,
	}
	witness := &TestKeccak256Circuit{
		Data: dataBits,
		Out:  outVars,
		k:    4,
	}
	fmt.Println("compile")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	assert.NoError(err)
	fmt.Println("constraints", cs.GetNbConstraints())

	fmt.Println("setup")
	pk, _vk, err := groth16.Setup(cs)
	assert.NoError(err)
	vk := _vk.(*groth16_bn254.VerifyingKey)
	printVk(vk)

	fmt.Println("gen witness")
	w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)

	fmt.Println("prove")
	solverOpt := solver.WithHints(limbs.SplitHint)
	_proof, err := groth16.Prove(cs, pk, w, backend.WithSolverOptions(solverOpt))
	assert.NoError(err)
	proof := _proof.(*groth16_bn254.Proof)
	exportProof(proof)

	fmt.Println("verify")
	err = groth16.Verify(proof, vk, pw)
	assert.NoError(err)

	fmt.Println("solidity gen")
	f, err := os.Create("KeccakVerifier.sol")
	assert.NoError(err)
	defer f.Close()
	err = vk.ExportSolidity(f)
	assert.NoError(err)
	panic("")
}

func exportProof(proof groth16.Proof) (a [2]*big.Int, b [2][2]*big.Int, c [2]*big.Int, commitments [][2]*big.Int, commitmentPok [2]*big.Int) {
	var buf bytes.Buffer
	const fpSize = 4 * 8
	_, err := proof.WriteRawTo(&buf)
	if err != nil {
		fmt.Print(err)
	}
	proofBytes := buf.Bytes()

	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	p := proof.(*groth16_bn254.Proof)
	fmt.Printf("len commitment %d \n", len(p.Commitments))
	commitments = make([][2]*big.Int, len(p.Commitments))
	for i := range commitments {
		commitments[i][0] = new(big.Int)
		commitments[i][1] = new(big.Int)
		p.Commitments[0].X.BigInt(commitments[i][0])
		p.Commitments[0].Y.BigInt(commitments[i][1])
	}
	return
}

func printVk(vk *groth16_bn254.VerifyingKey) {
	fmt.Printf("vk.G1.Alpha %s\n", &vk.G1.Alpha)
	for i, k := range vk.G1.K {
		kk := k
		kp := &kk
		fmt.Printf("vk.G1.K[%d] %s\n", i, kp)
	}
	fmt.Println("len vk.PublicAndCommitmentCommitted:", len(vk.PublicAndCommitmentCommitted))
	for _, vi := range vk.PublicAndCommitmentCommitted {
		fmt.Println(vi)
	}
}

func Pad101Bytes(data []byte) []byte {
	miss := 136 - len(data)%136
	if len(data)%136 == 0 {
		miss = 136
	}
	data = append(data, 1)
	for i := 0; i < miss-1; i++ {
		data = append(data, 0)
	}
	data[len(data)-1] ^= 0x80
	return data
}

func Bytes2BlockBits(bytes []byte) (bits []uint8) {
	if len(bytes)%136 != 0 {
		panic("invalid length")
	}
	return Bytes2Bits(bytes)
}

func Bytes2Bits(bytes []byte) (bits []uint8) {
	if len(bytes)%8 != 0 {
		panic("invalid length")
	}
	for i := 0; i < len(bytes); i++ {
		bits = append(bits, byte2Bits(bytes[i])...)
	}
	return
}

// bytes2Bits outputs bits in little-endian
func byte2Bits(b byte) (bits []uint8) {
	for i := 0; i < 8; i++ {
		bits = append(bits, (uint8(b)>>i)&1)
	}
	return
}
