//go:build icicle

package icicle_bls12377

import (
	"fmt"
	"math/big"
	"math/bits"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp/hash_to_field"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/pedersen"
	"github.com/consensys/gnark/backend"
	groth16_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	"github.com/consensys/gnark/backend/groth16/internal"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
	fcs "github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
	iciclegnark "github.com/ingonyama-zk/iciclegnark/curves/bls12377"
)

const HasIcicle = true

func SetupDevicePointers(pk *ProvingKey) error {
	// TODO, add lock here to make sure only init once
	return pk.setupDevicePointers()
}

func (pk *ProvingKey) setupDevicePointers() error {
	if pk.deviceInfo != nil {
		return nil
	}
	pk.deviceInfo = &deviceInfo{}
	n := int(pk.Domain.Cardinality)
	sizeBytes := n * fr.Bytes

	/*************************  Start Domain Device Setup  ***************************/
	copyCosetInvDone := make(chan unsafe.Pointer, 1)
	copyCosetDone := make(chan unsafe.Pointer, 1)
	copyDenDone := make(chan unsafe.Pointer, 1)
	/*************************     CosetTableInv      ***************************/
	go iciclegnark.CopyToDevice(pk.Domain.CosetTableInv, sizeBytes, copyCosetInvDone)

	/*************************     CosetTable      ***************************/
	go iciclegnark.CopyToDevice(pk.Domain.CosetTable, sizeBytes, copyCosetDone)

	/*************************     Den      ***************************/
	var denI, oneI fr.Element
	oneI.SetOne()
	denI.Exp(pk.Domain.FrMultiplicativeGen, big.NewInt(int64(pk.Domain.Cardinality)))
	denI.Sub(&denI, &oneI).Inverse(&denI)

	log2SizeFloor := bits.Len(uint(n)) - 1
	denIcicleArr := []fr.Element{denI}
	for i := 0; i < log2SizeFloor; i++ {
		denIcicleArr = append(denIcicleArr, denIcicleArr...)
	}
	pow2Remainder := n - 1<<log2SizeFloor
	for i := 0; i < pow2Remainder; i++ {
		denIcicleArr = append(denIcicleArr, denI)
	}

	go iciclegnark.CopyToDevice(denIcicleArr, sizeBytes, copyDenDone)

	/*************************     Twiddles and Twiddles Inv    ***************************/
	twiddlesInv_d_gen, twddles_err := iciclegnark.GenerateTwiddleFactors(n, true)
	if twddles_err != nil {
		return twddles_err
	}

	twiddles_d_gen, twddles_err := iciclegnark.GenerateTwiddleFactors(n, false)
	if twddles_err != nil {
		return twddles_err
	}

	/*************************  End Domain Device Setup  ***************************/
	pk.DomainDevice.Twiddles = twiddles_d_gen
	pk.DomainDevice.TwiddlesInv = twiddlesInv_d_gen

	pk.DomainDevice.CosetTableInv = <-copyCosetInvDone
	pk.DomainDevice.CosetTable = <-copyCosetDone
	pk.DenDevice = <-copyDenDone

	/*************************  Start G1 Device Setup  ***************************/
	/*************************     A      ***************************/
	pointsBytesA := len(pk.G1.A) * fp.Bytes * 2
	copyADone := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyPointsToDevice(pk.G1.A, pointsBytesA, copyADone) // Make a function for points

	/*************************     B      ***************************/
	pointsBytesB := len(pk.G1.B) * fp.Bytes * 2
	copyBDone := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyPointsToDevice(pk.G1.B, pointsBytesB, copyBDone) // Make a function for points

	/*************************     K      ***************************/
	var pointsNoInfinity []curve.G1Affine
	for i, gnarkPoint := range pk.G1.K {
		if gnarkPoint.IsInfinity() {
			pk.InfinityPointIndicesK = append(pk.InfinityPointIndicesK, i)
		} else {
			pointsNoInfinity = append(pointsNoInfinity, gnarkPoint)
		}
	}

	pointsBytesK := len(pointsNoInfinity) * fp.Bytes * 2
	copyKDone := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyPointsToDevice(pointsNoInfinity, pointsBytesK, copyKDone) // Make a function for points

	/*************************     Z      ***************************/
	pointsBytesZ := len(pk.G1.Z) * fp.Bytes * 2
	copyZDone := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyPointsToDevice(pk.G1.Z, pointsBytesZ, copyZDone) // Make a function for points

	/*************************  End G1 Device Setup  ***************************/
	pk.G1Device.A = <-copyADone
	pk.G1Device.B = <-copyBDone
	pk.G1Device.K = <-copyKDone
	pk.G1Device.Z = <-copyZDone

	/*************************  Start G2 Device Setup  ***************************/
	pointsBytesB2 := len(pk.G2.B) * fp.Bytes * 4
	copyG2BDone := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyG2PointsToDevice(pk.G2.B, pointsBytesB2, copyG2BDone) // Make a function for points
	pk.G2Device.B = <-copyG2BDone

	/*************************  End G2 Device Setup  ***************************/
	return nil
}

func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*groth16_bls12377.Proof, error) {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new prover config: %w", err)
	}
	if opt.HashToFieldFn == nil {
		opt.HashToFieldFn = hash_to_field.New([]byte(constraint.CommitmentDst))
	}
	if opt.Accelerator != "icicle" {
		return groth16_bls12377.Prove(r1cs, &pk.ProvingKey, fullWitness, opts...)
	}

	log := logger.Logger().With().Str("curve", r1cs.CurveID().String()).Str("acceleration", "icicle").Int("nbConstraints", r1cs.GetNbConstraints()).Str("backend", "groth16").Logger()
	if pk.deviceInfo == nil {
		log.Debug().Msg("precomputing proving key in GPU")
		if err := pk.setupDevicePointers(); err != nil {
			return nil, fmt.Errorf("setup device pointers: %w", err)
		}
	}

	commitmentInfo := r1cs.CommitmentInfo.(constraint.Groth16Commitments)

	proof := &groth16_bls12377.Proof{Commitments: make([]curve.G1Affine, len(commitmentInfo))}

	solverOpts := opt.SolverOpts[:len(opt.SolverOpts):len(opt.SolverOpts)]

	privateCommittedValues := make([][]fr.Element, len(commitmentInfo))

	// override hints
	bsb22ID := solver.GetHintID(fcs.Bsb22CommitmentComputePlaceholder)
	solverOpts = append(solverOpts, solver.OverrideHint(bsb22ID, func(_ *big.Int, in []*big.Int, out []*big.Int) error {
		i := int(in[0].Int64())
		in = in[1:]
		privateCommittedValues[i] = make([]fr.Element, len(commitmentInfo[i].PrivateCommitted))
		hashed := in[:len(commitmentInfo[i].PublicAndCommitmentCommitted)]
		committed := in[+len(hashed):]
		for j, inJ := range committed {
			privateCommittedValues[i][j].SetBigInt(inJ)
		}

		var err error
		if proof.Commitments[i], err = pk.CommitmentKeys[i].Commit(privateCommittedValues[i]); err != nil {
			return err
		}

		opt.HashToFieldFn.Write(constraint.SerializeCommitment(proof.Commitments[i].Marshal(), hashed, (fr.Bits-1)/8+1))
		hashBts := opt.HashToFieldFn.Sum(nil)
		opt.HashToFieldFn.Reset()
		nbBuf := fr.Bytes
		if opt.HashToFieldFn.Size() < fr.Bytes {
			nbBuf = opt.HashToFieldFn.Size()
		}
		var res fr.Element
		res.SetBytes(hashBts[:nbBuf])
		res.BigInt(out[0])
		return nil
	}))

	if r1cs.GkrInfo.Is() {
		var gkrData cs.GkrSolvingData
		solverOpts = append(solverOpts,
			solver.OverrideHint(r1cs.GkrInfo.SolveHintID, cs.GkrSolveHint(r1cs.GkrInfo, &gkrData)),
			solver.OverrideHint(r1cs.GkrInfo.ProveHintID, cs.GkrProveHint(r1cs.GkrInfo.HashName, &gkrData)))
	}

	_solution, err := r1cs.Solve(fullWitness, solverOpts...)
	if err != nil {
		return nil, err
	}

	solution := _solution.(*cs.R1CSSolution)
	wireValues := []fr.Element(solution.W)

	commitmentsSerialized := make([]byte, fr.Bytes*len(commitmentInfo))
	for i := range commitmentInfo {
		copy(commitmentsSerialized[fr.Bytes*i:], wireValues[commitmentInfo[i].CommitmentIndex].Marshal())
	}

	if proof.CommitmentPok, err = pedersen.BatchProve(pk.CommitmentKeys, privateCommittedValues, commitmentsSerialized); err != nil {
		return nil, err
	}

	// sample random r and s
	var r, s big.Int
	var _r, _s, _kr fr.Element
	if _, err := _r.SetRandom(); err != nil {
		return nil, err
	}
	if _, err := _s.SetRandom(); err != nil {
		return nil, err
	}
	_kr.Mul(&_r, &_s).Neg(&_kr)

	_r.BigInt(&r)
	_s.BigInt(&s)

	// computes r[δ], s[δ], kr[δ]
	deltas := curve.BatchScalarMultiplicationG1(&pk.G1.Delta, []fr.Element{_r, _s, _kr})

	var wireValuesADevice iciclegnark.OnDeviceData
	wireValuesA := make([]fr.Element, len(wireValues)-int(pk.NbInfinityA))
	for i, j := 0, 0; j < len(wireValuesA); i++ {
		if pk.InfinityA[i] {
			continue
		}
		wireValuesA[j] = wireValues[i]
		j++
	}
	wireValuesASize := len(wireValuesA)
	scalarBytes := wireValuesASize * fr.Bytes

	// Copy scalars to the device and retain ptr to them
	copyWireADone := make(chan unsafe.Pointer, 1)
	iciclegnark.CopyToDevice(wireValuesA, scalarBytes, copyWireADone)
	wireValuesADevicePtr := <-copyWireADone

	wireValuesADevice = iciclegnark.OnDeviceData{
		P:    wireValuesADevicePtr,
		Size: wireValuesASize,
	}
	iciclegnark.FreeDevicePointer(wireValuesADevice.P)

	wireValuesB := make([]fr.Element, len(wireValues)-int(pk.NbInfinityB))
	for i, j := 0, 0; j < len(wireValuesB); i++ {
		if pk.InfinityB[i] {
			continue
		}
		wireValuesB[j] = wireValues[i]
		j++
	}
	wireValuesBSize := len(wireValuesB)
	scalarBytes = wireValuesBSize * fr.Bytes

	// Copy scalars to the device and retain ptr to them
	copyWireBDone := make(chan unsafe.Pointer, 1)
	iciclegnark.CopyToDevice(wireValuesB, scalarBytes, copyWireBDone)
	wireValuesBDevicePtr := <-copyWireBDone

	var wireValuesBDevice iciclegnark.OnDeviceData
	wireValuesBDevice = iciclegnark.OnDeviceData{
		P:    wireValuesBDevicePtr,
		Size: wireValuesBSize,
	}

	var bs1, ar curve.G1Jac
	if bs1, _, err = iciclegnark.MsmOnDevice(wireValuesBDevice.P, pk.G1Device.B, wireValuesBDevice.Size, true); err != nil {
		return nil, err
	}

	bs1.AddMixed(&pk.G1.Beta)
	bs1.AddMixed(&deltas[1])

	var Bs, deltaS curve.G2Jac
	if Bs, _, err = iciclegnark.MsmG2OnDevice(wireValuesBDevice.P, pk.G2Device.B, wireValuesBDevice.Size, true); err != nil {
		return nil, err
	}

	deltaS.FromAffine(&pk.G2.Delta)
	deltaS.ScalarMultiplication(&deltaS, &s)
	Bs.AddAssign(&deltaS)
	Bs.AddMixed(&pk.G2.Beta)

	proof.Bs.FromJacobian(&Bs)

	iciclegnark.FreeDevicePointer(wireValuesBDevice.P)

	var h unsafe.Pointer
	h = computeH(solution.A, solution.B, solution.C, pk)
	solution.A = nil
	solution.B = nil
	solution.C = nil

	var krs, krs2, p1 curve.G1Jac

	sizeH := int(pk.Domain.Cardinality - 1) // comes from the fact the deg(H)=(n-1)+(n-1)-n=n-2

	// check for small circuits as iciclegnark doesn't handle zero sizes well
	if len(pk.G1.Z) > 0 {
		if krs2, _, err = iciclegnark.MsmOnDevice(h, pk.G1Device.Z, sizeH, true); err != nil {
			return nil, err
		}
	}

	iciclegnark.FreeDevicePointer(h)

	// filter the wire values if needed
	// TODO Perf @Tabaie worst memory allocation offender
	toRemove := commitmentInfo.GetPrivateCommitted()
	toRemove = append(toRemove, commitmentInfo.CommitmentIndexes())
	scalars := filterHeap(wireValues[r1cs.GetNbPublicVariables():], r1cs.GetNbPublicVariables(), internal.ConcatAll(toRemove...))

	// filter zero/infinity points since icicle doesn't handle them
	// See https://github.com/ingonyama-zk/icicle/issues/169 for more info
	for _, indexToRemove := range pk.InfinityPointIndicesK {
		scalars = append(scalars[:indexToRemove], scalars[indexToRemove+1:]...)
	}

	scalarBytes = len(scalars) * fr.Bytes

	copyScalarsDDone := make(chan unsafe.Pointer, 1)
	iciclegnark.CopyToDevice(scalars, scalarBytes, copyScalarsDDone)
	scalars_d := <-copyScalarsDDone

	krs, _, err = iciclegnark.MsmOnDevice(scalars_d, pk.G1Device.K, len(scalars), true)
	iciclegnark.FreeDevicePointer(scalars_d)

	if err != nil {
		return nil, err
	}

	krs.AddMixed(&deltas[2])

	krs.AddAssign(&krs2)

	p1.ScalarMultiplication(&ar, &s)
	krs.AddAssign(&p1)

	p1.ScalarMultiplication(&bs1, &r)
	krs.AddAssign(&p1)

	proof.Krs.FromJacobian(&krs)

	return proof, nil
}

func filterHeap(slice []fr.Element, sliceFirstIndex int, toRemove []int) (r []fr.Element) {

	if len(toRemove) == 0 {
		return slice
	}

	heap := utils.IntHeap(toRemove)
	heap.Heapify()

	r = make([]fr.Element, 0, len(slice))

	// note: we can optimize that for the likely case where len(slice) >>> len(toRemove)
	for i := 0; i < len(slice); i++ {
		if len(heap) > 0 && i+sliceFirstIndex == heap[0] {
			for len(heap) > 0 && i+sliceFirstIndex == heap[0] {
				heap.Pop()
			}
			continue
		}
		r = append(r, slice[i])
	}

	return
}

func computeH(a, b, c []fr.Element, pk *ProvingKey) unsafe.Pointer {
	n := len(a)

	// add padding to ensure input length is domain cardinality
	padding := make([]fr.Element, int(pk.Domain.Cardinality)-n)
	a = append(a, padding...)
	b = append(b, padding...)
	c = append(c, padding...)
	n = len(a)

	sizeBytes := n * fr.Bytes

	/*********** Copy a,b,c to Device Start ************/
	// Individual channels are necessary to know which device pointers
	// point to which vector
	copyADone := make(chan unsafe.Pointer, 1)
	copyBDone := make(chan unsafe.Pointer, 1)
	copyCDone := make(chan unsafe.Pointer, 1)

	go iciclegnark.CopyToDevice(a, sizeBytes, copyADone)
	go iciclegnark.CopyToDevice(b, sizeBytes, copyBDone)
	go iciclegnark.CopyToDevice(c, sizeBytes, copyCDone)

	a_device := <-copyADone
	b_device := <-copyBDone
	c_device := <-copyCDone
	/*********** Copy a,b,c to Device End ************/

	computeInttNttDone := make(chan error, 1)
	computeInttNttOnDevice := func(devicePointer unsafe.Pointer) {
		a_intt_d := iciclegnark.INttOnDevice(devicePointer, pk.DomainDevice.TwiddlesInv, nil, n, sizeBytes, false)

		iciclegnark.NttOnDevice(devicePointer, a_intt_d, pk.DomainDevice.Twiddles, pk.DomainDevice.CosetTable, n, n, sizeBytes, true)

		computeInttNttDone <- nil
		iciclegnark.FreeDevicePointer(a_intt_d)
	}
	go computeInttNttOnDevice(a_device)
	go computeInttNttOnDevice(b_device)
	go computeInttNttOnDevice(c_device)
	_, _, _ = <-computeInttNttDone, <-computeInttNttDone, <-computeInttNttDone

	iciclegnark.PolyOps(a_device, b_device, c_device, pk.DenDevice, n)

	h := iciclegnark.INttOnDevice(a_device, pk.DomainDevice.TwiddlesInv, pk.DomainDevice.CosetTableInv, n, sizeBytes, true)

	go func() {
		iciclegnark.FreeDevicePointer(a_device)
		iciclegnark.FreeDevicePointer(b_device)
		iciclegnark.FreeDevicePointer(c_device)
	}()

	iciclegnark.ReverseScalars(h, n)
	return h
}
