//go:build icicle

package icicle_bn254

import (
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	"github.com/consensys/gnark/backend"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/internal"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	fcs "github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
	"github.com/ingonyama-zk/icicle/wrappers/golang/core"
	cr "github.com/ingonyama-zk/icicle/wrappers/golang/cuda_runtime"
	iciclewrapper_bn254 "github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
	iciclegnark_bn254 "github.com/ingonyama-zk/iciclegnark/curves/bn254"
)

const HasIcicle = true

var (
	setupDeviceLock sync.Mutex
	gpuResourceLock sync.Mutex
)

func SetupDevicePointers(pk *ProvingKey) error {
	// TODO, add lock here to make sure only init once
	return pk.setupDevicePointers()
}

func (pk *ProvingKey) setupDevicePointers() error {
	setupDeviceLock.Lock()
	defer setupDeviceLock.Unlock()
	if pk.deviceInfo != nil {
		return nil
	}
	pk.deviceInfo = &deviceInfo{}

	// copy pk A to device
	fmt.Printf("start copy pk A \n")
	copyADone := make(chan core.DeviceSlice, 1)
	go iciclegnark_bn254.CopyPointsToDevice(pk.G1.A, copyADone) // Make a function for points
	pk.G1Device.A = <-copyADone
	fmt.Printf("end copy pk A \n")

	// opcy pk B to device
	fmt.Printf("start copy pk B \n")
	copyBDone := make(chan core.DeviceSlice, 1)
	go iciclegnark_bn254.CopyPointsToDevice(pk.G1.B, copyBDone) // Make a function for points
	pk.G1Device.B = <-copyBDone
	fmt.Printf("end copy pk B \n")

	fmt.Printf("start copy pk K \n")
	copyKDone := make(chan core.DeviceSlice, 1)
	go iciclegnark_bn254.CopyPointsToDevice(pk.G1.K, copyKDone) // Make a function for points
	pk.G1Device.K = <-copyKDone
	fmt.Printf("end copy pk K \n")

	fmt.Printf("start copy pk Z \n")
	copyZDone := make(chan core.DeviceSlice, 1)
	go iciclegnark_bn254.CopyPointsToDevice(pk.G1.Z, copyZDone) // Make a function for points
	pk.G1Device.Z = <-copyZDone
	fmt.Printf("end copy pk Z \n")

	fmt.Printf("start copy pk G2 B \n")
	copyG2BDone := make(chan core.DeviceSlice, 1)
	pointsBytesB2 := len(pk.G2.B) * fp.Bytes * 4
	go iciclegnark_bn254.CopyG2PointsToDevice(pk.G2.B, pointsBytesB2, copyG2BDone) // Make a function for points
	pk.G2Device.B = <-copyG2BDone
	fmt.Printf("end copy pk G2 B \n")

	// ntt config
	cfg := iciclewrapper_bn254.GetDefaultNttConfig()
	var s iciclewrapper_bn254.ScalarField

	// set pk.Domain.CosetTable[1]
	cosetTable, err := pk.Domain.CosetTable()
	if err != nil {
		return err
	}
	coset := cosetTable[1]
	cosetBits := coset.Bits()
	var configCosetGen [8]uint32
	configCosetGenRaw := core.ConvertUint64ArrToUint32Arr(cosetBits[:])
	if len(configCosetGenRaw) != 8 {
		return fmt.Errorf("len mismatch: %d != 8", len(configCosetGenRaw))
	}
	copy(configCosetGen[:], configCosetGenRaw[:8])
	cfg.CosetGen = configCosetGen

	// domain.Generator
	genBits := pk.Domain.Generator.Bits()
	s.FromLimbs(core.ConvertUint64ArrToUint32Arr(genBits[:]))
	fmt.Printf("start init icicle domain \n")
	//iciclewrapper_bn254.InitDomain(s, cfg.Ctx, true)
	fmt.Printf("end init icicle domain \n")

	return nil
}

// Prove generates the proof of knowledge of a r1cs with full witness (secret + public part).
func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*groth16_bn254.Proof, error) {
	fmt.Println("run icicle prove")
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new prover config: %w", err)
	}
	if opt.HashToFieldFn == nil {
		opt.HashToFieldFn = hash_to_field.New([]byte(constraint.CommitmentDst))
	}

	err = pk.setupDevicePointers()
	if err != nil {
		return nil, err
	}

	log := logger.Logger().With().Str("curve", r1cs.CurveID().String()).Str("acceleration", "none").Int("nbConstraints", r1cs.GetNbConstraints()).Str("backend", "groth16").Logger()

	commitmentInfo := r1cs.CommitmentInfo.(constraint.Groth16Commitments)

	proof := &groth16_bn254.Proof{Commitments: make([]curve.G1Affine, len(commitmentInfo))}

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

	start := time.Now()

	commitmentsSerialized := make([]byte, fr.Bytes*len(commitmentInfo))
	for i := range commitmentInfo {
		copy(commitmentsSerialized[fr.Bytes*i:], wireValues[commitmentInfo[i].CommitmentIndex].Marshal())
	}

	if proof.CommitmentPok, err = pedersen.BatchProve(pk.CommitmentKeys, privateCommittedValues, commitmentsSerialized); err != nil {
		return nil, err
	}

	// H (witness reduction / FFT part)
	var h []fr.Element
	chHDone := make(chan struct{}, 1)
	go func() {
		h = computeH(solution.A, solution.B, solution.C, &pk.Domain)
		solution.A = nil
		solution.B = nil
		solution.C = nil
		chHDone <- struct{}{}
	}()

	// we need to copy and filter the wireValues for each multi exp
	// as pk.G1.A, pk.G1.B and pk.G2.B may have (a significant) number of point at infinity
	var wireValuesA, wireValuesB []fr.Element
	chWireValuesA, chWireValuesB := make(chan struct{}, 1), make(chan struct{}, 1)

	go func() {
		wireValuesA = make([]fr.Element, len(wireValues)-int(pk.NbInfinityA))
		for i, j := 0, 0; j < len(wireValuesA); i++ {
			if pk.InfinityA[i] {
				continue
			}
			wireValuesA[j] = wireValues[i]
			j++
		}

		close(chWireValuesA)
	}()
	go func() {
		wireValuesB = make([]fr.Element, len(wireValues)-int(pk.NbInfinityB))
		for i, j := 0, 0; j < len(wireValuesB); i++ {
			if pk.InfinityB[i] {
				continue
			}
			wireValuesB[j] = wireValues[i]
			j++
		}

		close(chWireValuesB)
	}()

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

	var bs1, ar curve.G1Jac

	n := runtime.NumCPU()

	chBs1Done := make(chan error, 1)
	computeBS1 := func() {
		<-chWireValuesB
		if _, merr := bs1.MultiExp(pk.G1.B, wireValuesB, ecc.MultiExpConfig{NbTasks: n / 2}); merr != nil {
			chBs1Done <- merr
			close(chBs1Done)
			return
		}

		bs1InGpu, gerr := MsmOnDevice(pk.G1Device.B, wireValuesB)
		if gerr != nil {
			chBs1Done <- gerr
			close(chBs1Done)
			return
		}
		var bs1JacInGpu curve.G1Jac
		bs1JacInGpu.FromAffine(bs1InGpu)
		if bs1JacInGpu.Equal(&bs1) {
			fmt.Printf("bs1JacInGpu equal \n")
		} else {
			fmt.Printf("bs1JacInGpu not equal \n")
		}

		bs1.AddMixed(&pk.G1.Beta)
		bs1.AddMixed(&deltas[1])
		chBs1Done <- nil
	}

	chArDone := make(chan error, 1)
	computeAR1 := func() {
		<-chWireValuesA
		if _, merr := ar.MultiExp(pk.G1.A, wireValuesA, ecc.MultiExpConfig{NbTasks: n / 2}); merr != nil {
			chArDone <- merr
			close(chArDone)
			return
		}

		arInGpu, gerr := MsmOnDevice(pk.G1Device.A, wireValuesA)
		if gerr != nil {
			chArDone <- gerr
			close(chArDone)
			return
		}
		var arJacInGpu curve.G1Jac
		arJacInGpu.FromAffine(arInGpu)
		if arJacInGpu.Equal(&ar) {
			fmt.Printf("arJacInGpu equal \n")
		} else {
			fmt.Printf("arJacInGpu not equal \n")
		}

		ar.AddMixed(&pk.G1.Alpha)
		ar.AddMixed(&deltas[0])
		proof.Ar.FromJacobian(&ar)
		chArDone <- nil
	}

	chKrsDone := make(chan error, 1)
	computeKRS := func() {
		// we could NOT split the Krs multiExp in 2, and just append pk.G1.K and pk.G1.Z
		// however, having similar lengths for our tasks helps with parallelism

		var krs, krs2, p1 curve.G1Jac
		chKrs2Done := make(chan error, 1)
		sizeH := int(pk.Domain.Cardinality - 1) // comes from the fact the deg(H)=(n-1)+(n-1)-n=n-2
		go func() {
			_, kerr := krs2.MultiExp(pk.G1.Z, h[:sizeH], ecc.MultiExpConfig{NbTasks: n / 2})

			krs2InGpu, gerr := MsmOnDevice(pk.G1Device.Z, h[:sizeH])
			if gerr != nil {
				chKrsDone <- gerr
				return
			}

			var krs2JacInGpu curve.G1Jac
			krs2JacInGpu.FromAffine(krs2InGpu)
			if krs2JacInGpu.Equal(&krs2) {
				fmt.Printf("krs2JacInGpu equal \n")
			} else {
				fmt.Printf("krs2JacInGpu not equal \n")
			}

			chKrs2Done <- kerr
		}()

		// filter the wire values if needed
		// TODO Perf @Tabaie worst memory allocation offender
		toRemove := commitmentInfo.GetPrivateCommitted()
		toRemove = append(toRemove, commitmentInfo.CommitmentIndexes())
		_wireValues := filterHeap(wireValues[r1cs.GetNbPublicVariables():], r1cs.GetNbPublicVariables(), internal.ConcatAll(toRemove...))

		if _, merr := krs.MultiExp(pk.G1.K, _wireValues, ecc.MultiExpConfig{NbTasks: n / 2}); merr != nil {
			chKrsDone <- merr
			return
		}

		// TODO
		// filter zero/infinity points since icicle doesn't handle them
		// See https://github.com/ingonyama-zk/icicle/issues/169 for more info
		krsInGpu, gerr := MsmOnDevice(pk.G1Device.K, _wireValues)
		if gerr != nil {
			chKrsDone <- gerr
			return
		}

		var krsJacInGpu curve.G1Jac
		krsJacInGpu.FromAffine(krsInGpu)
		if krsJacInGpu.Equal(&krs) {
			fmt.Printf("krsJacInGpu equal \n")
		} else {
			fmt.Printf("krsJacInGpu not equal \n")
		}

		krs.AddMixed(&deltas[2])
		n := 3
		for n != 0 {
			select {
			case err := <-chKrs2Done:
				if err != nil {
					chKrsDone <- err
					return
				}
				krs.AddAssign(&krs2)
			case err := <-chArDone:
				if err != nil {
					chKrsDone <- err
					return
				}
				p1.ScalarMultiplication(&ar, &s)
				krs.AddAssign(&p1)
			case err := <-chBs1Done:
				if err != nil {
					chKrsDone <- err
					return
				}
				p1.ScalarMultiplication(&bs1, &r)
				krs.AddAssign(&p1)
			}
			n--
		}

		proof.Krs.FromJacobian(&krs)
		chKrsDone <- nil
	}

	computeBS2 := func() error {
		// Bs2 (1 multi exp G2 - size = len(wires))
		var Bs, deltaS curve.G2Jac

		nbTasks := n
		if nbTasks <= 16 {
			// if we don't have a lot of CPUs, this may artificially split the MSM
			nbTasks *= 2
		}
		<-chWireValuesB

		if _, merr := Bs.MultiExp(pk.G2.B, wireValuesB, ecc.MultiExpConfig{NbTasks: nbTasks}); merr != nil {
			return merr
		}

		bsInGpu, gerr := G2MsmOnDevice(pk.G2Device.B, wireValuesB)
		if gerr != nil {
			return gerr
		}

		var bsJacInGpu curve.G2Jac
		bsJacInGpu.FromAffine(bsInGpu)
		if bsJacInGpu.Equal(&Bs) {
			fmt.Printf("bsJacInGpu equal \n")
		} else {
			fmt.Printf("bsJacInGpu not equal \n")
		}

		deltaS.FromAffine(&pk.G2.Delta)
		deltaS.ScalarMultiplication(&deltaS, &s)
		Bs.AddAssign(&deltaS)
		Bs.AddMixed(&pk.G2.Beta)

		proof.Bs.FromJacobian(&Bs)
		return nil
	}

	// wait for FFT to end, as it uses all our CPUs
	<-chHDone

	// schedule our proof part computations
	go computeKRS()
	go computeAR1()
	go computeBS1()
	if err := computeBS2(); err != nil {
		return nil, err
	}

	// wait for all parts of the proof to be computed.
	if err := <-chKrsDone; err != nil {
		return nil, err
	}

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")

	return proof, nil
}

// if len(toRemove) == 0, returns slice
// else, returns a new slice without the indexes in toRemove. The first value in the slice is taken as indexes as sliceFirstIndex
// this assumes len(slice) > len(toRemove)
// filterHeap modifies toRemove
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

func computeH(a, b, c []fr.Element, domain *fft.Domain) []fr.Element {
	// H part of Krs
	// Compute H (hz=ab-c, where z=-2 on ker X^n+1 (z(x)=x^n-1))
	// 	1 - _a = ifft(a), _b = ifft(b), _c = ifft(c)
	// 	2 - ca = fft_coset(_a), ba = fft_coset(_b), cc = fft_coset(_c)
	// 	3 - h = ifft_coset(ca o cb - cc)

	n := len(a)

	// add padding to ensure input length is domain cardinality
	padding := make([]fr.Element, int(domain.Cardinality)-n)
	a = append(a, padding...)
	b = append(b, padding...)
	c = append(c, padding...)
	n = len(a)

	domain.FFTInverse(a, fft.DIF)
	domain.FFTInverse(b, fft.DIF)
	domain.FFTInverse(c, fft.DIF)

	domain.FFT(a, fft.DIT, fft.OnCoset())
	domain.FFT(b, fft.DIT, fft.OnCoset())
	domain.FFT(c, fft.DIT, fft.OnCoset())

	var den, one fr.Element
	one.SetOne()
	den.Exp(domain.FrMultiplicativeGen, big.NewInt(int64(domain.Cardinality)))
	den.Sub(&den, &one).Inverse(&den)

	// h = ifft_coset(ca o cb - cc)
	// reusing a to avoid unnecessary memory allocation
	utils.Parallelize(n, func(start, end int) {
		for i := start; i < end; i++ {
			a[i].Mul(&a[i], &b[i]).
				Sub(&a[i], &c[i]).
				Mul(&a[i], &den)
		}
	})

	// ifft_coset
	domain.FFTInverse(a, fft.DIF, fft.OnCoset())

	return a
}

func computeHonDevice(a, b, c []fr.Element, domain *fft.Domain) []fr.Element {

	return nil
}

func MsmOnDevice(gnarkPoints core.DeviceSlice, gnarkScalars []fr.Element) (*curve.G1Affine, error) {
	icicleScalars := iciclegnark_bn254.HostSliceFromScalars(gnarkScalars)

	cfg := core.GetDefaultMSMConfig()
	var p iciclewrapper_bn254.Projective
	var out core.DeviceSlice
	_, e := out.Malloc(p.Size(), p.Size())
	if e != cr.CudaSuccess {
		return nil, errors.New("cannot allocate")
	}
	e = iciclewrapper_bn254.Msm(icicleScalars, gnarkPoints, &cfg, out)
	if e != cr.CudaSuccess {
		return nil, errors.New("msm failed")
	}
	outHost := make(core.HostSlice[iciclewrapper_bn254.Projective], 1)
	outHost.CopyFromDevice(&out)
	out.Free()
	return iciclegnark_bn254.ProjectiveToGnarkAffine(&outHost[0]), nil
}

func G2MsmOnDevice(gnarkPoints core.DeviceSlice, gnarkScalars []fr.Element) (*curve.G2Affine, error) {
	icicleScalars := core.HostSliceFromElements(iciclegnark_bn254.BatchConvertFromFrGnark(gnarkScalars))

	cfg := core.GetDefaultMSMConfig()
	var p iciclewrapper_bn254.G2Projective
	var out core.DeviceSlice
	_, e := out.Malloc(p.Size(), p.Size())
	if e != cr.CudaSuccess {
		return nil, errors.New("Cannot allocate g2")
	}
	e = iciclewrapper_bn254.G2Msm(icicleScalars, gnarkPoints, &cfg, out)
	if e != cr.CudaSuccess {
		return nil, errors.New("Msm g2 failed")
	}
	outHost := make(core.HostSlice[iciclewrapper_bn254.G2Projective], 1)
	outHost.CopyFromDevice(&out)
	out.Free()
	return iciclegnark_bn254.G2PointToGnarkAffine(&outHost[0]), nil
}
