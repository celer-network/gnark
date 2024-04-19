//go:build icicle

package icicle_bn254

import (
	"fmt"
	"math/big"
	"sync"
	"time"

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
	"github.com/ingonyama-zk/icicle/wrappers/golang/cuda_runtime"
	"github.com/ingonyama-zk/icicle/wrappers/golang/curves/bn254"
	iciclegnark "github.com/ingonyama-zk/iciclegnark/curves/bn254"
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
	lg := logger.Logger().With().Str("curve", "bn254").Str("acceleration", "icicle").Str("backend", "groth16").Logger()
	lg.Info().Msg("start setupDevicePointers")
	pk.deviceInfo = &deviceInfo{}

	// ntt config
	ctx, _ := cuda_runtime.GetDefaultDeviceContext()
	var s bn254.ScalarField

	// domain.Generator
	gen, _ := fft.Generator(2 * pk.Domain.Cardinality)
	genBits := gen.Bits()
	s.FromLimbs(core.ConvertUint64ArrToUint32Arr(genBits[:]))
	bn254.InitDomain(s, ctx, false)

	/*************************  Start G1 Device Setup  ***************************/
	/*************************     A      ***************************/
	copyADone := make(chan core.DeviceSlice, 1)
	cuda_runtime.RunOnDevice(0, func(args ...any) {
		iciclegnark.CopyPointsToDevice(pk.G1.A, copyADone)
	})

	/*************************     B      ***************************/
	copyBDone := make(chan core.DeviceSlice, 1)
	cuda_runtime.RunOnDevice(0, func(args ...any) {
		iciclegnark.CopyPointsToDevice(pk.G1.B, copyBDone)
	})

	/*************************     K      ***************************/
	var pointsNoInfinity []curve.G1Affine
	for i, gnarkPoint := range pk.G1.K {
		if gnarkPoint.IsInfinity() {
			pk.InfinityPointIndicesK = append(pk.InfinityPointIndicesK, i)
		} else {
			pointsNoInfinity = append(pointsNoInfinity, gnarkPoint)
		}
	}

	copyKDone := make(chan core.DeviceSlice, 1)
	cuda_runtime.RunOnDevice(0, func(args ...any) {
		iciclegnark.CopyPointsToDevice(pointsNoInfinity, copyKDone)
	})

	/*************************     Z      ***************************/
	copyZDone := make(chan core.DeviceSlice, 1)
	padding := make([]curve.G1Affine, 1)
	// padding[0] = curve.G1Affine.generator()
	Z_plus_point := append(pk.G1.Z, padding...)
	cuda_runtime.RunOnDevice(0, func(args ...any) {
		iciclegnark.CopyPointsToDevice(Z_plus_point, copyZDone)
	})

	/*************************  End G1 Device Setup  ***************************/
	pk.G1Device.A = <-copyADone
	pk.G1Device.B = <-copyBDone
	pk.G1Device.K = <-copyKDone
	pk.G1Device.Z = <-copyZDone

	/*************************  Start G2 Device Setup  ***************************/
	pointsBytesB2 := len(pk.G2.B) * fp.Bytes * 4
	copyG2BDone := make(chan core.DeviceSlice, 1)
	cuda_runtime.RunOnDevice(0, func(args ...any) {
		iciclegnark.CopyG2PointsToDevice(pk.G2.B, pointsBytesB2, copyG2BDone) // Make a function for points
	})
	pk.G2Device.B = <-copyG2BDone

	lg.Info().Msg("end setupDevicePointers")

	return nil
}

// Prove generates the proof of knowledge of a r1cs with full witness (secret + public part).
func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*groth16_bn254.Proof, error) {
	lg := logger.Logger().With().Str("curve", r1cs.CurveID().String()).Str("acceleration", "icicle").Int("nbConstraints", r1cs.GetNbConstraints()).Str("backend", "groth16").Logger()
	lg.Info().Msg("start prove")
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

	var errPedersen error
	chPedersenDone := make(chan struct{}, 1)
	go func() {
		// TODO: after the bottleneck of HostSlice creation is solved, this function that's currently executed on CPU
		// might become the bottleneck, especially for relatively weak CPUs
		if proof.CommitmentPok, err = pedersen.BatchProve(pk.CommitmentKeys, privateCommittedValues, commitmentsSerialized); err != nil {
			errPedersen = err
		}

		close(chPedersenDone)
	}()
	if errPedersen != nil {
		return nil, errPedersen
	}

	// we need to copy and filter the wireValues for each multi exp
	// as pk.G1.A, pk.G1.B and pk.G2.B may have (a significant) number of point at infinity
	var wireValuesA, wireValuesB, _wireValues []fr.Element
	chWireValuesA, chWireValuesB, chWireValues := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)

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
	go func() {
		// filter the wire values if needed
		// TODO Perf @Tabaie worst memory allocation offender
		toRemove := commitmentInfo.GetPrivateCommitted()
		toRemove = append(toRemove, commitmentInfo.CommitmentIndexes())
		_wireValues = filterHeap(wireValues[r1cs.GetNbPublicVariables():], r1cs.GetNbPublicVariables(), internal.ConcatAll(toRemove...))

		close(chWireValues)
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

	<-chWireValuesB
	bs1Done := make(chan error, 1)
	cuda_runtime.RunOnDevice(0, func(args ...any) {
		var calBs1Err error
		bs1, calBs1Err = CalBs1(wireValuesB, pk.G1Device.B, &pk.G1.Beta, &deltas[1])
		bs1Done <- calBs1Err
	})

	BsDone := make(chan error, 1)
	cuda_runtime.RunOnDevice(0, func(args ...any) {
		var Bs curve.G2Jac
		var calBsErr error
		Bs, calBsErr = CalG2Bs(wireValuesB, pk.G2Device.B, &pk.G2.Delta, &pk.G2.Beta, s)
		proof.Bs.FromJacobian(&Bs)
		BsDone <- calBsErr
	})
	<-BsDone

	<-chWireValuesA
	arDone := make(chan error, 1)
	cuda_runtime.RunOnDevice(0, func(args ...any) {
		var calArErr error
		ar, calArErr = CalAr(wireValuesA, pk.G1Device.A, &pk.G1.Alpha, &deltas[0])
		proof.Ar.FromJacobian(&ar)
		arDone <- calArErr
	})
	<-arDone

	var krs2, krs, p1 curve.G1Jac

	krs2Done := make(chan error, 1)
	cuda_runtime.RunOnDevice(0, func(args ...any) {
		var calkrs2Err error
		krs2, calkrs2Err = CalKrs2(solution.A, solution.B, solution.C, &pk.Domain, pk.G1Device.Z)
		solution.A = nil
		solution.B = nil
		solution.C = nil
		krs2Done <- calkrs2Err
	})
	<-krs2Done

	<-chWireValues

	krsDone := make(chan error, 1)
	cuda_runtime.RunOnDevice(0, func(args ...any) {
		var calkrsErr error
		krs, calkrsErr = CalKrs(_wireValues, pk.G1Device.K)
		krsDone <- calkrsErr
	})
	<-krsDone

	krs.AddMixed(&deltas[2])
	krs.AddAssign(&krs2)
	p1.ScalarMultiplication(&ar, &s)
	krs.AddAssign(&p1)
	<-bs1Done
	p1.ScalarMultiplication(&bs1, &r)
	krs.AddAssign(&p1)

	proof.Krs.FromJacobian(&krs)

	<-chPedersenDone

	lg.Debug().Dur("took", time.Since(start)).Msg("prover done")

	return proof, nil
}

func CalAr(wireValuesA []fr.Element, deviceA core.DeviceSlice, alpha, deltas0 *curve.G1Affine) (ar curve.G1Jac, err error) {
	cfg := bn254.GetDefaultMSMConfig()
	stream, cudaErr := cuda_runtime.CreateStream()
	if cudaErr != cuda_runtime.CudaSuccess {
		return curve.G1Jac{}, fmt.Errorf("create ar stream fail: %d", cudaErr)
	}
	cfg.Ctx.Stream = &stream
	cfg.IsAsync = true

	outHost := make(core.HostSlice[bn254.Projective], 1)
	var out core.DeviceSlice
	out.MallocAsync(outHost.SizeOfElement(), outHost.SizeOfElement(), stream)

	wireValuesAhost := iciclegnark.HostSliceFromScalars(wireValuesA)
	cudaErr = bn254.Msm(wireValuesAhost, deviceA, &cfg, out)
	if cudaErr != cuda_runtime.CudaSuccess {
		return curve.G1Jac{}, fmt.Errorf("ar msm fail: %d", cudaErr)
	}
	outHost.CopyFromDeviceAsync(&out, stream)
	ar = *iciclegnark.G1ProjectivePointToGnarkJac(&outHost[0])
	ar.AddMixed(alpha)
	ar.AddMixed(deltas0)
	return
}

func CalBs1(wireValuesB []fr.Element, deviceB core.DeviceSlice, beta, deltas1 *curve.G1Affine) (bs1 curve.G1Jac, err error) {
	cfg := bn254.GetDefaultMSMConfig()
	stream, cudaErr := cuda_runtime.CreateStream()
	if cudaErr != cuda_runtime.CudaSuccess {
		return curve.G1Jac{}, fmt.Errorf("create bs1 stream fail: %d", cudaErr)
	}
	cfg.Ctx.Stream = &stream
	cfg.IsAsync = true

	outHost := make(core.HostSlice[bn254.Projective], 1)
	var out core.DeviceSlice
	out.MallocAsync(outHost.SizeOfElement(), outHost.SizeOfElement(), stream)

	wireValuesBhost := iciclegnark.HostSliceFromScalars(wireValuesB)
	cudaErr = bn254.Msm(wireValuesBhost, deviceB, &cfg, out)
	if cudaErr != cuda_runtime.CudaSuccess {
		return curve.G1Jac{}, fmt.Errorf("bs1 msm fail: %d", cudaErr)
	}
	outHost.CopyFromDeviceAsync(&out, stream)
	bs1 = *iciclegnark.G1ProjectivePointToGnarkJac(&outHost[0])
	bs1.AddMixed(beta)
	bs1.AddMixed(deltas1)
	return
}

func CalG2Bs(wireValuesB []fr.Element, deviceG2B core.DeviceSlice, delta, beta *curve.G2Affine, s big.Int) (Bs curve.G2Jac, err error) {
	var deltaS curve.G2Jac
	cfg := bn254.GetDefaultMSMConfig()
	stream, cudaErr := cuda_runtime.CreateStream()
	if cudaErr != cuda_runtime.CudaSuccess {
		return curve.G2Jac{}, fmt.Errorf("create g2 bs stream fail: %d", cudaErr)
	}
	cfg.Ctx.Stream = &stream
	cfg.IsAsync = true

	outHostG2 := make(core.HostSlice[bn254.G2Projective], 1)
	var outG2 core.DeviceSlice
	outG2.MallocAsync(outHostG2.SizeOfElement(), outHostG2.SizeOfElement(), stream)

	wireValuesBhost := iciclegnark.HostSliceFromScalars(wireValuesB)
	cudaErr = bn254.G2Msm(wireValuesBhost, deviceG2B, &cfg, outG2)
	if cudaErr != cuda_runtime.CudaSuccess {
		return curve.G2Jac{}, fmt.Errorf("g2 Bs msm fail: %d", cudaErr)
	}
	outHostG2.CopyFromDeviceAsync(&outG2, stream)
	outG2.FreeAsync(stream)

	Bs = *iciclegnark.G2PointToGnarkJac(&outHostG2[0])

	deltaS.FromAffine(delta)
	deltaS.ScalarMultiplication(&deltaS, &s)
	Bs.AddAssign(&deltaS)
	Bs.AddMixed(beta)
	return
}

func CalKrs2(a, b, c []fr.Element, domain *fft.Domain, deviceZ core.DeviceSlice) (krs2 curve.G1Jac, err error) {
	cfg := bn254.GetDefaultMSMConfig()
	stream, cudaErr := cuda_runtime.CreateStream()
	if cudaErr != cuda_runtime.CudaSuccess {
		return curve.G1Jac{}, fmt.Errorf("create krs2 stream fail: %d", cudaErr)
	}
	cfg.Ctx.Stream = &stream
	cfg.IsAsync = true

	h_device := computeHonDevice(a, b, c, domain, stream)

	outHost := make(core.HostSlice[bn254.Projective], 1)
	var out core.DeviceSlice
	out.MallocAsync(outHost.SizeOfElement(), outHost.SizeOfElement(), stream)

	cudaErr = bn254.Msm(h_device, deviceZ, &cfg, out)
	if cudaErr != cuda_runtime.CudaSuccess {
		return curve.G1Jac{}, fmt.Errorf("MSM krs2 fail: %d", cudaErr)
	}
	outHost.CopyFromDeviceAsync(&out, stream)
	h_device.FreeAsync(stream)

	krs2 = *iciclegnark.G1ProjectivePointToGnarkJac(&outHost[0])
	return
}

func CalKrs(_wireValues []fr.Element, deviceK core.DeviceSlice) (krs curve.G1Jac, err error) {
	cfg := bn254.GetDefaultMSMConfig()
	stream, cudaErr := cuda_runtime.CreateStream()
	if cudaErr != cuda_runtime.CudaSuccess {
		return curve.G1Jac{}, fmt.Errorf("create krs stream fail: %d", cudaErr)
	}
	cfg.Ctx.Stream = &stream
	cfg.IsAsync = true

	outHost := make(core.HostSlice[bn254.Projective], 1)
	var out core.DeviceSlice
	out.MallocAsync(outHost.SizeOfElement(), outHost.SizeOfElement(), stream)

	_wireValuesHost := iciclegnark.HostSliceFromScalars(_wireValues)
	cudaErr = bn254.Msm(_wireValuesHost, deviceK, &cfg, out)
	if cudaErr != cuda_runtime.CudaSuccess {
		return curve.G1Jac{}, fmt.Errorf("MSM krs fail: %d", cudaErr)
	}
	outHost.CopyFromDeviceAsync(&out, stream)
	out.FreeAsync(stream)
	krs = *iciclegnark.G1ProjectivePointToGnarkJac(&outHost[0])
	return
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

func computeHonDevice(a, b, c []fr.Element, domain *fft.Domain, stream cuda_runtime.Stream) core.DeviceSlice {
	cosetGen, _ := fft.Generator(2 * domain.Cardinality)
	cosetBits := cosetGen.Bits()
	var configCosetGen [8]uint32
	configCosetGenRaw := core.ConvertUint64ArrToUint32Arr(cosetBits[:])
	copy(configCosetGen[:], configCosetGenRaw[:8])

	cfg := bn254.GetDefaultNttConfig()
	cfg.IsAsync = true
	cfg.Ctx.Stream = &stream

	n := len(a)

	padding := make([]fr.Element, int(domain.Cardinality)-n)
	a = append(a, padding...)
	b = append(b, padding...)
	c = append(c, padding...)
	n = len(a)
	a_host := iciclegnark.HostSliceFromScalars(a)
	b_host := iciclegnark.HostSliceFromScalars(b)
	c_host := iciclegnark.HostSliceFromScalars(c)

	var a_device core.DeviceSlice
	var b_device core.DeviceSlice
	var c_device core.DeviceSlice
	a_host.CopyToDeviceAsync(&a_device, stream, true)
	b_host.CopyToDeviceAsync(&b_device, stream, true)
	c_host.CopyToDeviceAsync(&c_device, stream, true)

	cfg.Ordering = core.KNM

	bn254.Ntt(a_device, core.KInverse, &cfg, a_device)
	bn254.Ntt(b_device, core.KInverse, &cfg, b_device)
	bn254.Ntt(c_device, core.KInverse, &cfg, c_device)

	cfg.CosetGen = configCosetGen
	cfg.Ordering = core.KMN

	bn254.Ntt(a_device, core.KForward, &cfg, a_device)
	bn254.Ntt(b_device, core.KForward, &cfg, b_device)
	bn254.Ntt(c_device, core.KForward, &cfg, c_device)

	var den, one fr.Element
	one.SetOne()
	den.Exp(cosetGen, big.NewInt(int64(domain.Cardinality)))
	den.Sub(&den, &one).Inverse(&den)
	den_repeated := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		den_repeated[i] = den
	}
	den_host := iciclegnark.HostSliceFromScalars(den_repeated)

	vcfg := core.DefaultVecOpsConfig()
	vcfg.Ctx.Stream = &stream

	// h = ifft_coset(ca o cb - cc)
	bn254.VecOp(a_device, b_device, a_device, vcfg, core.Mul)
	bn254.VecOp(a_device, c_device, a_device, vcfg, core.Sub)
	den_host.CopyToDeviceAsync(&b_device, stream, false)
	bn254.VecOp(a_device, b_device, a_device, vcfg, core.Mul)
	cfg.Ordering = core.KNR

	// ifft_coset
	bn254.Ntt(a_device, core.KInverse, &cfg, a_device)
	b_device.FreeAsync(stream)
	c_device.FreeAsync(stream)
	return a_device
}
