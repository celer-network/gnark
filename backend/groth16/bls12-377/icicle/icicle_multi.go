//go:build icicle

package icicle_bls12377

import (
	"fmt"
	"math/big"
	"math/bits"
	"runtime"
	"sync"
	"time"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/hash_to_field"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/pedersen"
	"github.com/consensys/gnark/backend"
	groth16_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	"github.com/consensys/gnark/backend/groth16/internal"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
	fcs "github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/logger"
	icicle_core "github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	icicle_cr "github.com/ingonyama-zk/icicle/v2/wrappers/golang/cuda_runtime"
	icicle_bls12377 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bls12377"
	icicle_g2 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bls12377/g2"
	icicle_msm "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bls12377/msm"
	icicle_ntt "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bls12377/ntt"
	icicle_vecops "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bls12377/vecOps"
	"github.com/rs/zerolog"
)

var (
	deviceLocks [8]sync.Mutex
)

func (pk *ProvingKey) setupDevicePointersOnMulti(deviceIds []int, freePk bool) error {
	deviceSetupLock.Lock()
	defer deviceSetupLock.Unlock()

	if pk.isDeviceReady() {
		return nil
	}

	pk.deviceInfo = &deviceInfo{}
	gen, _ := fft.Generator(2 * pk.Domain.Cardinality)
	/*************************     Den      ***************************/
	n := int(pk.Domain.Cardinality)
	var denI, oneI fr.Element
	oneI.SetOne()
	denI.Exp(gen, big.NewInt(int64(pk.Domain.Cardinality)))
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

	copyDenDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(deviceIds[0], func(args ...any) {
		denIcicleArrHost := (icicle_core.HostSlice[fr.Element])(denIcicleArr)
		denIcicleArrHost.CopyToDevice(&pk.DenDevice, true)
		icicle_bls12377.FromMontgomery(&pk.DenDevice)
		copyDenDone <- true
	})

	/*************************  Init Domain Device  ***************************/
	initNttDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(deviceIds[0], func(args ...any) {
		ctx, err := icicle_cr.GetDefaultDeviceContext()
		if err != icicle_cr.CudaSuccess {
			panic("Couldn't create device context") // TODO
		}

		genBits := gen.Bits()
		limbs := icicle_core.ConvertUint64ArrToUint32Arr(genBits[:])
		copy(pk.CosetGenerator[:], limbs[:fr.Limbs*2])
		var rouIcicle icicle_bls12377.ScalarField
		rouIcicle.FromLimbs(limbs)
		e := icicle_ntt.InitDomain(rouIcicle, ctx, false)
		if e.IcicleErrorCode != icicle_core.IcicleSuccess {
			panic("Couldn't initialize domain") // TODO
		}
		initNttDone <- true
	})

	/*************************  End Init Domain Device  ***************************/
	/*************************  Start G1 Device Setup  ***************************/
	/*************************     A      ***************************/
	copyADone := make(chan bool, 1)
	icicle_cr.RunOnDevice(deviceIds[1], func(args ...any) {
		g1AHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.A)
		g1AHost.CopyToDevice(&pk.G1Device.A, true)
		icicle_bls12377.AffineFromMontgomery(&pk.G1Device.A)
		copyADone <- true
	})
	/*************************     B      ***************************/
	copyBDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(deviceIds[3], func(args ...any) {
		g1BHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.B)
		g1BHost.CopyToDevice(&pk.G1Device.B, true)
		icicle_bls12377.AffineFromMontgomery(&pk.G1Device.B)
		copyBDone <- true
	})
	/*************************     K      ***************************/
	copyKDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(deviceIds[4], func(args ...any) {
		g1KHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.K)
		g1KHost.CopyToDevice(&pk.G1Device.K, true)
		icicle_bls12377.AffineFromMontgomery(&pk.G1Device.K)
		copyKDone <- true
	})
	/*************************     Z      ***************************/
	copyZDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(deviceIds[0], func(args ...any) {
		g1ZHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.Z)
		g1ZHost.CopyToDevice(&pk.G1Device.Z, true)
		icicle_bls12377.AffineFromMontgomery(&pk.G1Device.Z)
		copyZDone <- true
	})
	/*************************  End G1 Device Setup  ***************************/
	<-copyDenDone
	<-copyADone
	<-copyBDone
	<-copyKDone
	<-copyZDone

	<-initNttDone
	/*************************  Start G2 Device Setup  ***************************/
	copyG2BDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(deviceIds[2], func(args ...any) {
		g2BHost := (icicle_core.HostSlice[curve.G2Affine])(pk.G2.B)
		g2BHost.CopyToDevice(&pk.G2Device.B, true)
		icicle_g2.G2AffineFromMontgomery(&pk.G2Device.B)
		copyG2BDone <- true
	})

	<-copyG2BDone
	/*************************  End G2 Device Setup  ***************************/

	if freePk {
		pk.Domain = fft.Domain{Cardinality: pk.Domain.Cardinality}
		pk.G1.A = nil
		pk.G1.B = nil
		pk.G1.K = nil
		pk.G1.Z = make([]curve.G1Affine, 1) // maybe no need, as we can handle zero now
		pk.G2.B = nil
		runtime.GC()
	}

	pk.DeviceReady = true

	return nil
}

// Prove generates the proof of knowledge of a r1cs with full witness (secret + public part).
func ProveOnMulti(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*groth16_bls12377.Proof, error) {
	log := logger.Logger().With().Str("curve", r1cs.CurveID().String()).Str("acceleration", "icicle").Int("nbConstraints", r1cs.GetNbConstraints()).Str("backend", "groth16").Logger()
	log.Debug().Msg("start ProveOnMulti")
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new prover config: %w", err)
	}
	if opt.HashToFieldFn == nil {
		opt.HashToFieldFn = hash_to_field.New([]byte(constraint.CommitmentDst))
	}
	if !pk.isDeviceReady() {
		log.Debug().Msg("precomputing proving key on multi GPU")
		if err := pk.setupDevicePointersOnMulti(opt.MultiGpuSelect, opt.FreePkWithGpu); err != nil {
			return nil, fmt.Errorf("setup device pointers: %w", err)
		}
	}

	deviceIds := opt.MultiGpuSelect

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

	solveLimit <- 1
	_solution, err := r1cs.Solve(fullWitness, solverOpts...)
	<-solveLimit
	if err != nil {
		return nil, err
	}

	solution := _solution.(*cs.R1CSSolution)
	wireValues := []fr.Element(solution.W)

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
	commitmentPokDone := make(chan error, 1)
	go func() {
		commitmentsSerialized := make([]byte, fr.Bytes*len(commitmentInfo))
		for i := range commitmentInfo {
			copy(commitmentsSerialized[fr.Bytes*i:], wireValues[commitmentInfo[i].CommitmentIndex].Marshal())
		}

		proof.CommitmentPok, err = pedersen.BatchProve(pk.CommitmentKeys, privateCommittedValues, commitmentsSerialized)
		commitmentPokDone <- err
	}()

	deltas := curve.BatchScalarMultiplicationG1(&pk.G1.Delta, []fr.Element{_r, _s, _kr})

	start := time.Now()

	// we need to copy and filter the wireValues for each multi exp
	// as pk.G1.A, pk.G1.B and pk.G2.B may have (a significant) number of point at infinity
	var bs1, ar curve.G1Jac

	computeBS1 := func(deviceId int) error {
		deviceLocks[deviceId].Lock()
		defer deviceLocks[deviceId].Unlock()

		var wireValuesBDevice icicle_core.DeviceSlice
		wireValuesB := make([]fr.Element, len(wireValues)-int(pk.NbInfinityB))
		for i, j := 0, 0; j < len(wireValuesB); i++ {
			if pk.InfinityB[i] {
				continue
			}
			wireValuesB[j] = wireValues[i]
			j++
		}

		// Copy scalars to the device and retain ptr to them
		wireValuesBHost := (icicle_core.HostSlice[fr.Element])(wireValuesB)
		wireValuesBHost.CopyToDevice(&wireValuesBDevice, true)
		icicle_bls12377.FromMontgomery(&wireValuesBDevice)

		cfg := icicle_msm.GetDefaultMSMConfig()
		res := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)
		start := time.Now()
		icicle_msm.Msm(wireValuesBDevice, pk.G1Device.B, &cfg, res)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Bs1")
		bs1 = g1ProjectiveToG1Jac(res[0])
		bs1.AddMixed(&pk.G1.Beta)
		bs1.AddMixed(&deltas[1])

		wireValuesBDevice.Free()

		return nil
	}

	computeAR1 := func(deviceId int) error {
		deviceLocks[deviceId].Lock()
		defer deviceLocks[deviceId].Unlock()

		var wireValuesADevice icicle_core.DeviceSlice
		wireValuesA := make([]fr.Element, len(wireValues)-int(pk.NbInfinityA))
		for i, j := 0, 0; j < len(wireValuesA); i++ {
			if pk.InfinityA[i] {
				continue
			}
			wireValuesA[j] = wireValues[i]
			j++
		}

		// Copy scalars to the device and retain ptr to them
		wireValuesAHost := (icicle_core.HostSlice[fr.Element])(wireValuesA)
		wireValuesAHost.CopyToDevice(&wireValuesADevice, true)
		icicle_bls12377.FromMontgomery(&wireValuesADevice)

		cfg := icicle_msm.GetDefaultMSMConfig()
		res := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)
		start := time.Now()
		icicle_msm.Msm(wireValuesADevice, pk.G1Device.A, &cfg, res)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Ar1")
		ar = g1ProjectiveToG1Jac(res[0])

		ar.AddMixed(&pk.G1.Alpha)
		ar.AddMixed(&deltas[0])
		proof.Ar.FromJacobian(&ar)

		wireValuesADevice.Free()

		return nil
	}

	var krs, p1 curve.G1Jac
	computeKrs := func(deviceId int) error {
		deviceLocks[deviceId].Lock()
		defer deviceLocks[deviceId].Unlock()

		cfg := icicle_msm.GetDefaultMSMConfig()
		// filter the wire values if needed
		// TODO Perf @Tabaie worst memory allocation offender
		toRemove := commitmentInfo.GetPrivateCommitted()
		toRemove = append(toRemove, commitmentInfo.CommitmentIndexes())
		_wireValues := filterHeap(wireValues[r1cs.GetNbPublicVariables():], r1cs.GetNbPublicVariables(), internal.ConcatAll(toRemove...))
		_wireValuesHost := (icicle_core.HostSlice[fr.Element])(_wireValues)

		var wireValuesDevice icicle_core.DeviceSlice
		_wireValuesHost.CopyToDevice(&wireValuesDevice, true)
		icicle_bls12377.FromMontgomery(&wireValuesDevice)

		resKrs := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)
		start := time.Now()
		icicle_msm.Msm(wireValuesDevice, pk.G1Device.K, &cfg, resKrs)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Krs")
		krs = g1ProjectiveToG1Jac(resKrs[0])

		wireValuesDevice.Free()

		return nil
	}

	var krs2 curve.G1Jac
	computeKrs2 := func(deviceId int) error {
		deviceLocks[deviceId].Lock()
		defer deviceLocks[deviceId].Unlock()

		// H (witness reduction / FFT part)
		var h icicle_core.DeviceSlice
		h = computeHOnDevice(solution.A, solution.B, solution.C, pk, log, deviceId)
		solution.A = nil
		solution.B = nil
		solution.C = nil
		log.Debug().Msg("go computeHOnDevice")

		// TODO wait h done
		sizeH := int(pk.Domain.Cardinality - 1)

		cfg := icicle_msm.GetDefaultMSMConfig()
		//resKrs2 := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)
		start := time.Now()

		hc2_1 := h.Range(0, sizeH/2, false)
		hc2_2 := h.Range(sizeH/2, sizeH, false)
		resKrs2_1 := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)
		resKrs2_2 := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)

		icicle_msm.Msm(hc2_1, pk.G1Device.Z.Range(0, sizeH/2, false), &cfg, resKrs2_1)
		icicle_msm.Msm(hc2_2, pk.G1Device.Z.Range(sizeH/2, sizeH-1, true), &cfg, resKrs2_2)

		krs2_gpu_1 := g1ProjectiveToG1Jac(resKrs2_1[0])
		krs2_gpu_2 := g1ProjectiveToG1Jac(resKrs2_2[0])

		krs2_gpu_add := krs2_gpu_1.AddAssign(&krs2_gpu_2)
		krs2 = *krs2_gpu_add
		//icicle_msm.Msm(h.RangeTo(sizeH, false), pk.G1Device.Z, &cfg, resKrs2)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Krs2")
		//krs2 = g1ProjectiveToG1Jac(resKrs2[0])

		h.Free()

		return nil
	}

	computeKrs2WithNoSplit := func(deviceId int) error {
		deviceLocks[deviceId].Lock()
		defer deviceLocks[deviceId].Unlock()

		// H (witness reduction / FFT part)
		var h icicle_core.DeviceSlice
		h = computeHOnDevice(solution.A, solution.B, solution.C, pk, log, deviceId)
		solution.A = nil
		solution.B = nil
		solution.C = nil
		log.Debug().Msg("go computeHOnDevice no split")

		// TODO wait h done
		sizeH := int(pk.Domain.Cardinality - 1)
		cfg := icicle_msm.GetDefaultMSMConfig()
		resKrs2 := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)
		start := time.Now()
		icicle_msm.Msm(h.RangeTo(sizeH, false), pk.G1Device.Z, &cfg, resKrs2)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Krs2")
		krs2 = g1ProjectiveToG1Jac(resKrs2[0])
		h.Free()
		return nil
	}

	computeBS2 := func(deviceId int) error {
		deviceLocks[deviceId].Lock()
		defer deviceLocks[deviceId].Unlock()

		var wireValuesBDeviceForG2 icicle_core.DeviceSlice
		wireValuesB := make([]fr.Element, len(wireValues)-int(pk.NbInfinityB))
		for i, j := 0, 0; j < len(wireValuesB); i++ {
			if pk.InfinityB[i] {
				continue
			}
			wireValuesB[j] = wireValues[i]
			j++
		}

		// Copy scalars to the device and retain ptr to them
		wireValuesBHost := (icicle_core.HostSlice[fr.Element])(wireValuesB)
		wireValuesBHost.CopyToDevice(&wireValuesBDeviceForG2, true)
		icicle_bls12377.FromMontgomery(&wireValuesBDeviceForG2)

		// Bs2 (1 multi exp G2 - size = len(wires))
		var Bs, deltaS curve.G2Jac

		cfg := icicle_g2.G2GetDefaultMSMConfig()
		res := make(icicle_core.HostSlice[icicle_g2.G2Projective], 1)
		start := time.Now()
		icicle_g2.G2Msm(wireValuesBDeviceForG2, pk.G2Device.B, &cfg, res)

		log.Debug().Dur("took", time.Since(start)).Msg("MSM Bs2 G2")
		Bs = g2ProjectiveToG2Jac(&res[0])

		deltaS.FromAffine(&pk.G2.Delta)
		deltaS.ScalarMultiplication(&deltaS, &s)
		Bs.AddAssign(&deltaS)
		Bs.AddMixed(&pk.G2.Beta)

		proof.Bs.FromJacobian(&Bs)

		wireValuesBDeviceForG2.Free()

		return nil
	}

	BS2Done := make(chan error, 1)
	icicle_cr.RunOnDevice(deviceIds[2], func(args ...any) {
		BS2Done <- computeBS2(deviceIds[2])
	})

	log.Debug().Msg("go computeBS2")

	// schedule our proof part computations
	arDone := make(chan error, 1)
	icicle_cr.RunOnDevice(deviceIds[1], func(args ...any) {
		arDone <- computeAR1(deviceIds[1])
	})

	log.Debug().Msg("go computeAR1")

	BS1Done := make(chan error, 1)
	icicle_cr.RunOnDevice(deviceIds[3], func(args ...any) {
		BS1Done <- computeBS1(deviceIds[3])
	})

	log.Debug().Msg("go computeBS1")

	KrsDone := make(chan error, 1)
	icicle_cr.RunOnDevice(deviceIds[4], func(args ...any) {
		KrsDone <- computeKrs(deviceIds[4])
	})

	log.Debug().Msg("go computeKrs")

	Krs2Done := make(chan error, 1)
	icicle_cr.RunOnDevice(deviceIds[0], func(args ...any) {
		if opt.Krs2WithoutSplit {
			Krs2Done <- computeKrs2WithNoSplit(deviceIds[0])
		} else {
			Krs2Done <- computeKrs2(deviceIds[0])
		}
	})

	log.Debug().Msg("go computeKrs2")

	<-KrsDone
	krs.AddMixed(&deltas[2])
	<-Krs2Done
	krs.AddAssign(&krs2)

	<-arDone
	p1.ScalarMultiplication(&ar, &s)
	krs.AddAssign(&p1)

	<-BS1Done
	p1.ScalarMultiplication(&bs1, &r)
	krs.AddAssign(&p1)
	proof.Krs.FromJacobian(&krs)

	<-BS2Done
	<-commitmentPokDone

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")
	return proof, nil
}

// Prove generates the proof of knowledge of a r1cs with full witness (secret + public part).
func ProveOnMultiDebugNtt(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*groth16_bls12377.Proof, error) {
	log := logger.Logger().With().Str("curve", r1cs.CurveID().String()).Str("acceleration", "icicle").Int("nbConstraints", r1cs.GetNbConstraints()).Str("backend", "groth16").Logger()
	log.Debug().Msg("start ProveOnMulti")
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new prover config: %w", err)
	}
	if opt.HashToFieldFn == nil {
		opt.HashToFieldFn = hash_to_field.New([]byte(constraint.CommitmentDst))
	}
	if !pk.isDeviceReady() {
		log.Debug().Msg("precomputing proving key on multi GPU")
		if err := pk.setupDevicePointersOnMulti(opt.MultiGpuSelect, opt.FreePkWithGpu); err != nil {
			return nil, fmt.Errorf("setup device pointers: %w", err)
		}
	}

	deviceIds := opt.MultiGpuSelect

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

	solveLimit <- 1
	_solution, err := r1cs.Solve(fullWitness, solverOpts...)
	<-solveLimit
	if err != nil {
		return nil, err
	}

	solution := _solution.(*cs.R1CSSolution)
	wireValues := []fr.Element(solution.W)

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
	commitmentPokDone := make(chan error, 1)
	go func() {
		commitmentsSerialized := make([]byte, fr.Bytes*len(commitmentInfo))
		for i := range commitmentInfo {
			copy(commitmentsSerialized[fr.Bytes*i:], wireValues[commitmentInfo[i].CommitmentIndex].Marshal())
		}

		proof.CommitmentPok, err = pedersen.BatchProve(pk.CommitmentKeys, privateCommittedValues, commitmentsSerialized)
		commitmentPokDone <- err
	}()

	start := time.Now()

	var krs2 curve.G1Jac
	computeKrs2 := func(deviceId int) error {
		deviceLocks[deviceId].Lock()
		defer deviceLocks[deviceId].Unlock()

		// H (witness reduction / FFT part)
		var h icicle_core.DeviceSlice
		h = computeHOnDevice(solution.A, solution.B, solution.C, pk, log, deviceId)
		solution.A = nil
		solution.B = nil
		solution.C = nil
		log.Debug().Msg("go computeHOnDevice")

		// TODO wait h done
		sizeH := int(pk.Domain.Cardinality - 1)

		cfg := icicle_msm.GetDefaultMSMConfig()
		//resKrs2 := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)
		start := time.Now()

		hc2_1 := h.Range(0, sizeH/2, false)
		hc2_2 := h.Range(sizeH/2, sizeH, false)
		resKrs2_1 := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)
		resKrs2_2 := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)

		icicle_msm.Msm(hc2_1, pk.G1Device.Z.Range(0, sizeH/2, false), &cfg, resKrs2_1)
		icicle_msm.Msm(hc2_2, pk.G1Device.Z.Range(sizeH/2, sizeH-1, true), &cfg, resKrs2_2)

		krs2_gpu_1 := g1ProjectiveToG1Jac(resKrs2_1[0])
		krs2_gpu_2 := g1ProjectiveToG1Jac(resKrs2_2[0])

		krs2_gpu_add := krs2_gpu_1.AddAssign(&krs2_gpu_2)
		krs2 = *krs2_gpu_add
		//icicle_msm.Msm(h.RangeTo(sizeH, false), pk.G1Device.Z, &cfg, resKrs2)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Krs2")
		//krs2 = g1ProjectiveToG1Jac(resKrs2[0])

		h.Free()

		return nil
	}

	computeKrs2WithNoSplit := func(deviceId int) error {
		deviceLocks[deviceId].Lock()
		defer deviceLocks[deviceId].Unlock()

		// H (witness reduction / FFT part)
		var h icicle_core.DeviceSlice
		h = computeHOnDevice(solution.A, solution.B, solution.C, pk, log, deviceId)
		solution.A = nil
		solution.B = nil
		solution.C = nil
		log.Debug().Msg("go computeHOnDevice no split")

		// TODO wait h done
		sizeH := int(pk.Domain.Cardinality - 1)
		cfg := icicle_msm.GetDefaultMSMConfig()
		resKrs2 := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)
		start := time.Now()
		icicle_msm.Msm(h.RangeTo(sizeH, false), pk.G1Device.Z, &cfg, resKrs2)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Krs2")
		krs2 = g1ProjectiveToG1Jac(resKrs2[0])
		h.Free()
		return nil
	}

	Krs2Done := make(chan error, 1)
	icicle_cr.RunOnDevice(deviceIds[0], func(args ...any) {
		if opt.Krs2WithoutSplit {
			Krs2Done <- computeKrs2WithNoSplit(deviceIds[0])
		} else {
			Krs2Done <- computeKrs2(deviceIds[0])
		}
	})

	log.Debug().Msg("go computeKrs2")

	<-Krs2Done
	<-commitmentPokDone

	fmt.Sprintln(krs2)

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")
	return proof, nil
}

func computeHOnDevice(a, b, c []fr.Element, pk *ProvingKey, log zerolog.Logger, deviceId int) icicle_core.DeviceSlice {
	// H part of Krs
	// Compute H (hz=ab-c, where z=-2 on ker X^n+1 (z(x)=x^n-1))
	// 	1 - _a = ifft(a), _b = ifft(b), _c = ifft(c)
	// 	2 - ca = fft_coset(_a), ba = fft_coset(_b), cc = fft_coset(_c)
	// 	3 - h = ifft_coset(ca o cb - cc)

	n := len(a)

	// add padding to ensure input length is domain cardinality
	padding := make([]fr.Element, int(pk.Domain.Cardinality)-n)
	a = append(a, padding...)
	b = append(b, padding...)
	c = append(c, padding...)
	n = len(a)

	computeADone := make(chan icicle_core.DeviceSlice, 1)
	computeBDone := make(chan icicle_core.DeviceSlice, 1)
	computeCDone := make(chan icicle_core.DeviceSlice, 1)

	computeInttNttOnDevice := func(scalars []fr.Element, channel chan icicle_core.DeviceSlice) {
		cfg := icicle_ntt.GetDefaultNttConfig()
		scalarsStream, _ := icicle_cr.CreateStream()
		cfg.Ctx.Stream = &scalarsStream
		cfg.Ordering = icicle_core.KNM
		cfg.IsAsync = true
		scalarsHost := icicle_core.HostSliceFromElements(scalars)
		var scalarsDevice icicle_core.DeviceSlice
		scalarsHost.CopyToDeviceAsync(&scalarsDevice, scalarsStream, true)
		start := time.Now()
		icicle_ntt.Ntt(scalarsDevice, icicle_core.KInverse, &cfg, scalarsDevice)
		cfg.Ordering = icicle_core.KMN
		cfg.CosetGen = pk.CosetGenerator
		icicle_ntt.Ntt(scalarsDevice, icicle_core.KForward, &cfg, scalarsDevice)
		icicle_cr.SynchronizeStream(&scalarsStream)
		log.Debug().Dur("took", time.Since(start)).Msg("computeH: NTT + INTT")
		channel <- scalarsDevice
	}

	icicle_cr.RunOnDevice(deviceId, func(args ...any) {
		computeInttNttOnDevice(a, computeADone)
	})
	icicle_cr.RunOnDevice(deviceId, func(args ...any) {
		computeInttNttOnDevice(b, computeBDone)
	})
	icicle_cr.RunOnDevice(deviceId, func(args ...any) {
		computeInttNttOnDevice(c, computeCDone)
	})

	aDevice := <-computeADone
	bDevice := <-computeBDone
	cDevice := <-computeCDone

	vecCfg := icicle_core.DefaultVecOpsConfig()
	icicle_bls12377.FromMontgomery(&aDevice)
	icicle_vecops.VecOp(aDevice, bDevice, aDevice, vecCfg, icicle_core.Mul)
	icicle_vecops.VecOp(aDevice, cDevice, aDevice, vecCfg, icicle_core.Sub)
	icicle_vecops.VecOp(aDevice, pk.DenDevice, aDevice, vecCfg, icicle_core.Mul)
	defer bDevice.Free()
	defer cDevice.Free()

	cfg := icicle_ntt.GetDefaultNttConfig()
	cfg.CosetGen = pk.CosetGenerator
	cfg.Ordering = icicle_core.KNR
	icicle_ntt.Ntt(aDevice, icicle_core.KInverse, &cfg, aDevice)
	icicle_bls12377.FromMontgomery(&aDevice)
	return aDevice
}
