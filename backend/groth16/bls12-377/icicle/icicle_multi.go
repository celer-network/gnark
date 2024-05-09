//go:build icicle

package icicle_bls12377

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"math/big"
	"math/bits"
	"runtime"
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

const (
	device0 = 0 // for ntt
	device1 = 1
	device2 = 2
	device3 = 3
	device4 = 4
)

func (pk *ProvingKey) setupDevicePointersOnMulti() error {
	if pk.deviceInfo != nil {
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
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		denIcicleArrHost := (icicle_core.HostSlice[fr.Element])(denIcicleArr)
		denIcicleArrHost.CopyToDevice(&pk.DenDevice, true)
		icicle_bls12377.FromMontgomery(&pk.DenDevice)
		copyDenDone <- true
	})

	/*************************  Init Domain Device  ***************************/
	initNttDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
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
	icicle_cr.RunOnDevice(device1, func(args ...any) {
		g1AHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.A)
		g1AHost.CopyToDevice(&pk.G1Device.A, true)
		icicle_bls12377.AffineFromMontgomery(&pk.G1Device.A)
		copyADone <- true
	})
	/*************************     B      ***************************/
	copyBDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(device3, func(args ...any) {
		g1BHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.B)
		g1BHost.CopyToDevice(&pk.G1Device.B, true)
		icicle_bls12377.AffineFromMontgomery(&pk.G1Device.B)
		copyBDone <- true
	})
	/*************************     K      ***************************/
	copyKDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(device4, func(args ...any) {
		g1KHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.K)
		g1KHost.CopyToDevice(&pk.G1Device.K, true)
		icicle_bls12377.AffineFromMontgomery(&pk.G1Device.K)
		copyKDone <- true
	})
	/*************************     Z      ***************************/
	copyZDone := make(chan bool, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
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
	icicle_cr.RunOnDevice(device2, func(args ...any) {
		g2BHost := (icicle_core.HostSlice[curve.G2Affine])(pk.G2.B)
		g2BHost.CopyToDevice(&pk.G2Device.B, true)
		icicle_g2.G2AffineFromMontgomery(&pk.G2Device.B)
		copyG2BDone <- true
	})

	<-copyG2BDone
	/*************************  End G2 Device Setup  ***************************/
	return nil
}

const testsleep = 3

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
	if pk.deviceInfo == nil {
		log.Debug().Msg("precomputing proving key on multi GPU")
		if err := pk.setupDevicePointersOnMulti(); err != nil {
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

	_solution, err := r1cs.Solve(fullWitness, solverOpts...)
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
	deltas := curve.BatchScalarMultiplicationG1(&pk.G1.Delta, []fr.Element{_r, _s, _kr})

	start := time.Now()

	commitmentsSerialized := make([]byte, fr.Bytes*len(commitmentInfo))
	for i := range commitmentInfo {
		copy(commitmentsSerialized[fr.Bytes*i:], wireValues[commitmentInfo[i].CommitmentIndex].Marshal())
	}

	if proof.CommitmentPok, err = pedersen.BatchProve(pk.CommitmentKeys, privateCommittedValues, commitmentsSerialized); err != nil {
		return nil, err
	}

	// H (witness reduction / FFT part)
	var h icicle_core.DeviceSlice
	chHDone := make(chan struct{}, 1)
	go func() {
		h = computeHOnDevice(solution.A, solution.B, solution.C, pk, log)

		solution.A = nil
		solution.B = nil
		solution.C = nil
		chHDone <- struct{}{}
	}()

	log.Debug().Msg("go computeHOnDevice")
	//time.Sleep(testsleep * time.Second)

	// we need to copy and filter the wireValues for each multi exp
	// as pk.G1.A, pk.G1.B and pk.G2.B may have (a significant) number of point at infinity
	var wireValuesADevice, wireValuesBDevice, wireValuesBDeviceForG2 icicle_core.DeviceSlice
	chWireValuesA, chWireValuesB, chWireValuesBForG2 := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)

	icicle_cr.RunOnDevice(device1, func(args ...any) {
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

		close(chWireValuesA)
	})

	log.Debug().Msg("go wireValuesAHost")
	//time.Sleep(testsleep * time.Second)

	icicle_cr.RunOnDevice(device3, func(args ...any) {
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

		close(chWireValuesB)
	})

	log.Debug().Msg("go wireValuesBHost")
	//time.Sleep(testsleep * time.Second)

	icicle_cr.RunOnDevice(device2, func(args ...any) {
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

		close(chWireValuesBForG2)
	})

	log.Debug().Msg("go wireValuesBDeviceForG2")
	//time.Sleep(testsleep * time.Second)

	var bs1, ar curve.G1Jac

	computeBS1 := func() error {
		<-chWireValuesB

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

	computeAR1 := func() error {
		<-chWireValuesA

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
	computeKrs := func() error {
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

	var krs2, krs2_cpu curve.G1Jac
	computeKrs2 := func() error {
		<-chHDone
		// TODO wait h done
		sizeH := int(pk.Domain.Cardinality - 1)

		hc := h.RangeTo(sizeH, false)
		hOnHost := make(icicle_core.HostSlice[fr.Element], sizeH)
		icicle_bls12377.ToMontgomery(&hc)
		hOnHost.CopyFromDevice(&hc)

		var h_in_cpu []fr.Element
		for _, d := range hOnHost {
			h_in_cpu = append(h_in_cpu, d)
		}

		var krs2_cpu_1, krs2_cpu_2 curve.G1Jac
		var krs2_cpu_add *curve.G1Jac

		_, err = krs2_cpu.MultiExp(pk.G1.Z, h_in_cpu, ecc.MultiExpConfig{NbTasks: runtime.NumCPU() / 2})
		if err != nil {
			return err
		}

		_, err = krs2_cpu_1.MultiExp(pk.G1.Z[:10], h_in_cpu[:10], ecc.MultiExpConfig{NbTasks: runtime.NumCPU() / 2})
		if err != nil {
			return err
		}

		_, err = krs2_cpu_2.MultiExp(pk.G1.Z[10:], h_in_cpu[10:], ecc.MultiExpConfig{NbTasks: runtime.NumCPU() / 2})
		if err != nil {
			return err
		}

		krs2_cpu_add = krs2_cpu_1.AddAssign(&krs2_cpu_2)
		log.Debug().Msg(fmt.Sprintf("krs2_cpu_1 + krs2_cpu_2 is equal: %v", krs2_cpu_add.Equal(&krs2_cpu)))

		var hc2 icicle_core.DeviceSlice
		hOnHost.CopyToDevice(&hc2, true)
		icicle_bls12377.FromMontgomery(&hc2)

		cfg := icicle_msm.GetDefaultMSMConfig()
		resKrs2 := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)
		start := time.Now()
		log.Debug().Msg(fmt.Sprintf("hc2: %d, G1Device Z: %d, sizeH: %d", hc2.Len(), pk.G1Device.Z.Len(), sizeH))
		icicle_msm.Msm(hc2, pk.G1Device.Z, &cfg, resKrs2)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Krs2")
		krs2 = g1ProjectiveToG1Jac(resKrs2[0])

		log.Debug().Msg(fmt.Sprintf("krs2 is equal: %v", krs2.Equal(&krs2_cpu)))

		var krs2_gpu_add *curve.G1Jac

		hc2_1 := hc2.Range(0, sizeH/2, false)
		hc2_2 := hc2.Range(sizeH/2, sizeH-1, false)

		resKrs2_1 := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)
		resKrs2_2 := make(icicle_core.HostSlice[icicle_bls12377.Projective], 1)
		icicle_msm.Msm(hc2_1, pk.G1Device.Z.Range(0, sizeH/2, false), &cfg, resKrs2_1)
		icicle_msm.Msm(hc2_2, pk.G1Device.Z.Range(sizeH/2, sizeH-1, false), &cfg, resKrs2_2)

		krs2_gpu_1 := g1ProjectiveToG1Jac(resKrs2_1[0])
		krs2_gpu_2 := g1ProjectiveToG1Jac(resKrs2_2[0])

		krs2_gpu_add = krs2_gpu_1.AddAssign(&krs2_gpu_2)

		log.Debug().Msg(fmt.Sprintf("krs2_gpu_add is equal: %v", krs2_cpu.Equal(krs2_gpu_add)))

		h.Free()
		return nil
	}

	computeBS2 := func() error {
		// Bs2 (1 multi exp G2 - size = len(wires))
		var Bs, deltaS curve.G2Jac

		<-chWireValuesBForG2

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
	icicle_cr.RunOnDevice(device2, func(args ...any) {
		BS2Done <- computeBS2()
	})

	log.Debug().Msg("go computeBS2")
	//time.Sleep(testsleep * time.Second)

	// schedule our proof part computations
	arDone := make(chan error, 1)
	icicle_cr.RunOnDevice(device1, func(args ...any) {
		arDone <- computeAR1()
	})

	log.Debug().Msg("go computeAR1")
	//time.Sleep(testsleep * time.Second)

	BS1Done := make(chan error, 1)
	icicle_cr.RunOnDevice(device3, func(args ...any) {
		BS1Done <- computeBS1()
	})

	log.Debug().Msg("go computeBS1")
	//time.Sleep(testsleep * time.Second)

	KrsDone := make(chan error, 1)
	icicle_cr.RunOnDevice(device4, func(args ...any) {
		KrsDone <- computeKrs()
	})

	log.Debug().Msg("go computeKrs")
	//time.Sleep(testsleep * time.Second)

	Krs2Done := make(chan error, 1)
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		Krs2Done <- computeKrs2()
	})

	log.Debug().Msg("go computeKrs2")
	//time.Sleep(testsleep * time.Second)

	<-KrsDone
	<-Krs2Done
	<-BS2Done
	<-arDone
	<-BS1Done

	krs.AddMixed(&deltas[2])

	krs.AddAssign(&krs2)

	p1.ScalarMultiplication(&ar, &s)
	krs.AddAssign(&p1)

	p1.ScalarMultiplication(&bs1, &r)
	krs.AddAssign(&p1)

	proof.Krs.FromJacobian(&krs)

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")
	return proof, nil
}

func computeHOnDevice(a, b, c []fr.Element, pk *ProvingKey, log zerolog.Logger) icicle_core.DeviceSlice {
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

	icicle_cr.RunOnDevice(device0, func(args ...any) {
		computeInttNttOnDevice(a, computeADone)
	})
	icicle_cr.RunOnDevice(device0, func(args ...any) {
		computeInttNttOnDevice(b, computeBDone)
	})
	icicle_cr.RunOnDevice(device0, func(args ...any) {
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
