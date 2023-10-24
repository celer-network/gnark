// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gnark DO NOT EDIT

package groth16

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/logger"
	"github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bls12377"
	"math/big"
	"time"
	"unsafe"
)

// Proof represents a Groth16 proof that was encoded with a ProvingKey and can be verified
// with a valid statement and a VerifyingKey
// Notation follows Figure 4. in DIZK paper https://eprint.iacr.org/2018/691.pdf
type Proof struct {
	Ar, Krs                   curve.G1Affine
	Bs                        curve.G2Affine
	Commitment, CommitmentPok curve.G1Affine
}

// isValid ensures proof elements are in the correct subgroup
func (proof *Proof) isValid() bool {
	return proof.Ar.IsInSubGroup() && proof.Krs.IsInSubGroup() && proof.Bs.IsInSubGroup()
}

// CurveID returns the curveID
func (proof *Proof) CurveID() ecc.ID {
	return curve.ID
}

const BUCKET_FACTOR int = 10

// Prove generates the proof of knowledge of a r1cs with full witness (secret + public part).
func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*Proof, error) {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, err
	}

	log := logger.Logger().With().Str("curve", r1cs.CurveID().String()).Int("nbConstraints", r1cs.GetNbConstraints()).Str("backend", "groth16").Logger()

	proof := &Proof{}

	solverOpts := opt.SolverOpts[:len(opt.SolverOpts):len(opt.SolverOpts)]

	if r1cs.CommitmentInfo.Is() {
		solverOpts = append(solverOpts, solver.OverrideHint(r1cs.CommitmentInfo.HintID, func(_ *big.Int, in []*big.Int, out []*big.Int) error {
			// Perf-TODO: Converting these values to big.Int and back may be a performance bottleneck.
			// If that is the case, figure out a way to feed the solution vector into this function
			if len(in) != r1cs.CommitmentInfo.NbCommitted() { // TODO: Remove
				return fmt.Errorf("unexpected number of committed variables")
			}
			values := make([]fr.Element, r1cs.CommitmentInfo.NbPrivateCommitted)
			nbPublicCommitted := len(in) - len(values)
			inPrivate := in[nbPublicCommitted:]
			for i, inI := range inPrivate {
				values[i].SetBigInt(inI)
			}

			var err error
			proof.Commitment, proof.CommitmentPok, err = pk.CommitmentKey.Commit(values)
			if err != nil {
				return err
			}

			var res fr.Element
			res, err = solveCommitmentWire(&r1cs.CommitmentInfo, &proof.Commitment, in[:r1cs.CommitmentInfo.NbPublicCommitted()])
			res.BigInt(out[0])
			return err
		}))
	}

	_solution, err := r1cs.Solve(fullWitness, solverOpts...)
	if err != nil {
		return nil, err
	}

	solution := _solution.(*cs.R1CSSolution)
	wireValues := []fr.Element(solution.W)

	start := time.Now()

	// H (witness reduction / FFT part)
	var h unsafe.Pointer
	var h_err error
	chHDone := make(chan struct{}, 1)
	go func() {
		h, h_err = computeH(solution.A, solution.B, solution.C, pk)
		solution.A = nil
		solution.B = nil
		solution.C = nil
		chHDone <- struct{}{}
	}()

	// we need to copy and filter the wireValues for each multi exp
	// as pk.G1.A, pk.G1.B and pk.G2.B may have (a significant) number of point at infinity
	var wireValuesADevice, wireValuesBDevice OnDeviceData
	var wireValuesADeviceErr, wireValuesBDeviceErr error
	chWireValuesA, chWireValuesB := make(chan struct{}, 1), make(chan struct{}, 1)

	// go func() {
	// 	wireValuesA := make([]fr.Element, len(wireValues)-int(pk.NbInfinityA))
	// 	for i, j := 0, 0; j < len(wireValuesA); i++ {
	// 		if pk.InfinityA[i] {
	// 			continue
	// 		}
	// 		wireValuesA[j] = wireValues[i]
	// 		j++
	// 	}

	// 	wireValuesASize := len(wireValuesA)
	// 	scalarBytes := wireValuesASize * fr.Bytes
	// 	wireValuesADevicePtr, _ := goicicle.CudaMalloc(scalarBytes)
	// 	goicicle.CudaMemCpyHtoD[fr.Element](wireValuesADevicePtr, wireValuesA, scalarBytes)
	// 	MontConvOnDevice(wireValuesADevicePtr, wireValuesASize, false)
	// 	wireValuesADevice = OnDeviceData{wireValuesADevicePtr, wireValuesASize}

	// 	close(chWireValuesA)
	// }()
	// go func() {
	// 	wireValuesB := make([]fr.Element, len(wireValues)-int(pk.NbInfinityB))
	// 	for i, j := 0, 0; j < len(wireValuesB); i++ {
	// 		if pk.InfinityB[i] {
	// 			continue
	// 		}
	// 		wireValuesB[j] = wireValues[i]
	// 		j++
	// 	}

	// 	wireValuesBSize := len(wireValuesB)
	// 	scalarBytes := wireValuesBSize * fr.Bytes
	// 	wireValuesBDevicePtr, _ := goicicle.CudaMalloc(scalarBytes)
	// 	goicicle.CudaMemCpyHtoD[fr.Element](wireValuesBDevicePtr, wireValuesB, scalarBytes)
	// 	MontConvOnDevice(wireValuesBDevicePtr, wireValuesBSize, false)
	// 	wireValuesBDevice = OnDeviceData{wireValuesBDevicePtr, wireValuesBSize}

	// 	close(chWireValuesB)
	// }()

	go func() {
		wireValuesADevice, wireValuesADeviceErr = PrepareWireValueOnDevice(wireValues, pk.NbInfinityA, pk.InfinityA)
		close(chWireValuesA)
	}()

	go func() {
		wireValuesBDevice, wireValuesBDeviceErr = PrepareWireValueOnDevice(wireValues, pk.NbInfinityB, pk.InfinityB)
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

	computeBS1 := func() {
		<-chWireValuesB

		icicleRes, _, _, time := MsmOnDevice(wireValuesBDevice.p, pk.G1Device.B, wireValuesBDevice.size, BUCKET_FACTOR, true)
		log.Debug().Dur("took", time).Msg("Icicle API: MSM BS1 MSM")

		bs1 = icicleRes
		bs1.AddMixed(&pk.G1.Beta)
		bs1.AddMixed(&deltas[1])
	}

	computeAR1 := func() {
		<-chWireValuesA

		icicleRes, _, _, timing := MsmOnDevice(wireValuesADevice.p, pk.G1Device.A, wireValuesADevice.size, BUCKET_FACTOR, true)
		log.Debug().Dur("took", timing).Msg("Icicle API: MSM AR1 MSM")

		ar = icicleRes
		ar.AddMixed(&pk.G1.Alpha)
		ar.AddMixed(&deltas[0])
		proof.Ar.FromJacobian(&ar)
	}

	computeKRS := func() {
		// we could NOT split the Krs multiExp in 2, and just append pk.G1.K and pk.G1.Z
		// however, having similar lengths for our tasks helps with parallelism

		var krs, krs2, p1 curve.G1Jac
		sizeH := int(pk.Domain.Cardinality - 1) // comes from the fact the deg(H)=(n-1)+(n-1)-n=n-2

		icicleRes, _, _, timing := MsmOnDevice(h, pk.G1Device.Z, sizeH, BUCKET_FACTOR, true)
		log.Debug().Dur("took", timing).Msg("Icicle API: MSM KRS2 MSM")

		krs2 = icicleRes
		// filter the wire values if needed;
		_wireValues := filter(wireValues, r1cs.CommitmentInfo.PrivateToPublic())

		scals := _wireValues[r1cs.GetNbPublicVariables():]

		// Filter scalars matching infinity point indices
		for _, indexToRemove := range pk.G1InfPointIndices.K {
			scals = append(scals[:indexToRemove], scals[indexToRemove+1:]...)
		}

		scalarBytes := len(scals) * fr.Bytes
		scalars_d, _ := goicicle.CudaMalloc(scalarBytes)
		goicicle.CudaMemCpyHtoD[fr.Element](scalars_d, scals, scalarBytes)
		MontConvOnDevice(scalars_d, len(scals), false)

		icicleRes, _, _, timing = MsmOnDevice(scalars_d, pk.G1Device.K, len(scals), BUCKET_FACTOR, true)
		log.Debug().Dur("took", timing).Msg("Icicle API: MSM KRS MSM")

		goicicle.CudaFree(scalars_d)

		krs = icicleRes
		krs.AddMixed(&deltas[2])

		krs.AddAssign(&krs2)

		p1.ScalarMultiplication(&ar, &s)
		krs.AddAssign(&p1)

		p1.ScalarMultiplication(&bs1, &r)
		krs.AddAssign(&p1)

		proof.Krs.FromJacobian(&krs)
	}

	computeBS2 := func() error {
		// Bs2 (1 multi exp G2 - size = len(wires))
		var Bs, deltaS curve.G2Jac

		<-chWireValuesB

		icicleG2Res, _, _, timing := MsmG2OnDevice(wireValuesBDevice.p, pk.G2Device.B, wireValuesBDevice.size, BUCKET_FACTOR, true)
		log.Debug().Dur("took", timing).Msg("Icicle API: MSM G2 BS")

		Bs = icicleG2Res
		deltaS.FromAffine(&pk.G2.Delta)
		deltaS.ScalarMultiplication(&deltaS, &s)
		Bs.AddAssign(&deltaS)
		Bs.AddMixed(&pk.G2.Beta)

		proof.Bs.FromJacobian(&Bs)
		return nil
	}

	// wait for FFT to end, as it uses all our CPUs
	<-chHDone
	if h_err != nil {
		return nil, h_err
	}
	if wireValuesADeviceErr != nil {
		return nil, wireValuesADeviceErr
	}
	if wireValuesBDeviceErr != nil {
		return nil, wireValuesBDeviceErr
	}
	// schedule our proof part computations
	startMSM := time.Now()
	computeBS1()
	computeAR1()
	computeKRS()
	if err := computeBS2(); err != nil {
		return nil, err
	}
	log.Debug().Dur("took", time.Since(startMSM)).Msg("Total MSM time")

	log.Debug().Dur("took", time.Since(start)).Msg("prover done; TOTAL PROVE TIME")

	go func() {
		goicicle.CudaFree(wireValuesADevice.p)
		goicicle.CudaFree(wireValuesBDevice.p)
		goicicle.CudaFree(h)
	}()

	return proof, nil
}

// if len(toRemove) == 0, returns slice
// else, returns a new slice without the indexes in toRemove
// this assumes toRemove indexes are sorted and len(slice) > len(toRemove)
func filter(slice []fr.Element, toRemove []int) (r []fr.Element) {

	if len(toRemove) == 0 {
		return slice
	}
	r = make([]fr.Element, 0, len(slice)-len(toRemove))

	j := 0
	// note: we can optimize that for the likely case where len(slice) >>> len(toRemove)
	for i := 0; i < len(slice); i++ {
		if j < len(toRemove) && i == toRemove[j] {
			j++
			continue
		}
		r = append(r, slice[i])
	}

	return r
}

func computeH(a, b, c []fr.Element, pk *ProvingKey) (unsafe.Pointer, error) {
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

	sizeBytes := n * fr.Bytes

	log := logger.Logger()

	/*********** Copy a,b,c to Device Start ************/
	computeHTime := time.Now()
	copyADone := make(chan unsafe.Pointer, 1)
	copyBDone := make(chan unsafe.Pointer, 1)
	copyCDone := make(chan unsafe.Pointer, 1)

	convTime := time.Now()
	go CopyToDevice(a, sizeBytes, copyADone)
	go CopyToDevice(b, sizeBytes, copyBDone)
	go CopyToDevice(c, sizeBytes, copyCDone)

	a_device := <-copyADone
	b_device := <-copyBDone
	c_device := <-copyCDone

	log.Debug().Dur("took", time.Since(convTime)).Msg("Icicle API: Conv and Copy a,b,c")
	/*********** Copy a,b,c to Device End ************/

	computeInttNttDone := make(chan error, 1)
	computeInttNttOnDevice := func(devicePointer unsafe.Pointer) {
		a_intt_d, timings_a := INttOnDevice(devicePointer, pk.DomainDevice.TwiddlesInv, nil, n, sizeBytes, false)
		log.Debug().Dur("took", timings_a[0]).Msg("Icicle API: INTT Reverse")
		log.Debug().Dur("took", timings_a[1]).Msg("Icicle API: INTT Interp")

		timing_a2 := NttOnDevice(devicePointer, a_intt_d, pk.DomainDevice.Twiddles, pk.DomainDevice.CosetTable, n, n, sizeBytes, true)
		log.Debug().Dur("took", timing_a2[1]).Msg("Icicle API: NTT Coset Reverse")
		log.Debug().Dur("took", timing_a2[0]).Msg("Icicle API: NTT Coset Eval")

		computeInttNttDone <- nil

		goicicle.CudaFree(a_intt_d)
	}

	computeInttNttTime := time.Now()
	go computeInttNttOnDevice(a_device)
	go computeInttNttOnDevice(b_device)
	go computeInttNttOnDevice(c_device)
	_, _, _ = <-computeInttNttDone, <-computeInttNttDone, <-computeInttNttDone
	log.Debug().Dur("took", time.Since(computeInttNttTime)).Msg("Icicle API: INTT and NTT")

	poltime := PolyOps(a_device, b_device, c_device, pk.DenDevice, n)
	log.Debug().Dur("took", poltime[0]).Msg("Icicle API: PolyOps Mul a b")
	log.Debug().Dur("took", poltime[1]).Msg("Icicle API: PolyOps Sub a c")
	log.Debug().Dur("took", poltime[2]).Msg("Icicle API: PolyOps Mul a den")

	h, timings_final := INttOnDevice(a_device, pk.DomainDevice.TwiddlesInv, pk.DomainDevice.CosetTableInv, n, sizeBytes, true)
	log.Debug().Dur("took", timings_final[0]).Msg("Icicle API: INTT Coset Reverse")
	log.Debug().Dur("took", timings_final[1]).Msg("Icicle API: INTT Coset Interp")

	go func() {
		goicicle.CudaFree(a_device)
		goicicle.CudaFree(b_device)
		goicicle.CudaFree(c_device)
	}()

	_, err := icicle.ReverseScalars(h, n)
	if err != nil {
		fmt.Println(err)
	}
	log.Debug().Dur("took", time.Since(computeHTime)).Msg("Icicle API: computeH")

	return h, nil
}

func PrepareWireValueOnDevice(wireValues []fr.Element, nbInfinityA uint64, infinityA []bool) (data OnDeviceData, err error) {
	wireValuesA := make([]fr.Element, len(wireValues)-int(nbInfinityA))
	for i, j := 0, 0; j < len(wireValuesA); i++ {
		if infinityA[i] {
			continue
		}
		wireValuesA[j] = wireValues[i]
		j++
	}

	data.size = len(wireValuesA)
	scalarBytes := data.size * fr.Bytes
	if data.p, err = goicicle.CudaMalloc(scalarBytes); err != nil {
		return
	}
	if ret := goicicle.CudaMemCpyHtoD[fr.Element](data.p, wireValuesA, scalarBytes); ret != 0 {
		err = fmt.Errorf("CudaMemCpyHtoD in PrepareWireValueOnDevice %d", ret)
		return
	}
	if err = MontConvOnDevice(data.p, data.size, false); err != nil {
		return
	}
	return
}
