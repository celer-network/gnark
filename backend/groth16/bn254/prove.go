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
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
	"github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bn254"
	"math/big"
	"runtime"
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

// Prove generates the proof of knowledge of a r1cs with full witness (secret + public part).
func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*Proof, error) {
	//pk_for_gpu := *pk

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
	var h []fr.Element
	var hOnDevice unsafe.Pointer
	chHDone := make(chan struct{}, 1)
	go func() {
		hOnDevice = computeHOnDevice(solution.A, solution.B, solution.C, pk)
		h = computeH(solution.A, solution.B, solution.C, &pk.Domain)
		solution.A = nil
		solution.B = nil
		solution.C = nil
		chHDone <- struct{}{}
	}()

	// we need to copy and filter the wireValues for each multi exp
	// as pk.G1.A, pk.G1.B and pk.G2.B may have (a significant) number of point at infinity
	var wireValuesA, wireValuesB []fr.Element
	var wireValuesADevice, wireValuesBDevice OnDeviceData
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

		wireValuesASize := len(wireValuesA)
		scalarBytes := wireValuesASize * fr.Bytes
		wireValuesADevicePtr, _ := goicicle.CudaMalloc(scalarBytes)
		goicicle.CudaMemCpyHtoD[fr.Element](wireValuesADevicePtr, wireValuesA, scalarBytes)
		MontConvOnDevice(wireValuesADevicePtr, wireValuesASize, false)
		wireValuesADevice = OnDeviceData{wireValuesADevicePtr, wireValuesASize}

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

		wireValuesBSize := len(wireValuesB)
		scalarBytes := wireValuesBSize * fr.Bytes
		wireValuesBDevicePtr, _ := goicicle.CudaMalloc(scalarBytes)
		goicicle.CudaMemCpyHtoD[fr.Element](wireValuesBDevicePtr, wireValuesB, scalarBytes)
		MontConvOnDevice(wireValuesBDevicePtr, wireValuesBSize, false)
		wireValuesBDevice = OnDeviceData{wireValuesBDevicePtr, wireValuesBSize}

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
		if _, err := bs1.MultiExp(pk.G1.B, wireValuesB, ecc.MultiExpConfig{NbTasks: n / 2}); err != nil {
			chBs1Done <- err
			close(chBs1Done)
			return
		}

		icicleRes, _, _, timing := MsmOnDevice(wireValuesBDevice.p, pk.G1Device.B, wireValuesBDevice.size, 10, true)
		log.Debug().Dur("took", timing).Msg("Icicle API: MSM BS1 MSM")
		fmt.Printf("icicleRes == bs1, %v \n", icicleRes.Equal(&bs1))

		bs1.AddMixed(&pk.G1.Beta)
		bs1.AddMixed(&deltas[1])
		chBs1Done <- nil
	}

	chArDone := make(chan error, 1)
	computeAR1 := func() {
		<-chWireValuesA
		if _, err := ar.MultiExp(pk.G1.A, wireValuesA, ecc.MultiExpConfig{NbTasks: n / 2}); err != nil {
			chArDone <- err
			close(chArDone)
			return
		}

		icicleRes, _, _, timing := MsmOnDevice(wireValuesADevice.p, pk.G1Device.A, wireValuesADevice.size, 10, true)
		log.Debug().Dur("took", timing).Msg("Icicle API: MSM AR1 MSM")
		fmt.Printf("icicleRes == ar, %v \n", icicleRes.Equal(&ar))

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
			_, err := krs2.MultiExp(pk.G1.Z, h[:sizeH], ecc.MultiExpConfig{NbTasks: n / 2})

			icicleRes, _, _, timing := MsmOnDevice(hOnDevice, pk.G1Device.Z, sizeH, 10, true)
			log.Debug().Dur("took", timing).Msg("Icicle API: MSM KRS2 MSM")
			fmt.Printf("icicleRes == krs2, %v \n", icicleRes.Equal(&krs2))

			chKrs2Done <- err
		}()

		// filter the wire values if needed;
		_wireValues := filter(wireValues, r1cs.CommitmentInfo.PrivateToPublic())

		if _, err := krs.MultiExp(pk.G1.K, _wireValues[r1cs.GetNbPublicVariables():], ecc.MultiExpConfig{NbTasks: n / 2}); err != nil {
			chKrsDone <- err
			return
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
		if _, err := Bs.MultiExp(pk.G2.B, wireValuesB, ecc.MultiExpConfig{NbTasks: nbTasks}); err != nil {
			return err
		}

		icicleG2Res, _, _, timing := MsmG2OnDevice(wireValuesBDevice.p, pk.G2Device.B, wireValuesBDevice.size, 10, true)
		log.Debug().Dur("took", timing).Msg("Icicle API: MSM G2 BS")
		fmt.Printf("icicleRes == bs1, %v \n", icicleG2Res.Equal(&Bs))

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

func computeHOnDevice(a, b, c []fr.Element, pk *ProvingKey) unsafe.Pointer {
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

	icicle.ReverseScalars(h, n)
	log.Debug().Dur("took", time.Since(computeHTime)).Msg("Icicle API: computeH")

	return h
}
