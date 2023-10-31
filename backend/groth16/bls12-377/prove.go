package groth16

import (
	"fmt"
	"math/big"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/logger"
	"github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bls12377"
	"github.com/rs/zerolog/log"
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

	deltas, r, s, err := CalDeltas(&pk.G1.Delta)
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

	go func() {
		wireValuesADevice, wireValuesADeviceErr = PrepareWireValueOnDevice(wireValues, pk.NbInfinityA, pk.InfinityA)
		close(chWireValuesA)
	}()

	go func() {
		wireValuesBDevice, wireValuesBDeviceErr = PrepareWireValueOnDevice(wireValues, pk.NbInfinityB, pk.InfinityB)
		close(chWireValuesB)
	}()

	var ar, bs1 *curve.G1Jac

	computeBS1 := func() error {
		<-chWireValuesB

		var bs1Err error
		bs1, bs1Err = Bs1MsmOnDevice(wireValuesBDevice.p, pk.G1Device.B, &pk.G1.Beta, &deltas[1], wireValuesBDevice.size)
		if bs1Err != nil {
			return bs1Err
		}
		return nil
	}

	computeAR1 := func() error {
		<-chWireValuesA
		var arErr error
		ar, arErr = Ar1MsmOnDevice(wireValuesADevice.p, pk.G1Device.A, &pk.G1.Alpha, &deltas[0], wireValuesADevice.size, &proof.Ar)
		if arErr != nil {
			return arErr
		}
		return nil
	}

	computeKRS := func() error {
		// we could NOT split the Krs multiExp in 2, and just append pk.G1.K and pk.G1.Z
		// however, having similar lengths for our tasks helps with parallelism
		krsErr := KrsMsmOnDevice(h, pk.G1Device.Z, pk.G1Device.K, pk.Domain.Cardinality, wireValues,
			r1cs.CommitmentInfo.PrivateToPublic(), pk.G1InfPointIndices.K, r1cs.GetNbPublicVariables(), &deltas[2], &proof.Krs, ar, bs1, s, r)
		if krsErr != nil {
			return krsErr
		}
		return nil
	}

	computeBS2 := func() error {
		<-chWireValuesB
		return Bs2MsmOnDevice(wireValuesBDevice.p, pk.G2Device.B, wireValuesBDevice.size, &pk.G2.Delta, &pk.G2.Beta, s, &proof.Bs)
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
	if err = computeKRS(); err != nil {
		return nil, err
	}
	// wireValues = nil

	if err = computeBS1(); err != nil {
		return nil, err
	}
	if err = computeAR1(); err != nil {
		return nil, err
	}
	if err = computeBS2(); err != nil {
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

func CalDeltas(pkDelta *curve.G1Affine) ([]curve.G1Affine, *big.Int, *big.Int, error) {
	// sample random r and s
	r := new(big.Int)
	s := new(big.Int)
	var _r, _s, _kr fr.Element
	if _, err := _r.SetRandom(); err != nil {
		return nil, nil, nil, err
	}
	if _, err := _s.SetRandom(); err != nil {
		return nil, nil, nil, err
	}
	_kr.Mul(&_r, &_s).Neg(&_kr)
	_r.BigInt(r)
	_s.BigInt(s)

	// computes r[δ], s[δ], kr[δ]
	deltas := curve.BatchScalarMultiplicationG1(pkDelta, []fr.Element{_r, _s, _kr})
	return deltas, r, s, nil
}

// bs1
func Bs1MsmOnDevice(wireValuesBDevice, B unsafe.Pointer, beta, deltas1 *curve.G1Affine, size int) (bs1 *curve.G1Jac, err error) {
	var timing time.Duration
	if bs1, _, err, timing = MsmOnDevice(wireValuesBDevice, B, size, BUCKET_FACTOR, true); err != nil {
		return
	}
	log.Debug().Dur("took", timing).Msg("Icicle API: MSM BS1 MSM")
	bs1.AddMixed(beta)
	bs1.AddMixed(deltas1)
	return bs1, nil
}

// ar1
func Ar1MsmOnDevice(wireValuesADevice, A unsafe.Pointer, alpha, deltas0 *curve.G1Affine, size int, proofAr *curve.G1Affine) (ar *curve.G1Jac, err error) {
	var timing time.Duration
	if ar, _, err, timing = MsmOnDevice(wireValuesADevice, A, size, BUCKET_FACTOR, true); err != nil {
		return
	}
	log.Debug().Dur("took", timing).Msg("Icicle API: MSM AR1 MSM")
	ar.AddMixed(alpha)
	ar.AddMixed(deltas0)
	proofAr.FromJacobian(ar)
	return
}

// bs2
func Bs2MsmOnDevice(wireValuesBDevice, B unsafe.Pointer, size int, g2Delta, g2Beta *curve.G2Affine, s *big.Int, proofBs *curve.G2Affine) error {
	var bs *curve.G2Jac
	var err error
	deltaS := new(curve.G2Jac)
	var timing time.Duration
	if bs, _, err, timing = MsmG2OnDevice(wireValuesBDevice, B, size, BUCKET_FACTOR, true); err != nil {
		return err
	}
	log.Debug().Dur("took", timing).Msg("Icicle API: MSM G2 BS")

	deltaS.FromAffine(g2Delta)
	deltaS.ScalarMultiplication(deltaS, s)

	bs.AddAssign(deltaS)
	bs.AddMixed(g2Beta)

	proofBs.FromJacobian(bs)
	return nil
}

// krs
func KrsMsmOnDevice(h, Z, deviceK unsafe.Pointer, cardinality uint64, wireValues []fr.Element, privateToPublic, k []int,
	nbPublicVariables int, deltas2, Krs *curve.G1Affine, ar, bs1 *curve.G1Jac, s, r *big.Int) error {
	// we could NOT split the Krs multiExp in 2, and just append pk.G1.K and pk.G1.Z
	// however, having similar lengths for our tasks helps with parallelism

	var krs, krs2, p1 *curve.G1Jac
	sizeH := int(cardinality - 1) // comes from the fact the deg(H)=(n-1)+(n-1)-n=n-2

	icicleRes, _, err, timing := MsmOnDevice(h, Z, sizeH, BUCKET_FACTOR, true)
	log.Debug().Dur("took", timing).Msg("Icicle API: MSM KRS2 MSM")
	if err != nil {
		return err
	}

	krs2 = icicleRes
	// filter the wire values if needed;
	_wireValues := filter(wireValues, privateToPublic)

	scals := _wireValues[nbPublicVariables:]

	// Filter scalars matching infinity point indices
	for _, indexToRemove := range k {
		scals = append(scals[:indexToRemove], scals[indexToRemove+1:]...)
	}

	scalarBytes := len(scals) * fr.Bytes
	scalars_d, err := goicicle.CudaMalloc(scalarBytes)
	if err != nil {
		return err
	}
	ret := goicicle.CudaMemCpyHtoD[fr.Element](scalars_d, scals, scalarBytes)
	if ret != 0 {
		return fmt.Errorf("CudaMemCpyHtoD in krs, ret: %d", ret)
	}
	err = MontConvOnDevice(scalars_d, len(scals), false)
	if err != nil {
		return err
	}

	icicleRes, _, err, timing = MsmOnDevice(scalars_d, deviceK, len(scals), BUCKET_FACTOR, true)
	if err != nil {
		return err
	}
	log.Debug().Dur("took", timing).Msg("Icicle API: MSM KRS MSM")

	ret = goicicle.CudaFree(scalars_d)
	if ret != 0 {
		return fmt.Errorf("krs CudaFree failt, ret: %d", ret)
	}

	krs = icicleRes
	krs.AddMixed(deltas2)

	krs.AddAssign(krs2)

	p1 = new(curve.G1Jac)
	p1.ScalarMultiplication(ar, s)
	krs.AddAssign(p1)

	p1.ScalarMultiplication(bs1, r)
	krs.AddAssign(p1)

	Krs.FromJacobian(krs)
	return nil
}
