package zkpschemes

const Groth16Prove = `

import (
	{{ template "import_curve" . }}
	{{ template "import_backend" . }}
	"runtime"
	"sync"
	"github.com/consensys/gnark/internal/utils/debug"
	"github.com/consensys/gnark/internal/utils/parallel"
	"github.com/consensys/gnark/backend"
)


// Proof represents a Groth16 proof that was encoded with a ProvingKey and can be verified
// with a valid statement and a VerifyingKey
type Proof struct {
	Ar, Krs curve.G1Affine
	Bs      curve.G2Affine
}

var (
	root        fr.Element
	minusTwoInv fr.Element
)

func init() {
	root.SetString(backend_{{toLower .Curve}}.RootOfUnityStr)
	minusTwoInv.SetUint64(2)
	minusTwoInv.Neg(&minusTwoInv).
		Inverse(&minusTwoInv)
}

// Prove creates proof from a circuit
func Prove(r1cs *backend_{{toLower .Curve}}.R1CS, pk *ProvingKey, solution map[string]interface{}) (*Proof, error) {
	proof := &Proof{}

	// fft domain (computeH)
	fftDomain := backend_{{toLower .Curve}}.NewDomain(root, backend_{{toLower .Curve}}.MaxOrder, r1cs.NbConstraints)

	// sample random r and s
	var r, s, _r, _s fr.Element
	r.SetRandom()
	s.SetRandom()
	_r = r.ToRegular()
	_s = s.ToRegular()

	// Solve the R1CS and compute the a, b, c vectors
	wireValues := make([]fr.Element, r1cs.NbWires)
	a := make([]fr.Element, r1cs.NbConstraints, fftDomain.Cardinality) 
	b := make([]fr.Element, r1cs.NbConstraints, fftDomain.Cardinality)
	c := make([]fr.Element, r1cs.NbConstraints, fftDomain.Cardinality)
	err := r1cs.Solve(solution, a, b, c, wireValues)
	if err != nil {
		return nil, err
	}
	// get the wire values in regular form
	// wireValues := make([]fr.Element, len(r1cs.WireValues))
	work := func(start, end int) {
		for i := start; i < end; i++ {
			wireValues[i].FromMont()
		}
	}
	parallel.Execute( len(wireValues), work)

	// compute proof elements
	// 4 multiexp + 1 FFT
	// G2 multiexp is likely the most compute intensive task here

	// H (witness reduction / FFT part)
	chH := computeH(a, b, c, fftDomain)

	// these tokens ensure multiExp tasks are enqueue in order in the pool
	// so that bs2 doesn't compete with ar1 and bs1 for resources
	// hence delaying Krs compute longer than needed
	chTokenA := make(chan struct{}, 1)
	chTokenB := make(chan struct{}, 1)

	// Ar1 (1 multi exp G1 - size = len(wires))
	chAr1 := computeAr1(pk, _r, wireValues, chTokenA)

	// Bs1 (1 multi exp G1 - size = len(wires))
	chBs1 := computeBs1(pk, _s, wireValues, chTokenA, chTokenB)

	// Bs2 (1 multi exp G2 - size = len(wires))
	chBs2 := computeBs2(pk, _s, wireValues, chTokenB)

	// Krs -- computeKrs go routine will wait for H, Ar1 and Bs1 to be done
	h := <-chH
	proof.Ar = <-chAr1
	bs := <-chBs1
	proof.Krs = <-computeKrs(pk, r, s, _r, _s, wireValues, proof.Ar, bs, h, r1cs.NbWires-r1cs.NbPublicWires, chTokenB)

	proof.Bs = <-chBs2

	return proof, nil
}

func computeKrs(pk *ProvingKey, r, s, _r, _s fr.Element, wireValues []fr.Element, ar, bs curve.G1Affine, h []fr.Element, kIndex int, chToken chan struct{}) <-chan curve.G1Affine {
	chResult := make(chan curve.G1Affine, 1)
	go func() {
		var Krs curve.G1Jac
		var KrsAffine curve.G1Affine

		// Krs (H part + priv part)
		r.Mul(&r, &s).Neg(&r)
		points := append(pk.G1.Z, pk.G1.K[:kIndex]...) //, Ar, bs1, pk.G1.Delta)
		scalars := append(h, wireValues[:kIndex]...)   //, _s, _r, r.ToRegular())
		// Krs random part
		points = append(points, pk.G1.Delta, ar, bs)
		scalars = append(scalars, r.ToRegular(), _s, _r)
		<-chToken
		chAsync := Krs.MultiExp({{- if eq .Curve "GENERIC"}}curve.GetCurve(){{- else}}curve.{{.Curve}}(){{- end}}, points, scalars)
		<-chAsync
		Krs.ToAffineFromJac(&KrsAffine)

		chResult <- KrsAffine
		close(chResult)
	}()
	return chResult
}

func computeBs2(pk *ProvingKey, _s fr.Element, wireValues []fr.Element, chToken chan struct{}) <-chan curve.G2Affine {
	chResult := make(chan curve.G2Affine, 1)
	go func() {
		var Bs curve.G2Jac
		var BsAffine curve.G2Affine
		points2 := append(pk.G2.B, pk.G2.Delta)
		scalars2 := append(wireValues, _s)
		<-chToken
		chAsync := Bs.MultiExp({{- if eq .Curve "GENERIC"}}curve.GetCurve(){{- else}}curve.{{.Curve}}(){{- end}}, points2, scalars2)
		chToken <- struct{}{}
		<-chAsync
		Bs.AddMixed(&pk.G2.Beta)
		Bs.ToAffineFromJac(&BsAffine)
		chResult <- BsAffine
		close(chResult)
	}()
	return chResult
}

func computeBs1(pk *ProvingKey, _s fr.Element, wireValues []fr.Element, chTokenA, chTokenB chan struct{}) <-chan curve.G1Affine {
	chResult := make(chan curve.G1Affine, 1)
	go func() {
		var bs1 curve.G1Jac
		var bs1Affine curve.G1Affine

		points := append(pk.G1.B, pk.G1.Delta)
		scalars := append(wireValues, _s)
		<-chTokenA
		chAsync := bs1.MultiExp({{- if eq .Curve "GENERIC"}}curve.GetCurve(){{- else}}curve.{{.Curve}}(){{- end}}, points, scalars)
		chTokenB <- struct{}{}
		<-chAsync
		bs1.AddMixed(&pk.G1.Beta)
		bs1.ToAffineFromJac(&bs1Affine)

		chResult <- bs1Affine
		close(chResult)
	}()
	return chResult
}

func computeAr1(pk *ProvingKey, _r fr.Element, wireValues []fr.Element, chToken chan struct{}) <-chan curve.G1Affine {
	chResult := make(chan curve.G1Affine, 1)
	go func() {
		var ar curve.G1Jac
		var arAffine curve.G1Affine
		points := append(pk.G1.A, pk.G1.Delta)
		scalars := append(wireValues, _r)
		chAsync := ar.MultiExp({{- if eq .Curve "GENERIC"}}curve.GetCurve(){{- else}}curve.{{.Curve}}(){{- end}}, points, scalars)
		chToken <- struct{}{}
		<-chAsync
		ar.AddMixed(&pk.G1.Alpha)
		ar.ToAffineFromJac(&arAffine)
		chResult <- arAffine
		close(chResult)
	}()
	return chResult
}

func computeH(a, b, c []fr.Element, fftDomain *backend_{{toLower .Curve}}.Domain) <-chan []fr.Element {
	chResult := make(chan []fr.Element, 1)
	go func() {
		// H part of Krs
		// Compute H (hz=ab-c, where z=-2 on ker X^n+1 (z(x)=x^n-1))
		// 	1 - _a = ifft(a), _b = ifft(b), _c = ifft(c)
		// 	2 - ca = fft_coset(_a), ba = fft_coset(_b), cc = fft_coset(_c)
		// 	3 - h = ifft_coset(ca o cb - cc)

		n := len(a)
		debug.Assert((n == len(b)) && (n == len(c)))

		// add padding
		padding := make([]fr.Element, fftDomain.Cardinality-n)
		a = append(a, padding...)
		b = append(b, padding...)
		c = append(c, padding...)
		n = len(a)

		// exptable = scale by inverse of n + coset
		// ifft(a) would normaly do FFT(a, wInv) then scale by CardinalityInv
		// fft_coset(a) would normaly mutliply a with expTable of fftDomain.GeneratorSqRt
		// this pre-computed expTable do both in one pass --> it contains
		// expTable[0] = fftDomain.CardinalityInv
		// expTable[1] = fftDomain.GeneratorSqrt^1 * fftDomain.CardinalityInv
		// expTable[2] = fftDomain.GeneratorSqrt^2 * fftDomain.CardinalityInv
		// ...
		expTable := make([]fr.Element, n)
		expTable[0] = fftDomain.CardinalityInv

		var wgExpTable sync.WaitGroup

		// to ensure the pool is busy while the FFT splits, we schedule precomputation of the exp table
		// before the FFTs
		asyncExpTable(fftDomain.CardinalityInv, fftDomain.GeneratorSqRt, expTable, &wgExpTable)

		var wg sync.WaitGroup
		FFTa := func(s []fr.Element) {
			// FFT inverse
			backend_{{toLower .Curve}}.FFT(s, fftDomain.GeneratorInv)

			// wait for the expTable to be pre-computed
			// in the nominal case, this is non-blocking as the expTable was scheduled before the FFT
			wgExpTable.Wait()
			parallel.Execute( n, func(start, end int) {
				for i := start; i < end; i++ {
					s[i].MulAssign(&expTable[i])
				}
			})

			// FFT coset
			backend_{{toLower .Curve}}.FFT(s, fftDomain.Generator)
			wg.Done()
		}
		wg.Add(3)
		go FFTa(a)
		go FFTa(b)
		FFTa(c)

		// wait for first step (ifft + fft_coset) to be done
		wg.Wait()

		// h = ifft_coset(ca o cb - cc)
		// reusing a to avoid unecessary memalloc
		parallel.Execute( n, func(start, end int) {
			for i := start; i < end; i++ {
				a[i].Mul(&a[i], &b[i]).
					SubAssign(&c[i]).
					MulAssign(&minusTwoInv)
			}
		})

		// before computing the ifft_coset, we schedule the expTable precompute of the ifft_coset
		// to ensure the pool is busy while the FFT splits
		// similar reasoning as in ifft pass -->
		// expTable[0] = fftDomain.CardinalityInv
		// expTable[1] = fftDomain.GeneratorSqRtInv^1 * fftDomain.CardinalityInv
		// expTable[2] = fftDomain.GeneratorSqRtInv^2 * fftDomain.CardinalityInv
		asyncExpTable(fftDomain.CardinalityInv, fftDomain.GeneratorSqRtInv, expTable, &wgExpTable)

		// ifft_coset
		backend_{{toLower .Curve}}.FFT(a, fftDomain.GeneratorInv)

		wgExpTable.Wait() // wait for pre-computation of exp table to be done
		parallel.Execute( n, func(start, end int) {
			for i := start; i < end; i++ {
				a[i].MulAssign(&expTable[i]).FromMont()
			}
		})

		chResult <- a
		close(chResult)
	}()

	return chResult
}

func asyncExpTable(scale, w fr.Element, table []fr.Element, wg *sync.WaitGroup) {
	n := len(table)

	// see if it makes sense to parallelize exp tables pre-computation
	interval := (n - 1) / runtime.NumCPU()
	// this ratio roughly correspond to the number of multiplication one can do in place of a Exp operation
	const ratioExpMul = 2400 / 26

	if interval < ratioExpMul {
		wg.Add(1)
		go func() {
			precomputeExpTableChunk(scale, w, 1, table[1:])
			wg.Done()
		}()
	} else {
		// we parallelize
		for i := 1; i < n; i += interval {
			start := i
			end := i + interval
			if end > n {
				end = n
			}
			wg.Add(1)
			go func() {
				precomputeExpTableChunk(scale, w, uint64(start), table[start:end])
				wg.Done()
			}()
		}
	}
}

func precomputeExpTableChunk(scale, w fr.Element, power uint64, table []fr.Element) {
	table[0].Exp(w, power)
	table[0].MulAssign(&scale)
	for i := 1; i < len(table); i++ {
		table[i].Mul(&table[i-1], &w)
	}
}


`
