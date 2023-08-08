// Package sw_bw6761 Package bw6761 efficient elliptic curve, pairing and hash to curve implementation for bw6-761.
//
// bw6-761: A Brezing--Weng curve (2-chain with bls12-377)
//
//	embedding degree k=6
//	seed x₀=9586122913090633729
//	𝔽p: p=6891450384315732539396789682275657542479668912536150109513790160209623422243491736087683183289411687640864567753786613451161759120554247759349511699125301598951605099378508850372543631423596795951899700429969112842764913119068299
//	𝔽r: r=258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177
//	(E/𝔽p): Y²=X³-1
//	(Eₜ/𝔽p): Y² = X³+4 (M-type twist)
//	r ∣ #E(Fp) and r ∣ #Eₜ(𝔽p)
//
// Extension fields tower:
//
//	𝔽p³[u] = 𝔽p/u³+4
//	𝔽p⁶[v] = 𝔽p²/v²-u
//
// optimal Ate loops:
//
//	x₀+1, x₀²-x₀-1
//
// Security: estimated 126-bit level following [https://eprint.iacr.org/2019/885.pdf]
// (r is 377 bits and p⁶ is 4566 bits)
//
// https://eprint.iacr.org/2020/351.pdf
//
// # Warning
//
// This code has not been audited and is provided as-is. In particular, there is no security guarantees such as constant time implementation or side-channel attack resistance.
package sw_bw6761

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)

// ID BW6_761 ID
const ID = ecc.BW6_761

// bCurveCoeff b coeff of the curve Y²=X³+b
var bCurveCoeff fp.Element

// bTwistCurveCoeff b coeff of the twist (defined over 𝔽p) curve
var bTwistCurveCoeff fp.Element

// Parameters useful for the GLV scalar multiplication. The third roots define the
// endomorphisms ϕ₁ and ϕ₂ for <G1Affine> and <G2Affine>. lambda is such that <r, ϕ-λ> lies above
// <r> in the ring Z[ϕ]. More concretely it's the associated eigenvalue
// of ϕ₁ (resp ϕ₂) restricted to <G1Affine> (resp <G2Affine>)
// see https://www.cosic.esat.kuleuven.be/nessie/reports/phase2/GLV.pdf
var thirdRootOneG1 fp.Element
var lambdaGLV big.Int

// glvBasis stores R-linearly independent vectors (a,b), (c,d)
// in ker((u,v) → u+vλ[r]), and their determinant
var glvBasis ecc.Lattice

// seed x₀ of the curve
var xGen big.Int

func init() {

	bCurveCoeff.SetOne().Neg(&bCurveCoeff)
	// M-twist
	bTwistCurveCoeff.SetUint64(4)

	// x₀+1
	loopCounter0 = [190]int8{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	// x₀³-x₀²-x₀
	T, _ := new(big.Int).SetString("880904806456922042166256752416502360955572640081583800319", 10)
	ecc.NafDecomposition(T, loopCounter1[:])

	thirdRootOneG1.SetString("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292650")

	lambdaGLV.SetString("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945", 10) // (x⁵-3x⁴+3x³-x+1)
	_r := fr.Modulus()
	ecc.PrecomputeLattice(_r, &lambdaGLV, &glvBasis)

	// x₀
	xGen.SetString("9586122913090633729", 10)

}
