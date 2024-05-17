package fields_bls12381

import "github.com/consensys/gnark/std/math/emulated"

func (e Ext12) nSquareTorus(z *E6, n int) *E6 {
	for i := 0; i < n; i++ {
		z = e.SquareTorus(z)
	}
	return z
}

// ExptHalfTorus set z to x^(t/2) in E6 and return z
// const t/2 uint64 = 7566188111470821376 // negative
func (e Ext12) ExptHalfTorus(x *E6) *E6 {
	// FixedExp computation is derived from the addition chain:
	//
	//	_10      = 2*1
	//	_11      = 1 + _10
	//	_1100    = _11 << 2
	//	_1101    = 1 + _1100
	//	_1101000 = _1101 << 3
	//	_1101001 = 1 + _1101000
	//	return     ((_1101001 << 9 + 1) << 32 + 1) << 15
	//
	// Operations: 62 squares 5 multiplies
	//
	// Generated by github.com/mmcloughlin/addchain v0.4.0.

	// Step 1: z = x^0x2
	z := e.SquareTorus(x)

	// Step 2: z = x^0x3
	z = e.MulTorus(x, z)

	z = e.SquareTorus(z)
	z = e.SquareTorus(z)

	// Step 5: z = x^0xd
	z = e.MulTorus(x, z)

	// Step 8: z = x^0x68
	z = e.nSquareTorus(z, 3)

	// Step 9: z = x^0x69
	z = e.MulTorus(x, z)

	// Step 18: z = x^0xd200
	z = e.nSquareTorus(z, 9)

	// Step 19: z = x^0xd201
	z = e.MulTorus(x, z)

	// Step 51: z = x^0xd20100000000
	z = e.nSquareTorus(z, 32)

	// Step 52: z = x^0xd20100000001
	z = e.MulTorus(x, z)

	// Step 67: z = x^0x6900800000008000
	z = e.nSquareTorus(z, 15)

	z = e.InverseTorus(z) // because tAbsVal is negative

	return z
}

// ExptTorus set z to xᵗ in E6 and return z
// const t uint64 = 15132376222941642752 // negative
func (e Ext12) ExptTorus(x *E6) *E6 {
	z := e.ExptHalfTorus(x)
	z = e.SquareTorus(z)
	return z
}

// MulBy014 multiplies z by an E12 sparse element of the form
//
//	E12{
//		C0: E6{B0: c0, B1: c1, B2: 0},
//		C1: E6{B0: 0, B1: 1, B2: 0},
//	}
func (e *Ext12) MulBy014(z *E12, c0, c1 *E2) *E12 {

	a := e.MulBy01(&z.C0, c0, c1)

	var b E6
	// Mul by E6{0, 1, 0}
	b.B0 = *e.Ext2.MulByNonResidue(&z.C1.B2)
	b.B2 = z.C1.B1
	b.B1 = z.C1.B0

	one := e.Ext2.One()
	d := e.Ext2.Add(c1, one)

	zC1 := e.Ext6.Add(&z.C1, &z.C0)
	zC1 = e.Ext6.MulBy01(zC1, c0, d)
	tmp := e.Ext6.Add(&b, a)
	zC1 = e.Ext6.Sub(zC1, tmp)
	zC0 := e.Ext6.MulByNonResidue(&b)
	zC0 = e.Ext6.Add(zC0, a)

	return &E12{
		C0: *zC0,
		C1: *zC1,
	}
}

//	multiplies two E12 sparse element of the form:
//
//	E12{
//		C0: E6{B0: c0, B1: c1, B2: 0},
//		C1: E6{B0: 0, B1: 1, B2: 0},
//	}
//
// and
//
//	E12{
//		C0: E6{B0: d0, B1: d1, B2: 0},
//		C1: E6{B0: 0, B1: 1, B2: 0},
//	}
func (e Ext12) Mul014By014(d0, d1, c0, c1 *E2) [5]*E2 {
	x0 := e.Ext2.Mul(c0, d0)
	x1 := e.Ext2.Mul(c1, d1)
	x04 := e.Ext2.Add(c0, d0)
	tmp := e.Ext2.Add(c0, c1)
	x01 := e.Ext2.Add(d0, d1)
	x01 = e.Ext2.Mul(x01, tmp)
	tmp = e.Ext2.Add(x1, x0)
	x01 = e.Ext2.Sub(x01, tmp)
	x14 := e.Ext2.Add(c1, d1)

	zC0B0 := e.Ext2.NonResidue()
	zC0B0 = e.Ext2.Add(zC0B0, x0)

	return [5]*E2{zC0B0, x01, x1, x04, x14}
}

// MulBy01245 multiplies z by an E12 sparse element of the form
//
//	E12{
//		C0: E6{B0: c0, B1: c1, B2: c2},
//		C1: E6{B0: 0, B1: c4, B2: c5},
//	}
func (e *Ext12) MulBy01245(z *E12, x [5]*E2) *E12 {
	c0 := &E6{B0: *x[0], B1: *x[1], B2: *x[2]}
	c1 := &E6{B0: *e.Ext2.Zero(), B1: *x[3], B2: *x[4]}
	a := e.Ext6.Add(&z.C0, &z.C1)
	b := e.Ext6.Add(c0, c1)
	a = e.Ext6.Mul(a, b)
	b = e.Ext6.Mul(&z.C0, c0)
	c := e.Ext6.MulBy12(&z.C1, x[3], x[4])
	d := e.Ext6.Add(c, b)
	z1 := e.Ext6.Sub(a, d)
	z0 := e.Ext6.MulByNonResidue(c)
	z0 = e.Ext6.Add(z0, b)
	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

// Torus-based arithmetic:
//
// After the easy part of the final exponentiation the elements are in a proper
// subgroup of Fpk (E12) that coincides with some algebraic tori. The elements
// are in the torus Tk(Fp) and thus in each torus Tk/d(Fp^d) for d|k, d≠k.  We
// take d=6. So the elements are in T2(Fp6).
// Let G_{q,2} = {m ∈ Fq^2 | m^(q+1) = 1} where q = p^6.
// When m.C1 = 0, then m.C0 must be 1 or −1.
//
// We recall the tower construction:
//
//	𝔽p²[u] = 𝔽p/u²+1
//	𝔽p⁶[v] = 𝔽p²/v³-1-u
//	𝔽p¹²[w] = 𝔽p⁶/w²-v

// CompressTorus compresses x ∈ E12 to (x.C0 + 1)/x.C1 ∈ E6
func (e Ext12) CompressTorus(x *E12) *E6 {
	// x ∈ G_{q,2} \ {-1,1}
	y := e.Ext6.Add(&x.C0, e.Ext6.One())
	y = e.Ext6.DivUnchecked(y, &x.C1)
	return y
}

// DecompressTorus decompresses y ∈ E6 to (y+w)/(y-w) ∈ E12
func (e Ext12) DecompressTorus(y *E6) *E12 {
	var n, d E12
	one := e.Ext6.One()
	n.C0 = *y
	n.C1 = *one
	d.C0 = *y
	d.C1 = *e.Ext6.Neg(one)

	x := e.DivUnchecked(&n, &d)
	return x
}

// MulTorus multiplies two compressed elements y1, y2 ∈ E6
// and returns (y1 * y2 + v)/(y1 + y2)
// N.B.: we use MulTorus in the final exponentiation throughout y1 ≠ -y2 always.
func (e Ext12) MulTorus(y1, y2 *E6) *E6 {
	n := e.Ext6.Mul(y1, y2)
	n.B1 = *e.Ext2.Add(&n.B1, e.Ext2.One())
	d := e.Ext6.Add(y1, y2)
	y3 := e.Ext6.DivUnchecked(n, d)
	return y3
}

// InverseTorus inverses a compressed elements y ∈ E6
// and returns -y
func (e Ext12) InverseTorus(y *E6) *E6 {
	return e.Ext6.Neg(y)
}

// SquareTorus squares a compressed elements y ∈ E6
// and returns (y + v/y)/2
//
// It uses a hint to verify that (2x-y)y = v saving one E6 AssertIsEqual.
func (e Ext12) SquareTorus(y *E6) *E6 {
	res, err := e.fp.NewHint(squareTorusHint, 6, &y.B0.A0, &y.B0.A1, &y.B1.A0, &y.B1.A1, &y.B2.A0, &y.B2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	sq := E6{
		B0: E2{A0: *res[0], A1: *res[1]},
		B1: E2{A0: *res[2], A1: *res[3]},
		B2: E2{A0: *res[4], A1: *res[5]},
	}

	// v = (2x-y)y
	v := e.Ext6.Double(&sq)
	v = e.Ext6.Sub(v, y)
	v = e.Ext6.Mul(v, y)

	_v := E6{B0: *e.Ext2.Zero(), B1: *e.Ext2.One(), B2: *e.Ext2.Zero()}
	e.Ext6.AssertIsEqual(v, &_v)

	return &sq

}

// FrobeniusTorus raises a compressed elements y ∈ E6 to the modulus p
// and returns y^p / v^((p-1)/2)
func (e Ext12) FrobeniusTorus(y *E6) *E6 {
	t0 := e.Ext2.Conjugate(&y.B0)
	t1 := e.Ext2.Conjugate(&y.B1)
	t2 := e.Ext2.Conjugate(&y.B2)
	t1 = e.Ext2.MulByNonResidue1Power2(t1)
	t2 = e.Ext2.MulByNonResidue1Power4(t2)

	v0 := E2{emulated.ValueOf[emulated.BLS12381Fp]("877076961050607968509681729531255177986764537961432449499635504522207616027455086505066378536590128544573588734230"), emulated.ValueOf[emulated.BLS12381Fp]("877076961050607968509681729531255177986764537961432449499635504522207616027455086505066378536590128544573588734230")}
	res := &E6{B0: *t0, B1: *t1, B2: *t2}
	res = e.Ext6.MulBy0(res, &v0)

	return res
}

// FrobeniusSquareTorus raises a compressed elements y ∈ E6 to the square modulus p^2
// and returns y^(p^2) / v^((p^2-1)/2)
func (e Ext12) FrobeniusSquareTorus(y *E6) *E6 {
	v0 := emulated.ValueOf[emulated.BLS12381Fp]("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437")
	t0 := e.Ext2.MulByElement(&y.B0, &v0)
	t1 := e.Ext2.MulByNonResidue2Power2(&y.B1)
	t1 = e.Ext2.MulByElement(t1, &v0)
	t2 := e.Ext2.MulByNonResidue2Power4(&y.B2)
	t2 = e.Ext2.MulByElement(t2, &v0)

	return &E6{B0: *t0, B1: *t1, B2: *t2}
}
