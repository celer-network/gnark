package icicle_bls12377

import (
	"math/big"
	"math/bits"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	groth16_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	cs "github.com/consensys/gnark/constraint/bls12-377"
	iciclegnark "github.com/ingonyama-zk/iciclegnark/curves/bls12377"
)

type deviceInfo struct {
	G1Device struct {
		A, B, K, Z unsafe.Pointer
	}
	DomainDevice struct {
		Twiddles, TwiddlesInv     unsafe.Pointer
		CosetTable, CosetTableInv unsafe.Pointer
	}
	G2Device struct {
		B unsafe.Pointer
	}
	DenDevice             unsafe.Pointer
	InfinityPointIndicesK []int
}

type ProvingKey struct {
	groth16_bls12377.ProvingKey
	*deviceInfo
}

func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *groth16_bls12377.VerifyingKey) error {
	return groth16_bls12377.Setup(r1cs, &pk.ProvingKey, vk)
}

func DummySetup(r1cs *cs.R1CS, pk *ProvingKey) error {
	return groth16_bls12377.DummySetup(r1cs, &pk.ProvingKey)
}

func (pk *ProvingKey) SetDevicePointers() error {
	if pk.deviceInfo != nil {
		return nil
	}
	pk.deviceInfo = &deviceInfo{}
	n := int(pk.Domain.Cardinality)
	sizeBytes := n * fr.Bytes

	/*************************  Start Domain Device Setup  ***************************/
	copyCosetInvDone := make(chan unsafe.Pointer, 1)
	copyCosetDone := make(chan unsafe.Pointer, 1)
	copyDenDone := make(chan unsafe.Pointer, 1)
	/*************************     CosetTableInv      ***************************/
	go iciclegnark.CopyToDevice(pk.Domain.CosetTableInv, sizeBytes, copyCosetInvDone)

	/*************************     CosetTable      ***************************/
	go iciclegnark.CopyToDevice(pk.Domain.CosetTable, sizeBytes, copyCosetDone)

	/*************************     Den      ***************************/
	var denI, oneI fr.Element
	oneI.SetOne()
	denI.Exp(pk.Domain.FrMultiplicativeGen, big.NewInt(int64(pk.Domain.Cardinality)))
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

	go iciclegnark.CopyToDevice(denIcicleArr, sizeBytes, copyDenDone)

	/*************************     Twiddles and Twiddles Inv    ***************************/
	twiddlesInv_d_gen, twddles_err := iciclegnark.GenerateTwiddleFactors(n, true)
	if twddles_err != nil {
		return twddles_err
	}

	twiddles_d_gen, twddles_err := iciclegnark.GenerateTwiddleFactors(n, false)
	if twddles_err != nil {
		return twddles_err
	}

	/*************************  End Domain Device Setup  ***************************/
	pk.DomainDevice.Twiddles = twiddles_d_gen
	pk.DomainDevice.TwiddlesInv = twiddlesInv_d_gen

	pk.DomainDevice.CosetTableInv = <-copyCosetInvDone
	pk.DomainDevice.CosetTable = <-copyCosetDone
	pk.DenDevice = <-copyDenDone

	/*************************  Start G1 Device Setup  ***************************/
	/*************************     A      ***************************/
	pointsBytesA := len(pk.G1.A) * fp.Bytes * 2
	copyADone := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyPointsToDevice(pk.G1.A, pointsBytesA, copyADone) // Make a function for points

	/*************************     B      ***************************/
	pointsBytesB := len(pk.G1.B) * fp.Bytes * 2
	copyBDone := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyPointsToDevice(pk.G1.B, pointsBytesB, copyBDone) // Make a function for points

	/*************************     K      ***************************/
	var pointsNoInfinity []curve.G1Affine
	for i, gnarkPoint := range pk.G1.K {
		if gnarkPoint.IsInfinity() {
			pk.InfinityPointIndicesK = append(pk.InfinityPointIndicesK, i)
		} else {
			pointsNoInfinity = append(pointsNoInfinity, gnarkPoint)
		}
	}

	pointsBytesK := len(pointsNoInfinity) * fp.Bytes * 2
	copyKDone := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyPointsToDevice(pointsNoInfinity, pointsBytesK, copyKDone) // Make a function for points

	/*************************     Z      ***************************/
	pointsBytesZ := len(pk.G1.Z) * fp.Bytes * 2
	copyZDone := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyPointsToDevice(pk.G1.Z, pointsBytesZ, copyZDone) // Make a function for points

	/*************************  End G1 Device Setup  ***************************/
	pk.G1Device.A = <-copyADone
	pk.G1Device.B = <-copyBDone
	pk.G1Device.K = <-copyKDone
	pk.G1Device.Z = <-copyZDone

	/*************************  Start G2 Device Setup  ***************************/
	pointsBytesB2 := len(pk.G2.B) * fp.Bytes * 4
	copyG2BDone := make(chan unsafe.Pointer, 1)
	go iciclegnark.CopyG2PointsToDevice(pk.G2.B, pointsBytesB2, copyG2BDone) // Make a function for points
	pk.G2Device.B = <-copyG2BDone

	pk.G1.A = nil
	pk.G1.B = nil
	pk.G1.K = nil
	pk.G1.Z = nil
	pk.G2.B = nil

	/*************************  End G2 Device Setup  ***************************/
	return nil
}
