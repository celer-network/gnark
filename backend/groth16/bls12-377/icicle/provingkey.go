package icicle_bls12377

import (
	"unsafe"
)

type DeviceInfo struct {
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
