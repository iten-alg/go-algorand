// Copyright (C) 2019-2022 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package logic

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	BLS12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	BN254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

const bls12381fpSize = 64
const bn254fpSize = 32

func bytesToBN254Field(b []byte) (ret BN254fp.Element) {
	ret.SetBytes(b)
	return
}

func bytesToBN254G1(b []byte) (ret bn254.G1Affine) {
	ret.X = bytesToBN254Field(b[:32])
	ret.Y = bytesToBN254Field(b[32:64])
	return
}

func bytesToBN254G1s(b []byte) (ret []bn254.G1Affine) {
	for i := 0; i < len(b)/64; i++ {
		ret = append(ret, bytesToBN254G1(b[(i*64):(i*64+64)]))
	}
	return
}

func bytesToBN254G2(b []byte) (ret bn254.G2Affine) {
	ret.X.A0 = bytesToBN254Field(b[:32])
	ret.X.A1 = bytesToBN254Field(b[32:64])
	ret.Y.A0 = bytesToBN254Field(b[64:96])
	ret.Y.A1 = bytesToBN254Field(b[96:128])
	return
}

func bytesToBN254G2s(b []byte) (ret []bn254.G2Affine) {
	for i := 0; i < len(b)/128; i++ {
		ret = append(ret, bytesToBN254G2(b[(i*128):(i*128+128)]))
	}
	return
}

func bN254G1ToBytes(g1 *bn254.G1Affine) (ret []byte) {
	retX := g1.X.Bytes()
	retY := g1.Y.Bytes()
	ret = append(retX[:], retY[:]...)
	return
}

func opBn256Add(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	bBytes := cx.stack[last].Bytes
	if len(aBytes) != 64 || len(bBytes) != 64 {
		return errors.New("expect G1 in 64 bytes")
	}
	a := bytesToBN254G1(aBytes)
	b := bytesToBN254G1(bBytes)
	res := new(bn254.G1Affine).Add(&a, &b)
	resBytes := bN254G1ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBn256ScalarMul(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	if len(aBytes) != 64 {
		return errors.New("expect G1 in 64 bytes")
	}
	a := bytesToBN254G1(aBytes)
	kBytes := cx.stack[last].Bytes
	k := new(big.Int).SetBytes(kBytes[:])
	res := new(bn254.G1Affine).ScalarMultiplication(&a, k)
	resBytes := bN254G1ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBn256Pairing(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	g1Bytes := cx.stack[prev].Bytes
	g2Bytes := cx.stack[last].Bytes
	g1 := bytesToBN254G1s(g1Bytes)
	g2 := bytesToBN254G2s(g2Bytes)
	ok, err := bn254.PairingCheck(g1, g2)
	if err != nil {
		return errors.New("pairing failed")
	}
	cx.stack = cx.stack[:last]
	cx.stack[prev].Uint = boolToUint(ok)
	cx.stack[prev].Bytes = nil
	return nil
}

func bytesToBLS12381Field(b []byte) (ret BLS12381fp.Element) {
	ret.SetBytes(b)
	return
}

func bytesToBLS12381G1(b []byte) (ret bls12381.G1Affine) {
	ret.X = bytesToBLS12381Field(b[:bls12381fpSize])
	ret.Y = bytesToBLS12381Field(b[bls12381fpSize : 2*bls12381fpSize])
	return
}

func bytesToBLS12381G1s(b []byte) (ret []bls12381.G1Affine) {
	for i := 0; i < len(b)/(2*bls12381fpSize); i++ {
		ret = append(ret, bytesToBLS12381G1(b[i*2*bls12381fpSize:i*2*bls12381fpSize+2*bls12381fpSize]))
	}
	return
}

func bytesToBLS12381G2(b []byte) (ret bls12381.G2Affine) {
	ret.X.A0 = bytesToBLS12381Field(b[:bls12381fpSize])
	ret.X.A1 = bytesToBLS12381Field(b[bls12381fpSize : 2*bls12381fpSize])
	ret.Y.A0 = bytesToBLS12381Field(b[2*bls12381fpSize : 3*bls12381fpSize])
	ret.Y.A1 = bytesToBLS12381Field(b[3*bls12381fpSize : 4*bls12381fpSize])
	return
}

func bytesToBLS12381G2s(b []byte) (ret []bls12381.G2Affine) {
	for i := 0; i < len(b)/(4*bls12381fpSize); i++ {
		ret = append(ret, bytesToBLS12381G2(b[i*4*bls12381fpSize:i*4*bls12381fpSize+4*bls12381fpSize]))
	}
	return
}

func bls12381G1ToBytes(g1 *bls12381.G1Affine) (ret []byte) {
	retX := g1.X.Bytes()
	retY := g1.Y.Bytes()
	ret = append(retX[:], retY[:]...)
	return
}

func opBLS12381Add(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	bBytes := cx.stack[last].Bytes
	if len(aBytes) != 2*bls12381fpSize || len(bBytes) != 2*bls12381fpSize {
		return fmt.Errorf("expect G1 in %d bytes", 2*bls12381fpSize)
	}
	a := bytesToBLS12381G1(aBytes)
	b := bytesToBLS12381G1(bBytes)
	res := new(bls12381.G1Affine).Add(&a, &b)
	resBytes := bls12381G1ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBLS12381ScalarMul(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	if len(aBytes) != 64 {
		return errors.New("expect G1 in 64 bytes")
	}
	a := bytesToBLS12381G1(aBytes)
	kBytes := cx.stack[last].Bytes
	// Overflow???
	k := new(big.Int).SetBytes(kBytes[:])
	res := new(bls12381.G1Affine).ScalarMultiplication(&a, k)
	resBytes := bls12381G1ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBLS12381Pairing(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	g1Bytes := cx.stack[prev].Bytes
	g2Bytes := cx.stack[last].Bytes
	g1 := bytesToBLS12381G1s(g1Bytes)
	g2 := bytesToBLS12381G2s(g2Bytes)
	ok, err := bls12381.PairingCheck(g1, g2)
	if err != nil {
		return errors.New("pairing failed")
	}
	cx.stack = cx.stack[:last]
	cx.stack[prev].Uint = boolToUint(ok)
	cx.stack[prev].Bytes = nil
	return nil
}
