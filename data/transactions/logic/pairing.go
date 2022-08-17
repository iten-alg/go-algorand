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
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	BN254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	BN254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	BLS12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

/* IMPORTANT
->bn254 op funcs seem to not check if the supplied points are on the curve, or even the proper length (including scalars' lengths)
->bn254 pairing does not check if points are in correct subgroup
->this seems not good

->unclear when we should error vs when we should put some kind of nil val on the stack

->eth uses 64 bytes for bls fp1, but we only need 48, so I'm setting it to 48
(but this should be tracked for any eth compatibility issues)
->eth also often uses concatenation when we use separate stack elements

->per https://github.com/matter-labs/eip1962/blob/master/documentation/ABI.md it seems it is expected that not all of the pairs
in pairing op require subgroup check

->eth precompile states we need to check if int representation of field element is strictly less than modulus
->we did not originally do this in bn254 PR
->unclear if we need to since it seems anything modulus above would get reduced in SetBytes but not sure
*/
const (
	bls12381fpSize  = 48
	bls12381g1Size  = 2 * bls12381fpSize
	bls12381fp2Size = 2 * bls12381fpSize
	bls12381g2Size  = 2 * bls12381fp2Size
	bn254fpSize     = 32
	bn254g1Size     = 2 * bn254fpSize
	bn254fp2Size    = 2 * bn254fpSize
	bn254g2Size     = 2 * bn254fp2Size
	scalarSize      = 32
)

func bytesToBLS12381Field(b []byte) (ret BLS12381fp.Element) {
	ret.SetBytes(b)
	return
}

func bytesToBLS12381G1(b []byte) (ret bls12381.G1Affine, err error) {
	if len(b) != bls12381g1Size {
		return ret, errors.New("Improper encoding")
	}
	ret.X = bytesToBLS12381Field(b[:bls12381fpSize])
	ret.Y = bytesToBLS12381Field(b[bls12381fpSize:bls12381g1Size])
	if !ret.IsOnCurve() {
		return bls12381.G1Affine{}, errors.New("Point not on curve")
	}
	return
}

// The gnark library suggests that IsInSubgroup() additionally checks if point is on curve
// So we have an extra func here to avoid checking twice
func pairingBytesToBLS12381G1(b []byte) (ret bls12381.G1Affine, err error) {
	if len(b) != bls12381g1Size {
		return ret, errors.New("Improper encoding")
	}
	ret.X = bytesToBLS12381Field(b[:bls12381fpSize])
	ret.Y = bytesToBLS12381Field(b[bls12381fpSize:bls12381g1Size])
	return
}

func bytesToBLS12381G1s(b []byte) ([]bls12381.G1Affine, error) {
	if len(b)%(bls12381g1Size) != 0 {
		return nil, errors.New("Improper encoding")
	}
	points := make([]bls12381.G1Affine, len(b)/(bls12381g1Size))
	for i := 0; i < len(b)/(bls12381g1Size); i++ {
		point, err := bytesToBLS12381G1(b[i*bls12381g1Size : (i+1)*bls12381g1Size])
		if err != nil {
			// revisit later to see if way to check in one step if any errored instead of having to check each one
			return nil, err
		}
		points[i] = point
	}
	return points, nil
}

// Required b/c pairing check needs points to be in proper subgroup but multiexp does not necessarily
func pairingBytesToBLS12381G1s(b []byte) ([]bls12381.G1Affine, error) {
	if len(b)%(2*bls12381fpSize) != 0 {
		return nil, errors.New("Improper encoding")
	}
	points := make([]bls12381.G1Affine, len(b)/(2*bls12381fpSize))
	for i := 0; i < len(b)/(2*bls12381fpSize); i++ {
		point, err := pairingBytesToBLS12381G1(b[i*bls12381g1Size : (i+1)*bls12381g1Size])
		if err != nil {
			// revisit later to see if way to check in one step if any errored instead of having to check each one
			return nil, err
		}
		if !point.IsInSubGroup() {
			return nil, errors.New("Wrong subgroup")
		}
		points[i] = point
	}
	return points, nil
}

func bytesToBLS12381G2(b []byte) (ret bls12381.G2Affine, err error) {
	if len(b) != bls12381g2Size {
		return ret, errors.New("Improper encoding")
	}
	ret.X.A0 = bytesToBLS12381Field(b[:bls12381fpSize])
	ret.X.A1 = bytesToBLS12381Field(b[bls12381fpSize : 2*bls12381fpSize])
	ret.Y.A0 = bytesToBLS12381Field(b[2*bls12381fpSize : 3*bls12381fpSize])
	ret.Y.A1 = bytesToBLS12381Field(b[3*bls12381fpSize : 4*bls12381fpSize])
	if !ret.IsOnCurve() {
		return bls12381.G2Affine{}, errors.New("Point not on curve")
	}
	return
}

func bytesToBLS12381G2s(b []byte) ([]bls12381.G2Affine, error) {
	if len(b)%(bls12381g2Size) != 0 {
		return nil, errors.New("Improper encoding")
	}
	points := make([]bls12381.G2Affine, len(b)/bls12381g2Size)
	for i := 0; i < len(b)/bls12381g2Size; i++ {
		point, err := bytesToBLS12381G2(b[i*bls12381g2Size : (i+1)*bls12381g2Size])
		if err != nil {
			return nil, err
		}
		points[i] = point
	}
	return points, nil
}

func pairingBytesToBLS12381G2s(b []byte) ([]bls12381.G2Affine, error) {
	if len(b)%(bls12381g2Size) != 0 {
		return nil, errors.New("Improper encoding")
	}
	points := make([]bls12381.G2Affine, len(b)/bls12381g2Size)
	for i := 0; i < len(b)/bls12381g2Size; i++ {
		point, err := bytesToBLS12381G2(b[i*bls12381g2Size : (i+1)*bls12381g2Size])
		if err != nil {
			return nil, err
		}
		if !point.IsInSubGroup() {
			return nil, errors.New("Wrong subgroup")
		}
		points[i] = point
	}
	return points, nil
}

func bls12381G1ToBytes(g1 *bls12381.G1Affine) (ret []byte) {
	retX := g1.X.Bytes()
	retY := g1.Y.Bytes()
	ret = append(retX[:], retY[:]...)
	return
}

func bls12381G2ToBytes(g2 *bls12381.G2Affine) []byte {
	xFirst := g2.X.A0.Bytes()
	xSecond := g2.X.A1.Bytes()
	yFirst := g2.Y.A0.Bytes()
	ySecond := g2.Y.A1.Bytes()
	pointBytes := make([]byte, bls12381g2Size)
	copy(pointBytes, xFirst[:])
	copy(pointBytes[bls12381fpSize:], xSecond[:])
	copy(pointBytes[bls12381fp2Size:], yFirst[:])
	copy(pointBytes[bls12381fp2Size+bls12381fpSize:], ySecond[:])
	return pointBytes
}

func opBLS12381G1Add(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	bBytes := cx.stack[last].Bytes
	a, err := bytesToBLS12381G1(aBytes)
	if err != nil {
		return err
	}
	b, err := bytesToBLS12381G1(bBytes)
	if err != nil {
		return err
	}
	// Would be slightly more efficient to use global variable instead of constantly creating new points
	// But would mess with parallelization
	res := new(bls12381.G1Affine).Add(&a, &b)
	// It's possible it's more efficient to only check if the sum is on the curve as opposed to the summands,
	// but I doubt that's safe
	resBytes := bls12381G1ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBLS12381G2Add(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	bBytes := cx.stack[last].Bytes
	a, err := bytesToBLS12381G2(aBytes)
	if err != nil {
		return err
	}
	b, err := bytesToBLS12381G2(bBytes)
	if err != nil {
		return err
	}
	res := new(bls12381.G2Affine).Add(&a, &b)
	resBytes := bls12381G2ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBLS12381G1ScalarMul(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	a, err := bytesToBLS12381G1(aBytes)
	if err != nil {
		return err
	}
	kBytes := cx.stack[last].Bytes
	if len(kBytes) != scalarSize {
		return fmt.Errorf("Scalars must be %d bytes long", scalarSize)
	}
	// Would probably be more efficient to use uint32
	k := new(big.Int).SetBytes(kBytes[:]) // what is purpose of slicing to self
	res := new(bls12381.G1Affine).ScalarMultiplication(&a, k)
	resBytes := bls12381G1ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBLS12381G2ScalarMul(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	a, err := bytesToBLS12381G2(aBytes)
	if err != nil {
		return err
	}
	kBytes := cx.stack[last].Bytes
	if len(kBytes) != scalarSize {
		return fmt.Errorf("Scalars must be %d bytes long", scalarSize)
	}
	k := new(big.Int).SetBytes(kBytes[:])
	res := new(bls12381.G2Affine).ScalarMultiplication(&a, k)
	resBytes := bls12381G2ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBLS12381Pairing(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	g1Bytes := cx.stack[prev].Bytes
	g2Bytes := cx.stack[last].Bytes
	g1, err := pairingBytesToBLS12381G1s(g1Bytes)
	if err != nil {
		return err
	}
	g2, err := pairingBytesToBLS12381G2s(g2Bytes)
	if err != nil {
		return err
	}
	ok, err := bls12381.PairingCheck(g1, g2)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Uint = boolToUint(ok)
	cx.stack[prev].Bytes = nil
	// I'm assuming it's significantly more likely that err is nil than not
	return err
}

// Input: Top of stack is slice of k scalars, second to top is slice of k G1 points as uncompressed bytes
func opBLS12381G1MultiExponentiation(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	g1Bytes := cx.stack[prev].Bytes
	scalarBytes := cx.stack[last].Bytes
	g1Points, err := bytesToBLS12381G1s(g1Bytes)
	if err != nil {
		return err
	}
	if len(scalarBytes)%scalarSize != 0 || len(scalarBytes)/scalarSize != len(g1Points) {
		return errors.New("Bad input")
	}
	scalars := make([]fr.Element, len(g1Points))
	for i := 0; i < len(g1Points); i++ {
		scalars[i].SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
	}
	res, _ := new(bls12381.G1Affine).MultiExp(g1Points, scalars, ecc.MultiExpConfig{})
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = bls12381G1ToBytes(res)
	return nil
}

func opBLS12381G2MultiExponentiation(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	g2Bytes := cx.stack[prev].Bytes
	scalarBytes := cx.stack[last].Bytes
	g2Points, err := bytesToBLS12381G2s(g2Bytes)
	if err != nil {
		return err
	}
	if len(scalarBytes)%scalarSize != 0 || len(scalarBytes)/scalarSize != len(g2Points) {
		return errors.New("Bad input")
	}
	scalars := make([]fr.Element, len(g2Points))
	for i := 0; i < len(g2Points); i++ {
		scalars[i].SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
	}
	res, _ := new(bls12381.G2Affine).MultiExp(g2Points, scalars, ecc.MultiExpConfig{})
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = bls12381G2ToBytes(res)
	return nil
}

func opBLS12381MapFpToG1(cx *EvalContext) error {
	last := len(cx.stack) - 1
	fpBytes := cx.stack[last].Bytes
	if len(fpBytes) != bls12381fpSize {
		return errors.New("Bad input")
	}
	// should be MapToG1 in most recent version
	point := bls12381.MapToCurveG1Svdw(bytesToBLS12381Field(fpBytes))
	cx.stack[last].Bytes = bls12381G1ToBytes(&point)
	return nil
}

func opBLS12381MapFpToG2(cx *EvalContext) error {
	last := len(cx.stack) - 1
	fpBytes := cx.stack[last].Bytes
	if len(fpBytes) != bls12381fp2Size {
		return errors.New("Bad input")
	}
	// should be MapToG1 in most recent version
	fp2 := new(bls12381.G2Affine).X
	fp2.A0 = bytesToBLS12381Field(fpBytes[0:bls12381fpSize])
	fp2.A1 = bytesToBLS12381Field(fpBytes[bls12381fpSize:])
	point := bls12381.MapToCurveG2Svdw(fp2)
	cx.stack[last].Bytes = bls12381G2ToBytes(&point)
	return nil
}

func bytesToBN254Field(b []byte) (ret BN254fp.Element) {
	ret.SetBytes(b)
	return
}

func bytesToBN254G1(b []byte) (ret bn254.G1Affine, err error) {
	if len(b) != bn254g1Size {
		return ret, errors.New("Improper encoding")
	}
	ret.X = bytesToBN254Field(b[:bn254fpSize])
	ret.Y = bytesToBN254Field(b[bn254fpSize:bn254g1Size])
	if !ret.IsOnCurve() {
		return bn254.G1Affine{}, errors.New("Point not on curve")
	}
	return
}

// The gnark library suggests that IsInSubgroup() additionally checks if point is on curve
// So we have an extra func here to avoid checking twice
func pairingBytesToBN254G1(b []byte) (ret bn254.G1Affine, err error) {
	if len(b) != bn254g1Size {
		return ret, errors.New("Improper encoding")
	}
	ret.X = bytesToBN254Field(b[:bn254fpSize])
	ret.Y = bytesToBN254Field(b[bn254fpSize:bn254g1Size])
	return
}

func bytesToBN254G1s(b []byte) ([]bn254.G1Affine, error) {
	if len(b)%(bn254g1Size) != 0 {
		return nil, errors.New("Improper encoding")
	}
	points := make([]bn254.G1Affine, len(b)/(bn254g1Size))
	for i := 0; i < len(b)/(bn254g1Size); i++ {
		point, err := bytesToBN254G1(b[i*bn254g1Size : (i+1)*bn254g1Size])
		if err != nil {
			// revisit later to see if way to check in one step if any errored instead of having to check each one
			return nil, err
		}
		points[i] = point
	}
	return points, nil
}

// Required b/c pairing check needs points to be in proper subgroup but multiexp does not necessarily
func pairingBytesToBN254G1s(b []byte) ([]bn254.G1Affine, error) {
	if len(b)%(2*bn254fpSize) != 0 {
		return nil, errors.New("Improper encoding")
	}
	points := make([]bn254.G1Affine, len(b)/(2*bn254fpSize))
	for i := 0; i < len(b)/(2*bn254fpSize); i++ {
		point, err := pairingBytesToBN254G1(b[i*bn254g1Size : (i+1)*bn254g1Size])
		if err != nil {
			// revisit later to see if way to check in one step if any errored instead of having to check each one
			return nil, err
		}
		if !point.IsInSubGroup() {
			return nil, errors.New("Wrong subgroup")
		}
		points[i] = point
	}
	return points, nil
}

func bytesToBN254G2(b []byte) (ret bn254.G2Affine, err error) {
	if len(b) != bn254g2Size {
		return ret, errors.New("Improper encoding")
	}
	ret.X.A0 = bytesToBN254Field(b[:bn254fpSize])
	ret.X.A1 = bytesToBN254Field(b[bn254fpSize : 2*bn254fpSize])
	ret.Y.A0 = bytesToBN254Field(b[2*bn254fpSize : 3*bn254fpSize])
	ret.Y.A1 = bytesToBN254Field(b[3*bn254fpSize : 4*bn254fpSize])
	if !ret.IsOnCurve() {
		return bn254.G2Affine{}, errors.New("Point not on curve")
	}
	return
}

func bytesToBN254G2s(b []byte) ([]bn254.G2Affine, error) {
	if len(b)%(bn254g2Size) != 0 {
		return nil, errors.New("Improper encoding")
	}
	points := make([]bn254.G2Affine, len(b)/bn254g2Size)
	for i := 0; i < len(b)/bn254g2Size; i++ {
		point, err := bytesToBN254G2(b[i*bn254g2Size : (i+1)*bn254g2Size])
		if err != nil {
			return nil, err
		}
		points[i] = point
	}
	return points, nil
}

func pairingBytesToBN254G2s(b []byte) ([]bn254.G2Affine, error) {
	if len(b)%(bn254g2Size) != 0 {
		return nil, errors.New("Improper encoding")
	}
	points := make([]bn254.G2Affine, len(b)/bn254g2Size)
	for i := 0; i < len(b)/bn254g2Size; i++ {
		point, err := bytesToBN254G2(b[i*bn254g2Size : (i+1)*bn254g2Size])
		if err != nil {
			return nil, err
		}
		if !point.IsInSubGroup() {
			return nil, errors.New("Wrong subgroup")
		}
		points[i] = point
	}
	return points, nil
}

func bn254G1ToBytes(g1 *bn254.G1Affine) (ret []byte) {
	retX := g1.X.Bytes()
	retY := g1.Y.Bytes()
	ret = append(retX[:], retY[:]...)
	return
}

func bn254G2ToBytes(g2 *bn254.G2Affine) []byte {
	xFirst := g2.X.A0.Bytes()
	xSecond := g2.X.A1.Bytes()
	yFirst := g2.Y.A0.Bytes()
	ySecond := g2.Y.A1.Bytes()
	pointBytes := make([]byte, bn254g2Size)
	copy(pointBytes, xFirst[:])
	copy(pointBytes[bn254fpSize:], xSecond[:])
	copy(pointBytes[bn254fp2Size:], yFirst[:])
	copy(pointBytes[bn254fp2Size+bn254fpSize:], ySecond[:])
	return pointBytes
}

func opBN254G1Add(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	bBytes := cx.stack[last].Bytes
	a, err := bytesToBN254G1(aBytes)
	if err != nil {
		return err
	}
	b, err := bytesToBN254G1(bBytes)
	if err != nil {
		return err
	}
	// Would be slightly more efficient to use global variable instead of constantly creating new points
	// But would mess with parallelization
	res := new(bn254.G1Affine).Add(&a, &b)
	// It's possible it's more efficient to only check if the sum is on the curve as opposed to the summands,
	// but I doubt that's safe
	resBytes := bn254G1ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBN254G2Add(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	bBytes := cx.stack[last].Bytes
	a, err := bytesToBN254G2(aBytes)
	if err != nil {
		return err
	}
	b, err := bytesToBN254G2(bBytes)
	if err != nil {
		return err
	}
	res := new(bn254.G2Affine).Add(&a, &b)
	resBytes := bn254G2ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBN254G1ScalarMul(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	a, err := bytesToBN254G1(aBytes)
	if err != nil {
		return err
	}
	kBytes := cx.stack[last].Bytes
	if len(kBytes) != scalarSize {
		return fmt.Errorf("Scalars must be %d bytes long", scalarSize)
	}
	// Would probably be more efficient to use uint32
	k := new(big.Int).SetBytes(kBytes[:]) // what is purpose of slicing to self
	res := new(bn254.G1Affine).ScalarMultiplication(&a, k)
	resBytes := bn254G1ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBN254G2ScalarMul(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	a, err := bytesToBN254G2(aBytes)
	if err != nil {
		return err
	}
	kBytes := cx.stack[last].Bytes
	if len(kBytes) != scalarSize {
		return fmt.Errorf("Scalars must be %d bytes long", scalarSize)
	}
	k := new(big.Int).SetBytes(kBytes[:])
	res := new(bn254.G2Affine).ScalarMultiplication(&a, k)
	resBytes := bn254G2ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBN254Pairing(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	g1Bytes := cx.stack[prev].Bytes
	g2Bytes := cx.stack[last].Bytes
	g1, err := pairingBytesToBN254G1s(g1Bytes)
	if err != nil {
		return err
	}
	g2, err := pairingBytesToBN254G2s(g2Bytes)
	if err != nil {
		return err
	}
	ok, err := bn254.PairingCheck(g1, g2)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Uint = boolToUint(ok)
	cx.stack[prev].Bytes = nil
	// I'm assuming it's significantly more likely that err is nil than not
	return err
}

// Input: Top of stack is slice of k scalars, second to top is slice of k G1 points as uncompressed bytes
func opBN254G1MultiExponentiation(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	g1Bytes := cx.stack[prev].Bytes
	scalarBytes := cx.stack[last].Bytes
	g1Points, err := bytesToBN254G1s(g1Bytes)
	if err != nil {
		return err
	}
	if len(scalarBytes)%scalarSize != 0 || len(scalarBytes)/scalarSize != len(g1Points) {
		return errors.New("Bad input")
	}
	scalars := make([]BN254fr.Element, len(g1Points))
	for i := 0; i < len(g1Points); i++ {
		scalars[i].SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
	}
	res, _ := new(bn254.G1Affine).MultiExp(g1Points, scalars, ecc.MultiExpConfig{})
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = bn254G1ToBytes(res)
	return nil
}

func opBN254G2MultiExponentiation(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	g2Bytes := cx.stack[prev].Bytes
	scalarBytes := cx.stack[last].Bytes
	g2Points, err := bytesToBN254G2s(g2Bytes)
	if err != nil {
		return err
	}
	if len(scalarBytes)%scalarSize != 0 || len(scalarBytes)/scalarSize != len(g2Points) {
		return errors.New("Bad input")
	}
	scalars := make([]BN254fr.Element, len(g2Points))
	for i := 0; i < len(g2Points); i++ {
		scalars[i].SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
	}
	res, _ := new(bn254.G2Affine).MultiExp(g2Points, scalars, ecc.MultiExpConfig{})
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = bn254G2ToBytes(res)
	return nil
}

func opBN254MapFpToG1(cx *EvalContext) error {
	last := len(cx.stack) - 1
	fpBytes := cx.stack[last].Bytes
	if len(fpBytes) != bn254fpSize {
		return errors.New("Bad input")
	}
	// should be MapToG1 in most recent version
	point := bn254.MapToCurveG1Svdw(bytesToBN254Field(fpBytes))
	cx.stack[last].Bytes = bn254G1ToBytes(&point)
	return nil
}

func opBN254MapFpToG2(cx *EvalContext) error {
	last := len(cx.stack) - 1
	fpBytes := cx.stack[last].Bytes
	if len(fpBytes) != bn254fp2Size {
		return errors.New("Bad input")
	}
	// should be MapToG1 in most recent version
	fp2 := new(bn254.G2Affine).X
	fp2.A0 = bytesToBN254Field(fpBytes[0:bn254fpSize])
	fp2.A1 = bytesToBN254Field(fpBytes[bn254fpSize:])
	point := bn254.MapToCurveG2Svdw(fp2)
	cx.stack[last].Bytes = bn254G2ToBytes(&point)
	return nil
}
