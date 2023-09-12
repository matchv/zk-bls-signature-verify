package bls_tools

import (
	"encoding/hex"
	"math/big"

	"gnark/aggregate/bls12377"
)

var Hidden = []byte{
	113, 29, 108, 78, 50, 201, 46, 83, 23, 155, 25, 148, 132, 207, 140, 137,
	117, 66, 188, 87, 242, 178, 37, 130, 121, 159, 157, 101, 126, 236, 70, 153,
}

var GroupOrder = new(big.Int).SetBytes([]byte{
	115, 237, 167, 83, 41, 157, 125, 72, 51, 57, 216, 8, 9, 161, 216, 5,
	83, 189, 164, 2, 255, 254, 91, 254, 255, 255, 255, 255, 0, 0, 0, 1,
})

const PrivateKeySize = 32

type PrivateKey struct {
	value *big.Int
}

func (key PrivateKey) GetPublicKey() PublicKey {
	g1 := bls12377.NewG1()
	return PublicKey{
		value: g1.MulScalar(g1.New(), G1Generator(), bls12377.NewFr().FromBytes(key.value.Bytes())),
	}
}

func (key PrivateKey) Bytes() []byte {
	output := make([]byte, PrivateKeySize)
	key.value.FillBytes(output)
	return output
}

func (key PrivateKey) Hex() string {
	return "0x" + hex.EncodeToString(key.Bytes())
}

func (key PrivateKey) FarmerSk() PrivateKey {
	return derivePath(key, []int{12381, 8444, 0, 0})
}

func (key PrivateKey) PoolSk() PrivateKey {
	return derivePath(key, []int{12381, 8444, 1, 0})
}

func (key PrivateKey) WalletSk(index int) PrivateKey {
	return derivePath(key, []int{12381, 8444, 2, index})
}

func (key PrivateKey) LocalSk() PrivateKey {
	return derivePath(key, []int{12381, 8444, 3, 0})
}

func (key PrivateKey) SyntheticSk(hiddenPuzzleHash []byte) PrivateKey {
	secretExponent := new(big.Int).SetBytes(key.Bytes())
	pk := key.GetPublicKey()
	syntheticOffset := calculateSyntheticOffset(pk.Bytes(), hiddenPuzzleHash)
	syntheticSecretExponent := new(big.Int).Mod(new(big.Int).Add(secretExponent, syntheticOffset), GroupOrder)
	return KeyFromBytes(syntheticSecretExponent.Bytes())
}

func calculateSyntheticOffset(pk []byte, hiddenPuzzleHash []byte) *big.Int {
	blob := Hash256(append(pk, hiddenPuzzleHash...))
	offset := new(big.Int).SetBytes(blob)
	return new(big.Int).Mod(offset, GroupOrder)
}
