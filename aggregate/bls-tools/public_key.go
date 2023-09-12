package bls_tools

import (
	"encoding/hex"
	"gnark/aggregate/bls12377"
	"math/big"
)

type PublicKey struct {
	value *bls12377.PointG1
}

func NewPublicKey(data []byte) (PublicKey, error) {
	value, err := bls12377.NewG1().FromCompressed(data)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{
		value: value,
	}, nil
}

// FingerPrint Generate fingerprint
func (key PublicKey) FingerPrint() string {
	return new(big.Int).SetBytes(Hash256(bls12377.NewG1().ToCompressed(key.value))[:4]).String()
}

func (key PublicKey) Bytes() []byte {
	return bls12377.NewG1().ToCompressed(key.value)
}

func (key PublicKey) Hex() string {
	return "0x" + hex.EncodeToString(key.Bytes())
}

func (key PublicKey) G1() *bls12377.PointG1 {
	return key.value
}

func (key PublicKey) Add(pk PublicKey) PublicKey {
	g1 := bls12377.NewG1()
	return PublicKey{
		value: g1.Add(g1.New(), key.value, pk.G1()),
	}
}
