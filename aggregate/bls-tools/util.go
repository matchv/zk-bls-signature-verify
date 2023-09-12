package bls_tools

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log"
	"math/big"

	"gnark/aggregate/bls12377"
	"golang.org/x/crypto/hkdf"
)

var g1One, _ = hex.DecodeString("" +
	"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" +
	"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
)

//var g1One, _ = hex.DecodeString("" +
//	"81937999373150964239938255573465948239988671502647976594219695644855304257327692006745978603320413799295628339695" +
//	"241266749859715473739788878240585681733927191168601896383759122102112907357779751001206799952863815012735208165030",
//)

//var g1One = []byte{
//	0x17, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
//	0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
//	0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
//	0x08, 0xb3, 0xf4, 0x81, 0xe3, 0xaa, 0x0f, 0x1a, 0x09, 0xe3, 0x0e, 0xd7, 0x41, 0xd8, 0xae, 0x4f,
//	0xcf, 0x5e, 0x09, 0x5d, 0x5d, 0x00, 0xaf, 0x60, 0x0d, 0xb1, 0x8c, 0xb2, 0xc0, 0x4b, 0x3e, 0xdd,
//	0x03, 0xcc, 0x74, 0x4a, 0x28, 0x88, 0xae, 0x40, 0xca, 0xa2, 0x32, 0x94, 0x6c, 0x5e, 0x7e, 0x1,
//}

func G1Generator() *bls12377.PointG1 {
	one, err := bls12377.NewG1().FromBytes(g1One)
	if err != nil {
		log.Panicf(" generating point err: %s", err)
	}
	return one
}

func extractExpand(L int, key, salt, info []byte) (okm []byte) {
	okm = make([]byte, L)
	_, _ = hkdf.New(sha256.New, key, salt, info).Read(okm)

	return okm
}

func ikmToLamportSk(ikm, salt []byte) []byte {
	return extractExpand(32*255, ikm, salt, nil)
}

func parentSkToLamportPk(parentSk PrivateKey, index int) []byte {
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, uint32(index))
	ikm := make([]byte, 32)
	parentSk.value.FillBytes(ikm)
	notIkm := make([]byte, len(ikm))
	for i, e := range ikm {
		notIkm[i] = e ^ 0xFF
	}

	lamport0 := ikmToLamportSk(ikm, salt)
	lamport1 := ikmToLamportSk(notIkm, salt)

	var lamportPk []byte

	for i := 0; i < 255; i++ {
		lamportPk = append(lamportPk, Hash256(lamport0[i*32:(i+1)*32])...)
	}
	for i := 0; i < 255; i++ {
		lamportPk = append(lamportPk, Hash256(lamport1[i*32:(i+1)*32])...)
	}

	return Hash256(lamportPk)
}

func derivePath(sk PrivateKey, path []int) PrivateKey {
	for _, index := range path {
		sk = DeriveChildSk(sk, index)
	}
	return sk
}

func DeriveChildSk(parentSk PrivateKey, index int) PrivateKey {
	lamportPk := parentSkToLamportPk(parentSk, index)
	return KeyGen(lamportPk)
}

func Hash256(m []byte) []byte {
	hash := sha256.Sum256(m)
	return hash[:]
}

// Ref: https://github.com/Chia-Network/bls-signatures/blob/53243db501e1e9f5d031970da728efb1873f6c81/python-impl/hd_keys.py#L49
func DeriveChildSkUnhardened(parentSk PrivateKey, index uint32) PrivateKey {
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, index)

	// h = hash256(bytes(parent_sk.get_g1()) + index.to_bytes(4, "big"))
	hash := Hash256(append(parentSk.GetPublicKey().Bytes(), salt...))

	// bls.PrivateKey.aggregate([PrivateKey.from_bytes(h), parent_sk])
	sum := new(big.Int).Add(new(big.Int).SetBytes(hash), new(big.Int).SetBytes(parentSk.Bytes()))
	bytes := new(big.Int).Mod(sum, bls12377.NewG1().Q()).Bytes()

	return KeyFromBytes(bytes)
}

// To make keys more secure, choose path len value of at least 4
// ex: []int{44, 8444, 2, varyingIndex}
func DerivePathUnhardened(sk PrivateKey, path []uint32) PrivateKey {
	for _, index := range path {
		sk = DeriveChildSkUnhardened(sk, index)
	}
	return sk
}
