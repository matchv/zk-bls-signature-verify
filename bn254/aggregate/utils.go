package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	bn254_ecc "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

var (
	g1Gen bn254_ecc.G1Affine
	g2Gen bn254_ecc.G2Affine
	dst   = []byte("BLS12_377_ECC_HASH")
)

type PrivateKey struct {
	X *big.Int
}

type PublicKey struct {
	P *bn254_ecc.G2Affine
}

func init() {
	_, _, g1Gen, g2Gen = bn254_ecc.Generators()
}

// BatchGenerateKeyPairs generate BLS private and public key pairs
func BatchGenerateKeyPairs(size int) ([]*PrivateKey, []*PublicKey, error) {
	var privateKeys []*PrivateKey
	var publicKeys []*PublicKey
	for i := 0; i < size; i++ {
		priKey, pubKey, err := GenerateKeyPair()
		if err != nil {
			log.Panicf("GenerateKeyPair failed: %s\n", err)
		}
		privateKeys = append(privateKeys, priKey)
		publicKeys = append(publicKeys, pubKey)
	}
	return privateKeys, publicKeys, nil
}

// GenerateKeyPair generate BLS private and public key pair
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	// generate a random point in G2
	g2Order := bn254_fr.Modulus()
	sk, err := rand.Int(rand.Reader, g2Order)
	if err != nil {
		return nil, nil, err
	}

	pk := new(bn254_ecc.G2Affine).ScalarMultiplication(&g2Gen, sk)

	priKey := &PrivateKey{X: sk}
	pubKey := &PublicKey{P: pk}

	return priKey, pubKey, nil
}

// hashToG1 computes the hash of the G1
func hashToG1(msg []byte) *bn254_ecc.G1Affine {
	hashPointG1, _ := bn254_ecc.HashToG1(msg, dst)
	return &hashPointG1
}

// Sign BLS signature uses a particular function, defined as:
// S = pk * H(m)
//
// H is a hash function, for instance SHA256 or SM3.
// S is the signature.
// m is the message to sign.
// pk is the private key, which can be considered as a secret big number.
//
// To verify the signature, check that whether the result of e(P, H(m)) is equal to e(G, S) or not.
// Which means that: e(P, H(m)) = e(G, S)
// G is the base point or the generator point.
// P is the public key = pk*G.
// e is a special elliptic curve pairing function which has this feature: e(x*P, Q) = e(P, x*Q).
//
// It is true because of the pairing function described above:
// e(P, H(m)) = e(pk*G, H(m)) = e(G, pk*H(m)) = e(G, S)

func Sign(privateKey *PrivateKey, Hm *bn254_ecc.G1Affine) (blsSignature *bn254_ecc.G1Affine, err error) {

	//new(bn254_ecc.G1Affine).Neg(hPointG1)
	blsSignature = new(bn254_ecc.G1Affine).ScalarMultiplication(Hm, privateKey.X)

	fmt.Println("blsSignature.IsOnCurve():", blsSignature.IsOnCurve())

	return blsSignature, nil
}
