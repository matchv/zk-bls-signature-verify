package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bls381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	bls12381 "github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"log"
)

// Circuit Boneh-Lynn-Shacham (BLS) signature verification
// e(sig, g2) * e(hm, pk) == 1
// where:
//   - Sig (in G1) the signature
//   - G2 (in G2) the public generator of G2
//   - Hm (in G1) the hashed-to-curve message
//   - Pk (in G2) the public key of the signer
type Circuit struct {
	Sig bls12381.G1Affine
	G2  bls12381.G2Affine
	Hm  bls12381.G1Affine
	Pk  bls12381.G2Affine
}

// Define e(sig,g2) * e(hm,pk) == 1
func (circuit *Circuit) Define(api frontend.API) error {

	pair, _ := bls12381.NewPairing(api)
	ml, _ := pair.MillerLoop([]*bls12381.G1Affine{&circuit.Sig, &circuit.Hm}, []*bls12381.G2Affine{&circuit.G2, &circuit.Pk})
	one := fields_bls12381.NewExt12(api)
	one.One()

	// performs the final expo
	_ = pair.FinalExponentiation(ml)

	pair.AssertIsOnG1(&circuit.Sig)
	//pair.AssertIsOnG2(&circuit.G2)

	return nil
}

func main() {

	circuit := Circuit{}
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// Create  Pair  privateKey and PublicKey
	privateKey, PublicKey, err := GenerateKeyPair()
	if err != nil {
		log.Panic("GenerateKeyPair err: ", err)
	}

	msg := []byte("Sig Test")
	hm, err := bls381.HashToG1(msg, g1Gen.Marshal())
	if err != nil {
		log.Panic("HashToG1 err: ", err)
	}

	sig := new(bls381.G1Affine).ScalarMultiplication(&hm, privateKey.X)
	fmt.Println("Signature done")

	circuit = Circuit{
		Sig: bls12381.NewG1Affine(*sig),
		G2:  bls12381.NewG2Affine(g2Gen),
		Hm:  bls12381.NewG1Affine(hm),
		Pk:  bls12381.NewG2Affine(*PublicKey.P),
	}

	// witness definition
	witness, _ := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16 zkSNerrRK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Panic("Prove err: ", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Panic("Verify err: ", err)
	}
}
