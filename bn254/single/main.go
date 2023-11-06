package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	sw_bn254_ecc "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"log"
)

// BlsCircuit Boneh-Lynn-Shacham (BLS) signature verification
// e(sig, g2) * e(hm, pk) == 1
// where:
//   - Sig (in G1) the signature
//   - G2 (in G2) the public generator of G2
//   - Hm (in G1) the hashed-to-curve message
//   - Pk (in G2) the public key of the signer
type BlsCircuit struct {
	Sig sw_bn254.G1Affine
	G2  sw_bn254.G2Affine
	Hm  sw_bn254.G1Affine
	Pk  sw_bn254.G2Affine
}

// Define e(sig,g2) * e(hm,pk) == 1
func (circuit *BlsCircuit) Define(api frontend.API) error {
	pair, _ := sw_bn254.NewPairing(api)
	pl, _ := pair.Pair([]*sw_bn254.G1Affine{&circuit.Sig}, []*sw_bn254.G2Affine{&circuit.G2})
	pr, _ := pair.Pair([]*sw_bn254.G1Affine{&circuit.Hm}, []*sw_bn254.G2Affine{&circuit.Pk})
	pair.AssertIsEqual(pl, pr)
	return nil

}

func main() {
	circuit := BlsCircuit{}
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	// Create  Pair  privateKey and PublicKey
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		log.Panic("GenerateKeyPair err: ", err)
	}
	msg := []byte("Sig Test")
	hm, err := sw_bn254_ecc.HashToG1(msg, g1Gen.Marshal())
	if err != nil {
		log.Panic("HashToG1 err: ", err)
	}
	sig := new(sw_bn254_ecc.G1Affine).ScalarMultiplication(&hm, privateKey.X)
	circuit = BlsCircuit{
		Sig: sw_bn254.NewG1Affine(*sig),
		G2:  sw_bn254.NewG2Affine(g2Gen),
		Hm:  sw_bn254.NewG1Affine(hm),
		Pk:  sw_bn254.NewG2Affine(*publicKey.P),
	}

	// groth16 zkSNerrRK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Panicf("Failed to Setup err: %s", err)
	}
	// witness definition
	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		log.Panicf("Failed to create witness err: %s", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		log.Panicf("Failed to create witness Public err: %s", err)
	}

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Panicf("Prove err: %s", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Panicf("Verify err: %s", err)
	}
}
