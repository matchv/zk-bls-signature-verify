package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bn254_ecc "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	bn254 "github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"log"
)

const (
	SignatureNum = 2
)

// Circuit Boneh-Lynn-Shacham (BLS) signature verification
// e(sig, g2) == e(hm, pk)
// where:
//   - Sig (in G1) the signature
//   - G2 (in G2) the public generator of G2
//   - Hm (in G1) the hashed-to-curve message
//   - Pk (in G2) the public key of the signer
type Circuit struct {
	Sig bn254.G1Affine
	G2  bn254.G2Affine
	Hm  [SignatureNum]bn254.G1Affine
	Pk  [SignatureNum]bn254.G2Affine
}

// Define e(sig,g2) == e(hm,pk)
func (circuit *Circuit) Define(api frontend.API) error {
	pair, _ := bn254.NewPairing(api)
	pl, _ := pair.Pair([]*bn254.G1Affine{&circuit.Sig}, []*bn254.G2Affine{&circuit.G2})

	var hm []*bn254.G1Affine
	for _, v := range circuit.Hm {
		hm = append(hm, &v)
	}

	var pk []*bn254.G2Affine
	for _, v := range circuit.Pk {
		pk = append(pk, &v)
	}

	pr, _ := pair.Pair(hm, pk)
	pair.AssertIsEqual(pl, pr)
	return nil
}

func main() {

	circuit := Circuit{}
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// Create  Pair  privateKey and PublicKey
	privateKeys, publicKeys, err := BatchGenerateKeyPairs(SignatureNum)
	if err != nil {
		log.Panic("BatchGenerateKeyPairs err: ", err)
	}
	//fmt.Printf("Privatekeys Len: %d PublicKeys Len: %d\n", len(privateKeys), len(publicKeys))
	// Get Signature
	if len(privateKeys) != len(publicKeys) {
		log.Panicf("PrivateKey and PublicKey must have the same length\n")
	}

	signature := new(bn254_ecc.G1Affine)
	//witness assignment
	for k, v := range privateKeys {
		message := []byte(fmt.Sprintf("Signature_%d", k+1))
		//fmt.Printf("message: %s\n", message)
		hm := hashToG1(message)

		sig := new(bn254_ecc.G1Affine).ScalarMultiplication(hm, v.X)
		//fmt.Printf("signature0: %v\n", signature)
		signature = signature.Add(signature, sig)
		//fmt.Printf("signature1: %v\n", signature)

		//fmt.Printf("v: %v\n", v)
		//fmt.Printf("sig: %v\n", sig)

		hmG1Affine := bn254.NewG1Affine(*hm)
		circuit.Hm[k] = hmG1Affine
		//circuit.Hm = append(circuit.Hm, *hmG1Affine)

		pkG2Affine := bn254.NewG2Affine(*publicKeys[k].P)
		circuit.Pk[k] = pkG2Affine
		//circuit.Pk = append(circuit.Pk, *pkG2Affine)

	}
	// the public generator of G2
	g2Affine := bn254.NewG2Affine(g2Gen)
	circuit.G2 = g2Affine

	// signature transform
	sigG1Affine := bn254.NewG1Affine(*signature)
	circuit.Sig = sigG1Affine

	// groth16 zkSNerrRK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Panicf("Failed to Setup err: %s", err)
	}
	//fmt.Printf("vk: %v\n", vk.CurveID())

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
