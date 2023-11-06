package main

import (
	"encoding/json"
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

type BlsCircuit2 struct {
	Sig      bn254.G1Affine
	G2       bn254.G2Affine
	Hm1, Hm2 bn254.G1Affine
	Pk1, Pk2 bn254.G2Affine
}

// Define e(G, S) = e(P1, H(m1)) * e(P2, H(m2)) *…* e(P1000, H(m1000))
func (circuit *BlsCircuit2) Define(api frontend.API) error {

	pair, _ := bn254.NewPairing(api)

	p1 := []*bn254.G1Affine{
		&circuit.Hm1,
		&circuit.Hm2,
	}

	p2 := []*bn254.G2Affine{
		&circuit.Pk1,
		&circuit.Pk2,
	}

	pl, _ := pair.Pair([]*bn254.G1Affine{&circuit.Sig}, []*bn254.G2Affine{&circuit.G2})

	pr, _ := pair.Pair(p1, p2)

	api.AssertIsEqual(pl, pr)
	return nil
}

func checkBlsSignature2() {
	circuit := BlsCircuit2{}

	// Create  Pair  privateKey and PublicKey
	privateKeys, publicKeys, err := BatchGenerateKeyPairs(SignatureNum)
	if err != nil {
		log.Panic("BatchGenerateKeyPairs err: ", err)
	}
	//fmt.Printf("privateKeys Len: %d, PublicKeys Len: %d\n", len(privateKeys), len(publicKeys))

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
		signature.Add(signature, sig)
		//fmt.Printf("signature1: %v\n", signature)
		//fmt.Printf("sig%d: %v\n", k+1, sig)

		hmG1Affine := bn254.NewG1Affine(*hm)
		//circuit.Hm = append(circuit.Hm, *hmG1Affine)
		if k == 0 {
			circuit.Hm1 = hmG1Affine
		} else if k == 1 {
			circuit.Hm2 = hmG1Affine
		}

		pkG2Affine := bn254.NewG2Affine(*publicKeys[k].P)
		//circuit.Pk = append(circuit.Pk, *pkG2Affine)
		if k == 0 {
			circuit.Pk1 = pkG2Affine
		} else if k == 1 {
			circuit.Pk2 = pkG2Affine
		}
	}

	//fmt.Printf("signature2: %v\n", signature)

	// the public generator of G2
	g2Affine := bn254.NewG2Affine(g2Gen)
	circuit.G2 = g2Affine

	// signature transform
	sigG1Affine := bn254.NewG1Affine(*signature)
	circuit.Sig = sigG1Affine

	jsonData, _ := json.Marshal(circuit)
	fmt.Printf("jsonData:%s\n", string(jsonData))

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

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

func main() {
	checkBlsSignature2()
}
