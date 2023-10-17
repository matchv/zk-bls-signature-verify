package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bls12377_ecc "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	bls12377 "github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"log"
)

const (
	SignatureNum = 128
)

// BlsCircuit Boneh-Lynn-Shacham (BLS) signature verification
// where:
//   - Sig (in G1) the signature
//   - G2 (in G2) the public generator of G2
//   - Hm1,Hm2... (in G1) the hashed-to-curve message
//   - Pk1,Pk2... (in G2) the public key of the signer
type BlsCircuit struct {
	Sig bls12377.G1Affine
	G2  bls12377.G2Affine
	Hm  [SignatureNum]bls12377.G1Affine
	Pk  [SignatureNum]bls12377.G2Affine
}

// Define e(G, S) = e(P1, H(m1)) * e(P2, H(m2)) *…* e(P1000, H(m1000))
func (circuit *BlsCircuit) Define(api frontend.API) error {

	pl, _ := bls12377.Pair(api, []bls12377.G1Affine{circuit.Sig}, []bls12377.G2Affine{circuit.G2})
	//pr, _ := bls12377.Pair(api, []bls12377.G1Affine{circuit.Hm[0], circuit.Hm[1]}, []bls12377.G2Affine{circuit.Pk[0], circuit.Pk[1]})

	hm := []bls12377.G1Affine{}
	for _, v := range circuit.Hm {
		hm = append(hm, v)
	}

	pk := []bls12377.G2Affine{}
	for _, v := range circuit.Pk {
		pk = append(pk, v)
	}

	pr, _ := bls12377.Pair(api, hm, pk)
	pl.AssertIsEqual(api, pr)
	return nil
}

func main() {
	circuit := BlsCircuit{}
	ccs, _ := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
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

	signature := new(bls12377_ecc.G1Affine)
	//witness assignment
	for k, v := range privateKeys {
		message := []byte(fmt.Sprintf("Signature_%d", k+1))
		//fmt.Printf("message: %s\n", message)
		hm := hashToG1(message)

		sig := new(bls12377_ecc.G1Affine).ScalarMultiplication(hm, v.X)
		//fmt.Printf("signature0: %v\n", signature)
		signature.Add(signature, sig)
		//fmt.Printf("signature1: %v\n", signature)

		//fmt.Printf("v: %v\n", v)
		//fmt.Printf("sig: %v\n", sig)

		hmG1Affine := new(bls12377.G1Affine)
		hmG1Affine.Assign(hm)
		circuit.Hm[k] = *hmG1Affine
		//circuit.Hm = append(circuit.Hm, *hmG1Affine)

		pkG2Affine := new(bls12377.G2Affine)
		pkG2Affine.Assign(publicKeys[k].P)
		circuit.Pk[k] = *pkG2Affine
		//circuit.Pk = append(circuit.Pk, *pkG2Affine)

	}

	// the public generator of G2
	g2Affine := new(bls12377.G2Affine)
	g2Affine.Assign(&g2Gen)
	circuit.G2 = *g2Affine

	// signature transform
	sigG1Affine := new(bls12377.G1Affine)
	sigG1Affine.Assign(signature)
	circuit.Sig = *sigG1Affine

	//jsonData, _ := json.Marshal(circuit)
	//fmt.Printf("jsonData:%s\n", string(jsonData))

	// groth16 zkSNerrRK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Panicf("Failed to Setup err: %s", err)
	}
	//fmt.Printf("vk: %v\n", vk.CurveID())

	// witness definition
	witness, err := frontend.NewWitness(&circuit, ecc.BW6_761.ScalarField())
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
