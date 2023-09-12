package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	bls12377_ecc "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	bls12377 "github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"log"
)

const signatureNum = 2

// Circuit Boneh-Lynn-Shacham (BLS) signature verification
// e(sig, g2) * e(hm, pk) == 1
// where:
//   - Sig (in G1) the signature
//   - G2 (in G2) the public generator of G2
//   - Hm (in G1) the hashed-to-curve message
//   - Pk (in G2) the public key of the signer
type Circuit struct {
	Sig bls12377.G1Affine
	G2  bls12377.G2Affine
	Hm  bls12377.G1Affine
	Pk  bls12377.G2Affine
}

// Define e(sig,g2) * e(hm,pk) == 1
func (circuit *Circuit) Define(api frontend.API) error {
	//for i := 0; i < signatureNum; i++ {
	pl, _ := bls12377.Pair(api, []bls12377.G1Affine{circuit.Sig}, []bls12377.G2Affine{circuit.G2})
	pr, _ := bls12377.Pair(api, []bls12377.G1Affine{circuit.Hm}, []bls12377.G2Affine{circuit.Pk})

	pl.AssertIsEqual(api, pr)

	//}
	return nil
}

func main() {
	msg := []byte("Signature Test")
	for i := 0; i < signatureNum; i++ {
		var circuit Circuit
		ccs, _ := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
		privateKey, publicKey, err := GenerateKeyPair()
		if err != nil {
			log.Panicf("GenerateKeyPair err: %s", err)
		}

		hm, err := bls12377_ecc.HashToG1(msg, g1Gen.Marshal())
		if err != nil {
			log.Panicf("HashToG1 err: %s", err)
		}

		sig := new(bls12377_ecc.G1Affine).ScalarMultiplication(&hm, privateKey.X)
		sigAffineObj := new(bls12377.G1Affine)
		sigAffineObj.Assign(sig)
		g2AffineObj := new(bls12377.G2Affine)
		g2AffineObj.Assign(&g2Gen)
		hmAffineObj := new(bls12377.G1Affine)
		hmAffineObj.Assign(&hm)
		pkAffineObj := new(bls12377.G2Affine)
		pkAffineObj.Assign(publicKey.P)

		// Instantiate Circuit
		circuit.Hm = *hmAffineObj
		circuit.G2 = *g2AffineObj
		circuit.Sig = *sigAffineObj
		circuit.Pk = *pkAffineObj

		if ok, err := Verify(publicKey, sig.Marshal(), msg); err != nil || !ok {
			log.Panicf("verify failed i:%d\n", i)
		}

		//fmt.Printf("verify succeeded i:%d\n", i)
		// groth16 zkSNerrRK: Setup
		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			log.Panicf("Failed to Setup err: %s", err)
		}
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
}
