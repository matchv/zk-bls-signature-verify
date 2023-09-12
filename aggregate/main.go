package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	bls_tools "gnark/aggregate/bls-tools"
	"log"
)

type Circuit struct {
	publicKeys         [][]byte
	messages           [][]byte
	aggregateSignature []byte
}

var asm = new(bls_tools.AugSchemeMPL)

// Define e(sig,g2) * e(hm,pk) == 1
func (circuit *Circuit) Define(api frontend.API) error {
	fmt.Println("Define Starting")
	signatureIsValid := AggregateVerify(circuit.publicKeys, circuit.messages, circuit.aggregateSignature)

	result := 0
	if signatureIsValid {
		result = 1
	}
	api.AssertIsEqual(result, 1)

	if signatureIsValid {
		fmt.Println("Aggregated signature is valid")
	} else {
		fmt.Println("Aggregated signature is invalid")
	}

	return nil
}

const signatureNum = 1

func demo1() {
	circuit := new(Circuit)
	var signatures [][]byte
	for i := 1; i <= signatureNum; i++ {
		message := []byte(fmt.Sprintf("message:%d", i))
		privateKey := bls_tools.KeyGen(message)
		fmt.Printf("Private key: %v\n", privateKey)

		publicKey := privateKey.GetPublicKey()
		signature := asm.Sign(privateKey, message)

		circuit.messages = append(circuit.messages, message)
		circuit.publicKeys = append(circuit.publicKeys, publicKey.Bytes())
		signatures = append(signatures, signature)
	}
	// aggregate signature
	aggregateSignature, err := asm.Aggregate(signatures...)
	if err != nil {
		log.Panic("Aggregate signature creation failed: ", err)
	}

	// Verify aggregate signature
	signatureIsValid := asm.AggregateVerify(circuit.publicKeys, circuit.messages, aggregateSignature)
	if signatureIsValid {
		fmt.Println("Aggregated signature is valid")
	} else {
		fmt.Println("Aggregated signature is invalid")
	}
}

func demo2() {
	msgs, sigs, pubks, isErr := generateBatchTestData(signatureNum)
	if isErr {
		log.Panic("generateBatchTestData failed: ")
	}

	// Generate aggregate signature
	AggregateSignature, err := asm.Aggregate(sigs...)
	if err != nil {
		log.Panic("asm.Aggregate failed: ", err.Error())
	}
	circuit := Circuit{
		messages:           msgs,
		aggregateSignature: AggregateSignature,
		publicKeys:         pubks,
	}

	//circuit := Circuit{}
	ccs, _ := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)

	// witness definition
	witness, err := frontend.NewWitness(&circuit, ecc.BW6_761.ScalarField())
	if err != nil {
		log.Panicf("Failed to create witness err: %s", err)
	}
	fmt.Printf("witness: %+v\n", witness)
	publicWitness, _ := witness.Public()

	// groth16 zkSNerrRK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Panicf("Failed to Setup err: %s", err)
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

// [29068439691932164 5212125205240116882 5158703585069274468 10701178991839105062 4772007468162561125 9336940151432106134]
// [9586122913090633729 1660523435060625408 2230234197602682880 1883307231910630287 14284016967150029115 121098312706494698]
func main() {
	demo1()
	//demo2()

	// fromBytes: &[18103045581585958587 7806400890582735599 11623291730934869080 14080658508445169925 2780237799254240271 1725392847304644500]
	//p := bls_tools.G1Generator()
	// fromBytes: &[18103045581585958587 7806400890582735599 11623291730934869080 14080658508445169925 2780237799254240271 1725392847304644500]
	//
	//fmt.Println(p)
}
