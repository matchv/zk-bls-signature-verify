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

// BlsCircuit64 Boneh-Lynn-Shacham (BLS) signature verification
// where:
//   - Sig (in G1) the signature
//   - G2 (in G2) the public generator of G2
//   - Hm1,Hm2... (in G1) the hashed-to-curve message
//   - Pk1,Pk2... (in G2) the public key of the signer
type BlsCircuit64 struct {
	Sig                                                                                                                                                                                                                                                                                                                                                                                   bls12377.G1Affine
	G2                                                                                                                                                                                                                                                                                                                                                                                    bls12377.G2Affine
	Hm1, Hm2, Hm3, Hm4, Hm5, Hm6, Hm7, Hm8, Hm9, Hm10, Hm11, Hm12, Hm13, Hm14, Hm15, Hm16, Hm17, Hm18, Hm19, Hm20, Hm21, Hm22, Hm23, Hm24, Hm25, Hm26, Hm27, Hm28, Hm29, Hm30, Hm31, Hm32, Hm33, Hm34, Hm35, Hm36, Hm37, Hm38, Hm39, Hm40, Hm41, Hm42, Hm43, Hm44, Hm45, Hm46, Hm47, Hm48, Hm49, Hm50, Hm51, Hm52, Hm53, Hm54, Hm55, Hm56, Hm57, Hm58, Hm59, Hm60, Hm61, Hm62, Hm63, Hm64 bls12377.G1Affine
	Pk1, Pk2, Pk3, Pk4, Pk5, Pk6, Pk7, Pk8, Pk9, Pk10, Pk11, Pk12, Pk13, Pk14, Pk15, Pk16, Pk17, Pk18, Pk19, Pk20, Pk21, Pk22, Pk23, Pk24, Pk25, Pk26, Pk27, Pk28, Pk29, Pk30, Pk31, Pk32, Pk33, Pk34, Pk35, Pk36, Pk37, Pk38, Pk39, Pk40, Pk41, Pk42, Pk43, Pk44, Pk45, Pk46, Pk47, Pk48, Pk49, Pk50, Pk51, Pk52, Pk53, Pk54, Pk55, Pk56, Pk57, Pk58, Pk59, Pk60, Pk61, Pk62, Pk63, Pk64 bls12377.G2Affine
}

// Define e(G, S) = e(P1, H(m1)) * e(P2, H(m2)) *…* e(P1000, H(m1000))
func (circuit *BlsCircuit64) Define(api frontend.API) error {

	pl, _ := bls12377.Pair(api, []bls12377.G1Affine{circuit.Sig}, []bls12377.G2Affine{circuit.G2})
	pr, _ := bls12377.Pair(
		api,
		[]bls12377.G1Affine{circuit.Hm1, circuit.Hm2, circuit.Hm3, circuit.Hm4, circuit.Hm5, circuit.Hm6, circuit.Hm7, circuit.Hm8, circuit.Hm9, circuit.Hm10, circuit.Hm11, circuit.Hm12, circuit.Hm13, circuit.Hm14, circuit.Hm15, circuit.Hm16, circuit.Hm17, circuit.Hm18, circuit.Hm19, circuit.Hm20, circuit.Hm21, circuit.Hm22, circuit.Hm23, circuit.Hm24, circuit.Hm25, circuit.Hm26, circuit.Hm27, circuit.Hm28, circuit.Hm29, circuit.Hm30, circuit.Hm31, circuit.Hm32, circuit.Hm33, circuit.Hm34, circuit.Hm35, circuit.Hm36, circuit.Hm37, circuit.Hm38, circuit.Hm39, circuit.Hm40, circuit.Hm41, circuit.Hm42, circuit.Hm43, circuit.Hm44, circuit.Hm45, circuit.Hm46, circuit.Hm47, circuit.Hm48, circuit.Hm49, circuit.Hm50, circuit.Hm51, circuit.Hm52, circuit.Hm53, circuit.Hm54, circuit.Hm55, circuit.Hm56, circuit.Hm57, circuit.Hm58, circuit.Hm59, circuit.Hm60, circuit.Hm61, circuit.Hm62, circuit.Hm63, circuit.Hm64},
		[]bls12377.G2Affine{circuit.Pk1, circuit.Pk2, circuit.Pk3, circuit.Pk4, circuit.Pk5, circuit.Pk6, circuit.Pk7, circuit.Pk8, circuit.Pk9, circuit.Pk10, circuit.Pk11, circuit.Pk12, circuit.Pk13, circuit.Pk14, circuit.Pk15, circuit.Pk16, circuit.Pk17, circuit.Pk18, circuit.Pk19, circuit.Pk20, circuit.Pk21, circuit.Pk22, circuit.Pk23, circuit.Pk24, circuit.Pk25, circuit.Pk26, circuit.Pk27, circuit.Pk28, circuit.Pk29, circuit.Pk30, circuit.Pk31, circuit.Pk32, circuit.Pk33, circuit.Pk34, circuit.Pk35, circuit.Pk36, circuit.Pk37, circuit.Pk38, circuit.Pk39, circuit.Pk40, circuit.Pk41, circuit.Pk42, circuit.Pk43, circuit.Pk44, circuit.Pk45, circuit.Pk46, circuit.Pk47, circuit.Pk48, circuit.Pk49, circuit.Pk50, circuit.Pk51, circuit.Pk52, circuit.Pk53, circuit.Pk54, circuit.Pk55, circuit.Pk56, circuit.Pk57, circuit.Pk58, circuit.Pk59, circuit.Pk60, circuit.Pk61, circuit.Pk62, circuit.Pk63, circuit.Pk64})
	//pr, _ := bls12377.Pair(api, circuit.Hm, circuit.Pk)

	pl.AssertIsEqual(api, pr)
	return nil
}

type BlsCircuit128 struct {
	Sig                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                bls12377.G1Affine
	G2                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 bls12377.G2Affine
	Hm1, Hm2, Hm3, Hm4, Hm5, Hm6, Hm7, Hm8, Hm9, Hm10, Hm11, Hm12, Hm13, Hm14, Hm15, Hm16, Hm17, Hm18, Hm19, Hm20, Hm21, Hm22, Hm23, Hm24, Hm25, Hm26, Hm27, Hm28, Hm29, Hm30, Hm31, Hm32, Hm33, Hm34, Hm35, Hm36, Hm37, Hm38, Hm39, Hm40, Hm41, Hm42, Hm43, Hm44, Hm45, Hm46, Hm47, Hm48, Hm49, Hm50, Hm51, Hm52, Hm53, Hm54, Hm55, Hm56, Hm57, Hm58, Hm59, Hm60, Hm61, Hm62, Hm63, Hm64, Hm65, Hm66, Hm67, Hm68, Hm69, Hm70, Hm71, Hm72, Hm73, Hm74, Hm75, Hm76, Hm77, Hm78, Hm79, Hm80, Hm81, Hm82, Hm83, Hm84, Hm85, Hm86, Hm87, Hm88, Hm89, Hm90, Hm91, Hm92, Hm93, Hm94, Hm95, Hm96, Hm97, Hm98, Hm99, Hm100, Hm101, Hm102, Hm103, Hm104, Hm105, Hm106, Hm107, Hm108, Hm109, Hm110, Hm111, Hm112, Hm113, Hm114, Hm115, Hm116, Hm117, Hm118, Hm119, Hm120, Hm121, Hm122, Hm123, Hm124, Hm125, Hm126, Hm127, Hm128 bls12377.G1Affine
	Pk1, Pk2, Pk3, Pk4, Pk5, Pk6, Pk7, Pk8, Pk9, Pk10, Pk11, Pk12, Pk13, Pk14, Pk15, Pk16, Pk17, Pk18, Pk19, Pk20, Pk21, Pk22, Pk23, Pk24, Pk25, Pk26, Pk27, Pk28, Pk29, Pk30, Pk31, Pk32, Pk33, Pk34, Pk35, Pk36, Pk37, Pk38, Pk39, Pk40, Pk41, Pk42, Pk43, Pk44, Pk45, Pk46, Pk47, Pk48, Pk49, Pk50, Pk51, Pk52, Pk53, Pk54, Pk55, Pk56, Pk57, Pk58, Pk59, Pk60, Pk61, Pk62, Pk63, Pk64, Pk65, Pk66, Pk67, Pk68, Pk69, Pk70, Pk71, Pk72, Pk73, Pk74, Pk75, Pk76, Pk77, Pk78, Pk79, Pk80, Pk81, Pk82, Pk83, Pk84, Pk85, Pk86, Pk87, Pk88, Pk89, Pk90, Pk91, Pk92, Pk93, Pk94, Pk95, Pk96, Pk97, Pk98, Pk99, Pk100, Pk101, Pk102, Pk103, Pk104, Pk105, Pk106, Pk107, Pk108, Pk109, Pk110, Pk111, Pk112, Pk113, Pk114, Pk115, Pk116, Pk117, Pk118, Pk119, Pk120, Pk121, Pk122, Pk123, Pk124, Pk125, Pk126, Pk127, Pk128 bls12377.G2Affine
}

func (circuit *BlsCircuit128) Define(api frontend.API) error {

	pl, _ := bls12377.Pair(api, []bls12377.G1Affine{circuit.Sig}, []bls12377.G2Affine{circuit.G2})
	pr, _ := bls12377.Pair(
		api,
		[]bls12377.G1Affine{circuit.Hm1, circuit.Hm2, circuit.Hm3, circuit.Hm4, circuit.Hm5, circuit.Hm6, circuit.Hm7, circuit.Hm8, circuit.Hm9, circuit.Hm10, circuit.Hm11, circuit.Hm12, circuit.Hm13, circuit.Hm14, circuit.Hm15, circuit.Hm16, circuit.Hm17, circuit.Hm18, circuit.Hm19, circuit.Hm20, circuit.Hm21, circuit.Hm22, circuit.Hm23, circuit.Hm24, circuit.Hm25, circuit.Hm26, circuit.Hm27, circuit.Hm28, circuit.Hm29, circuit.Hm30, circuit.Hm31, circuit.Hm32, circuit.Hm33, circuit.Hm34, circuit.Hm35, circuit.Hm36, circuit.Hm37, circuit.Hm38, circuit.Hm39, circuit.Hm40, circuit.Hm41, circuit.Hm42, circuit.Hm43, circuit.Hm44, circuit.Hm45, circuit.Hm46, circuit.Hm47, circuit.Hm48, circuit.Hm49, circuit.Hm50, circuit.Hm51, circuit.Hm52, circuit.Hm53, circuit.Hm54, circuit.Hm55, circuit.Hm56, circuit.Hm57, circuit.Hm58, circuit.Hm59, circuit.Hm60, circuit.Hm61, circuit.Hm62, circuit.Hm63, circuit.Hm64, circuit.Hm65, circuit.Hm66, circuit.Hm67, circuit.Hm68, circuit.Hm69, circuit.Hm70, circuit.Hm71, circuit.Hm72, circuit.Hm73, circuit.Hm74, circuit.Hm75, circuit.Hm76, circuit.Hm77, circuit.Hm78, circuit.Hm79, circuit.Hm80, circuit.Hm81, circuit.Hm82, circuit.Hm83, circuit.Hm84, circuit.Hm85, circuit.Hm86, circuit.Hm87, circuit.Hm88, circuit.Hm89, circuit.Hm90, circuit.Hm91, circuit.Hm92, circuit.Hm93, circuit.Hm94, circuit.Hm95, circuit.Hm96, circuit.Hm97, circuit.Hm98, circuit.Hm99, circuit.Hm100, circuit.Hm101, circuit.Hm102, circuit.Hm103, circuit.Hm104, circuit.Hm105, circuit.Hm106, circuit.Hm107, circuit.Hm108, circuit.Hm109, circuit.Hm110, circuit.Hm111, circuit.Hm112, circuit.Hm113, circuit.Hm114, circuit.Hm115, circuit.Hm116, circuit.Hm117, circuit.Hm118, circuit.Hm119, circuit.Hm120, circuit.Hm121, circuit.Hm122, circuit.Hm123, circuit.Hm124, circuit.Hm125, circuit.Hm126, circuit.Hm127, circuit.Hm128},
		[]bls12377.G2Affine{circuit.Pk1, circuit.Pk2, circuit.Pk3, circuit.Pk4, circuit.Pk5, circuit.Pk6, circuit.Pk7, circuit.Pk8, circuit.Pk9, circuit.Pk10, circuit.Pk11, circuit.Pk12, circuit.Pk13, circuit.Pk14, circuit.Pk15, circuit.Pk16, circuit.Pk17, circuit.Pk18, circuit.Pk19, circuit.Pk20, circuit.Pk21, circuit.Pk22, circuit.Pk23, circuit.Pk24, circuit.Pk25, circuit.Pk26, circuit.Pk27, circuit.Pk28, circuit.Pk29, circuit.Pk30, circuit.Pk31, circuit.Pk32, circuit.Pk33, circuit.Pk34, circuit.Pk35, circuit.Pk36, circuit.Pk37, circuit.Pk38, circuit.Pk39, circuit.Pk40, circuit.Pk41, circuit.Pk42, circuit.Pk43, circuit.Pk44, circuit.Pk45, circuit.Pk46, circuit.Pk47, circuit.Pk48, circuit.Pk49, circuit.Pk50, circuit.Pk51, circuit.Pk52, circuit.Pk53, circuit.Pk54, circuit.Pk55, circuit.Pk56, circuit.Pk57, circuit.Pk58, circuit.Pk59, circuit.Pk60, circuit.Pk61, circuit.Pk62, circuit.Pk63, circuit.Pk64, circuit.Pk65, circuit.Pk66, circuit.Pk67, circuit.Pk68, circuit.Pk69, circuit.Pk70, circuit.Pk71, circuit.Pk72, circuit.Pk73, circuit.Pk74, circuit.Pk75, circuit.Pk76, circuit.Pk77, circuit.Pk78, circuit.Pk79, circuit.Pk80, circuit.Pk81, circuit.Pk82, circuit.Pk83, circuit.Pk84, circuit.Pk85, circuit.Pk86, circuit.Pk87, circuit.Pk88, circuit.Pk89, circuit.Pk90, circuit.Pk91, circuit.Pk92, circuit.Pk93, circuit.Pk94, circuit.Pk95, circuit.Pk96, circuit.Pk97, circuit.Pk98, circuit.Pk99, circuit.Pk100, circuit.Pk101, circuit.Pk102, circuit.Pk103, circuit.Pk104, circuit.Pk105, circuit.Pk106, circuit.Pk107, circuit.Pk108, circuit.Pk109, circuit.Pk110, circuit.Pk111, circuit.Pk112, circuit.Pk113, circuit.Pk114, circuit.Pk115, circuit.Pk116, circuit.Pk117, circuit.Pk118, circuit.Pk119, circuit.Pk120, circuit.Pk121, circuit.Pk122, circuit.Pk123, circuit.Pk124, circuit.Pk125, circuit.Pk126, circuit.Pk127, circuit.Pk128})
	//pr, _ := bls12377.Pair(api, circuit.Hm, circuit.Pk)

	pl.AssertIsEqual(api, pr)
	return nil
}

func checkBlsSignature64() {
	circuit := BlsCircuit64{}
	ccs, _ := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)

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
		//fmt.Printf("sig%d: %v\n", k+1, sig)

		hmG1Affine := new(bls12377.G1Affine)
		hmG1Affine.Assign(hm)
		//circuit.Hm = append(circuit.Hm, *hmG1Affine)
		if k == 0 {
			circuit.Hm1 = *hmG1Affine
		} else if k == 1 {
			circuit.Hm2 = *hmG1Affine
		} else if k == 2 {
			circuit.Hm3 = *hmG1Affine
		} else if k == 3 {
			circuit.Hm4 = *hmG1Affine
		} else if k == 4 {
			circuit.Hm5 = *hmG1Affine
		} else if k == 5 {
			circuit.Hm6 = *hmG1Affine
		} else if k == 6 {
			circuit.Hm7 = *hmG1Affine
		} else if k == 7 {
			circuit.Hm8 = *hmG1Affine
		} else if k == 8 {
			circuit.Hm9 = *hmG1Affine
		} else if k == 9 {
			circuit.Hm10 = *hmG1Affine
		} else if k == 10 {
			circuit.Hm11 = *hmG1Affine
		} else if k == 11 {
			circuit.Hm12 = *hmG1Affine
		} else if k == 12 {
			circuit.Hm13 = *hmG1Affine
		} else if k == 13 {
			circuit.Hm14 = *hmG1Affine
		} else if k == 14 {
			circuit.Hm15 = *hmG1Affine
		} else if k == 15 {
			circuit.Hm16 = *hmG1Affine
		} else if k == 16 {
			circuit.Hm17 = *hmG1Affine
		} else if k == 17 {
			circuit.Hm18 = *hmG1Affine
		} else if k == 18 {
			circuit.Hm19 = *hmG1Affine
		} else if k == 19 {
			circuit.Hm20 = *hmG1Affine
		} else if k == 20 {
			circuit.Hm21 = *hmG1Affine
		} else if k == 21 {
			circuit.Hm22 = *hmG1Affine
		} else if k == 22 {
			circuit.Hm23 = *hmG1Affine
		} else if k == 23 {
			circuit.Hm24 = *hmG1Affine
		} else if k == 24 {
			circuit.Hm25 = *hmG1Affine
		} else if k == 25 {
			circuit.Hm26 = *hmG1Affine
		} else if k == 26 {
			circuit.Hm27 = *hmG1Affine
		} else if k == 27 {
			circuit.Hm28 = *hmG1Affine
		} else if k == 28 {
			circuit.Hm29 = *hmG1Affine
		} else if k == 29 {
			circuit.Hm30 = *hmG1Affine
		} else if k == 30 {
			circuit.Hm31 = *hmG1Affine
		} else if k == 31 {
			circuit.Hm32 = *hmG1Affine
		} else if k == 32 {
			circuit.Hm33 = *hmG1Affine
		} else if k == 33 {
			circuit.Hm34 = *hmG1Affine
		} else if k == 34 {
			circuit.Hm35 = *hmG1Affine
		} else if k == 35 {
			circuit.Hm36 = *hmG1Affine
		} else if k == 36 {
			circuit.Hm37 = *hmG1Affine
		} else if k == 37 {
			circuit.Hm38 = *hmG1Affine
		} else if k == 38 {
			circuit.Hm39 = *hmG1Affine
		} else if k == 39 {
			circuit.Hm40 = *hmG1Affine
		} else if k == 40 {
			circuit.Hm41 = *hmG1Affine
		} else if k == 41 {
			circuit.Hm42 = *hmG1Affine
		} else if k == 42 {
			circuit.Hm43 = *hmG1Affine
		} else if k == 43 {
			circuit.Hm44 = *hmG1Affine
		} else if k == 44 {
			circuit.Hm45 = *hmG1Affine
		} else if k == 45 {
			circuit.Hm46 = *hmG1Affine
		} else if k == 46 {
			circuit.Hm47 = *hmG1Affine
		} else if k == 47 {
			circuit.Hm48 = *hmG1Affine
		} else if k == 48 {
			circuit.Hm49 = *hmG1Affine
		} else if k == 49 {
			circuit.Hm50 = *hmG1Affine
		} else if k == 50 {
			circuit.Hm51 = *hmG1Affine
		} else if k == 51 {
			circuit.Hm52 = *hmG1Affine
		} else if k == 52 {
			circuit.Hm53 = *hmG1Affine
		} else if k == 53 {
			circuit.Hm54 = *hmG1Affine
		} else if k == 54 {
			circuit.Hm55 = *hmG1Affine
		} else if k == 55 {
			circuit.Hm56 = *hmG1Affine
		} else if k == 56 {
			circuit.Hm57 = *hmG1Affine
		} else if k == 57 {
			circuit.Hm58 = *hmG1Affine
		} else if k == 58 {
			circuit.Hm59 = *hmG1Affine
		} else if k == 59 {
			circuit.Hm60 = *hmG1Affine
		} else if k == 60 {
			circuit.Hm61 = *hmG1Affine
		} else if k == 61 {
			circuit.Hm62 = *hmG1Affine
		} else if k == 62 {
			circuit.Hm63 = *hmG1Affine
		} else if k == 63 {
			circuit.Hm64 = *hmG1Affine
		}

		pkG2Affine := new(bls12377.G2Affine)
		pkG2Affine.Assign(publicKeys[k].P)
		//circuit.Pk = append(circuit.Pk, *pkG2Affine)
		if k == 0 {
			circuit.Pk1 = *pkG2Affine
		} else if k == 1 {
			circuit.Pk2 = *pkG2Affine
		} else if k == 2 {
			circuit.Pk3 = *pkG2Affine
		} else if k == 3 {
			circuit.Pk4 = *pkG2Affine
		} else if k == 4 {
			circuit.Pk5 = *pkG2Affine
		} else if k == 5 {
			circuit.Pk6 = *pkG2Affine
		} else if k == 6 {
			circuit.Pk7 = *pkG2Affine
		} else if k == 7 {
			circuit.Pk8 = *pkG2Affine
		} else if k == 8 {
			circuit.Pk9 = *pkG2Affine
		} else if k == 9 {
			circuit.Pk10 = *pkG2Affine
		} else if k == 10 {
			circuit.Pk11 = *pkG2Affine
		} else if k == 11 {
			circuit.Pk12 = *pkG2Affine
		} else if k == 12 {
			circuit.Pk13 = *pkG2Affine
		} else if k == 13 {
			circuit.Pk14 = *pkG2Affine
		} else if k == 14 {
			circuit.Pk15 = *pkG2Affine
		} else if k == 15 {
			circuit.Pk16 = *pkG2Affine
		} else if k == 16 {
			circuit.Pk17 = *pkG2Affine
		} else if k == 17 {
			circuit.Pk18 = *pkG2Affine
		} else if k == 18 {
			circuit.Pk19 = *pkG2Affine
		} else if k == 19 {
			circuit.Pk20 = *pkG2Affine
		} else if k == 20 {
			circuit.Pk21 = *pkG2Affine
		} else if k == 21 {
			circuit.Pk22 = *pkG2Affine
		} else if k == 22 {
			circuit.Pk23 = *pkG2Affine
		} else if k == 23 {
			circuit.Pk24 = *pkG2Affine
		} else if k == 24 {
			circuit.Pk25 = *pkG2Affine
		} else if k == 25 {
			circuit.Pk26 = *pkG2Affine
		} else if k == 26 {
			circuit.Pk27 = *pkG2Affine
		} else if k == 27 {
			circuit.Pk28 = *pkG2Affine
		} else if k == 28 {
			circuit.Pk29 = *pkG2Affine
		} else if k == 29 {
			circuit.Pk30 = *pkG2Affine
		} else if k == 30 {
			circuit.Pk31 = *pkG2Affine
		} else if k == 31 {
			circuit.Pk32 = *pkG2Affine
		} else if k == 32 {
			circuit.Pk33 = *pkG2Affine
		} else if k == 33 {
			circuit.Pk34 = *pkG2Affine
		} else if k == 34 {
			circuit.Pk35 = *pkG2Affine
		} else if k == 35 {
			circuit.Pk36 = *pkG2Affine
		} else if k == 36 {
			circuit.Pk37 = *pkG2Affine
		} else if k == 37 {
			circuit.Pk38 = *pkG2Affine
		} else if k == 38 {
			circuit.Pk39 = *pkG2Affine
		} else if k == 39 {
			circuit.Pk40 = *pkG2Affine
		} else if k == 40 {
			circuit.Pk41 = *pkG2Affine
		} else if k == 41 {
			circuit.Pk42 = *pkG2Affine
		} else if k == 42 {
			circuit.Pk43 = *pkG2Affine
		} else if k == 43 {
			circuit.Pk44 = *pkG2Affine
		} else if k == 44 {
			circuit.Pk45 = *pkG2Affine
		} else if k == 45 {
			circuit.Pk46 = *pkG2Affine
		} else if k == 46 {
			circuit.Pk47 = *pkG2Affine
		} else if k == 47 {
			circuit.Pk48 = *pkG2Affine
		} else if k == 48 {
			circuit.Pk49 = *pkG2Affine
		} else if k == 49 {
			circuit.Pk50 = *pkG2Affine
		} else if k == 50 {
			circuit.Pk51 = *pkG2Affine
		} else if k == 51 {
			circuit.Pk52 = *pkG2Affine
		} else if k == 52 {
			circuit.Pk53 = *pkG2Affine
		} else if k == 53 {
			circuit.Pk54 = *pkG2Affine
		} else if k == 54 {
			circuit.Pk55 = *pkG2Affine
		} else if k == 55 {
			circuit.Pk56 = *pkG2Affine
		} else if k == 56 {
			circuit.Pk57 = *pkG2Affine
		} else if k == 57 {
			circuit.Pk58 = *pkG2Affine
		} else if k == 58 {
			circuit.Pk59 = *pkG2Affine
		} else if k == 59 {
			circuit.Pk60 = *pkG2Affine
		} else if k == 60 {
			circuit.Pk61 = *pkG2Affine
		} else if k == 61 {
			circuit.Pk62 = *pkG2Affine
		} else if k == 62 {
			circuit.Pk63 = *pkG2Affine
		} else if k == 63 {
			circuit.Pk64 = *pkG2Affine
		}
	}

	//fmt.Printf("signature2: %v\n", signature)

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

func checkBlsSignature128() {
	circuit := BlsCircuit128{}
	ccs, _ := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)

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
		//fmt.Printf("sig%d: %v\n", k+1, sig)

		hmG1Affine := new(bls12377.G1Affine)
		hmG1Affine.Assign(hm)
		//circuit.Hm = append(circuit.Hm, *hmG1Affine)
		if k == 0 {
			circuit.Hm1 = *hmG1Affine
		} else if k == 1 {
			circuit.Hm2 = *hmG1Affine
		} else if k == 2 {
			circuit.Hm3 = *hmG1Affine
		} else if k == 3 {
			circuit.Hm4 = *hmG1Affine
		} else if k == 4 {
			circuit.Hm5 = *hmG1Affine
		} else if k == 5 {
			circuit.Hm6 = *hmG1Affine
		} else if k == 6 {
			circuit.Hm7 = *hmG1Affine
		} else if k == 7 {
			circuit.Hm8 = *hmG1Affine
		} else if k == 8 {
			circuit.Hm9 = *hmG1Affine
		} else if k == 9 {
			circuit.Hm10 = *hmG1Affine
		} else if k == 10 {
			circuit.Hm11 = *hmG1Affine
		} else if k == 11 {
			circuit.Hm12 = *hmG1Affine
		} else if k == 12 {
			circuit.Hm13 = *hmG1Affine
		} else if k == 13 {
			circuit.Hm14 = *hmG1Affine
		} else if k == 14 {
			circuit.Hm15 = *hmG1Affine
		} else if k == 15 {
			circuit.Hm16 = *hmG1Affine
		} else if k == 16 {
			circuit.Hm17 = *hmG1Affine
		} else if k == 17 {
			circuit.Hm18 = *hmG1Affine
		} else if k == 18 {
			circuit.Hm19 = *hmG1Affine
		} else if k == 19 {
			circuit.Hm20 = *hmG1Affine
		} else if k == 20 {
			circuit.Hm21 = *hmG1Affine
		} else if k == 21 {
			circuit.Hm22 = *hmG1Affine
		} else if k == 22 {
			circuit.Hm23 = *hmG1Affine
		} else if k == 23 {
			circuit.Hm24 = *hmG1Affine
		} else if k == 24 {
			circuit.Hm25 = *hmG1Affine
		} else if k == 25 {
			circuit.Hm26 = *hmG1Affine
		} else if k == 26 {
			circuit.Hm27 = *hmG1Affine
		} else if k == 27 {
			circuit.Hm28 = *hmG1Affine
		} else if k == 28 {
			circuit.Hm29 = *hmG1Affine
		} else if k == 29 {
			circuit.Hm30 = *hmG1Affine
		} else if k == 30 {
			circuit.Hm31 = *hmG1Affine
		} else if k == 31 {
			circuit.Hm32 = *hmG1Affine
		} else if k == 32 {
			circuit.Hm33 = *hmG1Affine
		} else if k == 33 {
			circuit.Hm34 = *hmG1Affine
		} else if k == 34 {
			circuit.Hm35 = *hmG1Affine
		} else if k == 35 {
			circuit.Hm36 = *hmG1Affine
		} else if k == 36 {
			circuit.Hm37 = *hmG1Affine
		} else if k == 37 {
			circuit.Hm38 = *hmG1Affine
		} else if k == 38 {
			circuit.Hm39 = *hmG1Affine
		} else if k == 39 {
			circuit.Hm40 = *hmG1Affine
		} else if k == 40 {
			circuit.Hm41 = *hmG1Affine
		} else if k == 41 {
			circuit.Hm42 = *hmG1Affine
		} else if k == 42 {
			circuit.Hm43 = *hmG1Affine
		} else if k == 43 {
			circuit.Hm44 = *hmG1Affine
		} else if k == 44 {
			circuit.Hm45 = *hmG1Affine
		} else if k == 45 {
			circuit.Hm46 = *hmG1Affine
		} else if k == 46 {
			circuit.Hm47 = *hmG1Affine
		} else if k == 47 {
			circuit.Hm48 = *hmG1Affine
		} else if k == 48 {
			circuit.Hm49 = *hmG1Affine
		} else if k == 49 {
			circuit.Hm50 = *hmG1Affine
		} else if k == 50 {
			circuit.Hm51 = *hmG1Affine
		} else if k == 51 {
			circuit.Hm52 = *hmG1Affine
		} else if k == 52 {
			circuit.Hm53 = *hmG1Affine
		} else if k == 53 {
			circuit.Hm54 = *hmG1Affine
		} else if k == 54 {
			circuit.Hm55 = *hmG1Affine
		} else if k == 55 {
			circuit.Hm56 = *hmG1Affine
		} else if k == 56 {
			circuit.Hm57 = *hmG1Affine
		} else if k == 57 {
			circuit.Hm58 = *hmG1Affine
		} else if k == 58 {
			circuit.Hm59 = *hmG1Affine
		} else if k == 59 {
			circuit.Hm60 = *hmG1Affine
		} else if k == 60 {
			circuit.Hm61 = *hmG1Affine
		} else if k == 61 {
			circuit.Hm62 = *hmG1Affine
		} else if k == 62 {
			circuit.Hm63 = *hmG1Affine
		} else if k == 63 {
			circuit.Hm64 = *hmG1Affine
		} else if k == 64 {
			circuit.Hm65 = *hmG1Affine
		} else if k == 65 {
			circuit.Hm66 = *hmG1Affine
		} else if k == 66 {
			circuit.Hm67 = *hmG1Affine
		} else if k == 67 {
			circuit.Hm68 = *hmG1Affine
		} else if k == 68 {
			circuit.Hm69 = *hmG1Affine
		} else if k == 69 {
			circuit.Hm70 = *hmG1Affine
		} else if k == 70 {
			circuit.Hm71 = *hmG1Affine
		} else if k == 71 {
			circuit.Hm72 = *hmG1Affine
		} else if k == 72 {
			circuit.Hm73 = *hmG1Affine
		} else if k == 73 {
			circuit.Hm74 = *hmG1Affine
		} else if k == 74 {
			circuit.Hm75 = *hmG1Affine
		} else if k == 75 {
			circuit.Hm76 = *hmG1Affine
		} else if k == 76 {
			circuit.Hm77 = *hmG1Affine
		} else if k == 77 {
			circuit.Hm78 = *hmG1Affine
		} else if k == 78 {
			circuit.Hm79 = *hmG1Affine
		} else if k == 79 {
			circuit.Hm80 = *hmG1Affine
		} else if k == 80 {
			circuit.Hm81 = *hmG1Affine
		} else if k == 81 {
			circuit.Hm82 = *hmG1Affine
		} else if k == 82 {
			circuit.Hm83 = *hmG1Affine
		} else if k == 83 {
			circuit.Hm84 = *hmG1Affine
		} else if k == 84 {
			circuit.Hm85 = *hmG1Affine
		} else if k == 85 {
			circuit.Hm86 = *hmG1Affine
		} else if k == 86 {
			circuit.Hm87 = *hmG1Affine
		} else if k == 87 {
			circuit.Hm88 = *hmG1Affine
		} else if k == 88 {
			circuit.Hm89 = *hmG1Affine
		} else if k == 89 {
			circuit.Hm90 = *hmG1Affine
		} else if k == 90 {
			circuit.Hm91 = *hmG1Affine
		} else if k == 91 {
			circuit.Hm92 = *hmG1Affine
		} else if k == 92 {
			circuit.Hm93 = *hmG1Affine
		} else if k == 93 {
			circuit.Hm94 = *hmG1Affine
		} else if k == 94 {
			circuit.Hm95 = *hmG1Affine
		} else if k == 95 {
			circuit.Hm96 = *hmG1Affine
		} else if k == 96 {
			circuit.Hm97 = *hmG1Affine
		} else if k == 97 {
			circuit.Hm98 = *hmG1Affine
		} else if k == 98 {
			circuit.Hm99 = *hmG1Affine
		} else if k == 99 {
			circuit.Hm100 = *hmG1Affine
		} else if k == 100 {
			circuit.Hm101 = *hmG1Affine
		} else if k == 101 {
			circuit.Hm102 = *hmG1Affine
		} else if k == 102 {
			circuit.Hm103 = *hmG1Affine
		} else if k == 103 {
			circuit.Hm104 = *hmG1Affine
		} else if k == 104 {
			circuit.Hm105 = *hmG1Affine
		} else if k == 105 {
			circuit.Hm106 = *hmG1Affine
		} else if k == 106 {
			circuit.Hm107 = *hmG1Affine
		} else if k == 107 {
			circuit.Hm108 = *hmG1Affine
		} else if k == 108 {
			circuit.Hm109 = *hmG1Affine
		} else if k == 109 {
			circuit.Hm110 = *hmG1Affine
		} else if k == 110 {
			circuit.Hm111 = *hmG1Affine
		} else if k == 111 {
			circuit.Hm112 = *hmG1Affine
		} else if k == 112 {
			circuit.Hm113 = *hmG1Affine
		} else if k == 113 {
			circuit.Hm114 = *hmG1Affine
		} else if k == 114 {
			circuit.Hm115 = *hmG1Affine
		} else if k == 115 {
			circuit.Hm116 = *hmG1Affine
		} else if k == 116 {
			circuit.Hm117 = *hmG1Affine
		} else if k == 117 {
			circuit.Hm118 = *hmG1Affine
		} else if k == 118 {
			circuit.Hm119 = *hmG1Affine
		} else if k == 119 {
			circuit.Hm120 = *hmG1Affine
		} else if k == 120 {
			circuit.Hm121 = *hmG1Affine
		} else if k == 121 {
			circuit.Hm122 = *hmG1Affine
		} else if k == 122 {
			circuit.Hm123 = *hmG1Affine
		} else if k == 123 {
			circuit.Hm124 = *hmG1Affine
		} else if k == 124 {
			circuit.Hm125 = *hmG1Affine
		} else if k == 125 {
			circuit.Hm126 = *hmG1Affine
		} else if k == 126 {
			circuit.Hm127 = *hmG1Affine
		} else if k == 127 {
			circuit.Hm128 = *hmG1Affine
		}

		pkG2Affine := new(bls12377.G2Affine)
		pkG2Affine.Assign(publicKeys[k].P)
		//circuit.Pk = append(circuit.Pk, *pkG2Affine)
		if k == 0 {
			circuit.Pk1 = *pkG2Affine
		} else if k == 1 {
			circuit.Pk2 = *pkG2Affine
		} else if k == 2 {
			circuit.Pk3 = *pkG2Affine
		} else if k == 3 {
			circuit.Pk4 = *pkG2Affine
		} else if k == 4 {
			circuit.Pk5 = *pkG2Affine
		} else if k == 5 {
			circuit.Pk6 = *pkG2Affine
		} else if k == 6 {
			circuit.Pk7 = *pkG2Affine
		} else if k == 7 {
			circuit.Pk8 = *pkG2Affine
		} else if k == 8 {
			circuit.Pk9 = *pkG2Affine
		} else if k == 9 {
			circuit.Pk10 = *pkG2Affine
		} else if k == 10 {
			circuit.Pk11 = *pkG2Affine
		} else if k == 11 {
			circuit.Pk12 = *pkG2Affine
		} else if k == 12 {
			circuit.Pk13 = *pkG2Affine
		} else if k == 13 {
			circuit.Pk14 = *pkG2Affine
		} else if k == 14 {
			circuit.Pk15 = *pkG2Affine
		} else if k == 15 {
			circuit.Pk16 = *pkG2Affine
		} else if k == 16 {
			circuit.Pk17 = *pkG2Affine
		} else if k == 17 {
			circuit.Pk18 = *pkG2Affine
		} else if k == 18 {
			circuit.Pk19 = *pkG2Affine
		} else if k == 19 {
			circuit.Pk20 = *pkG2Affine
		} else if k == 20 {
			circuit.Pk21 = *pkG2Affine
		} else if k == 21 {
			circuit.Pk22 = *pkG2Affine
		} else if k == 22 {
			circuit.Pk23 = *pkG2Affine
		} else if k == 23 {
			circuit.Pk24 = *pkG2Affine
		} else if k == 24 {
			circuit.Pk25 = *pkG2Affine
		} else if k == 25 {
			circuit.Pk26 = *pkG2Affine
		} else if k == 26 {
			circuit.Pk27 = *pkG2Affine
		} else if k == 27 {
			circuit.Pk28 = *pkG2Affine
		} else if k == 28 {
			circuit.Pk29 = *pkG2Affine
		} else if k == 29 {
			circuit.Pk30 = *pkG2Affine
		} else if k == 30 {
			circuit.Pk31 = *pkG2Affine
		} else if k == 31 {
			circuit.Pk32 = *pkG2Affine
		} else if k == 32 {
			circuit.Pk33 = *pkG2Affine
		} else if k == 33 {
			circuit.Pk34 = *pkG2Affine
		} else if k == 34 {
			circuit.Pk35 = *pkG2Affine
		} else if k == 35 {
			circuit.Pk36 = *pkG2Affine
		} else if k == 36 {
			circuit.Pk37 = *pkG2Affine
		} else if k == 37 {
			circuit.Pk38 = *pkG2Affine
		} else if k == 38 {
			circuit.Pk39 = *pkG2Affine
		} else if k == 39 {
			circuit.Pk40 = *pkG2Affine
		} else if k == 40 {
			circuit.Pk41 = *pkG2Affine
		} else if k == 41 {
			circuit.Pk42 = *pkG2Affine
		} else if k == 42 {
			circuit.Pk43 = *pkG2Affine
		} else if k == 43 {
			circuit.Pk44 = *pkG2Affine
		} else if k == 44 {
			circuit.Pk45 = *pkG2Affine
		} else if k == 45 {
			circuit.Pk46 = *pkG2Affine
		} else if k == 46 {
			circuit.Pk47 = *pkG2Affine
		} else if k == 47 {
			circuit.Pk48 = *pkG2Affine
		} else if k == 48 {
			circuit.Pk49 = *pkG2Affine
		} else if k == 49 {
			circuit.Pk50 = *pkG2Affine
		} else if k == 50 {
			circuit.Pk51 = *pkG2Affine
		} else if k == 51 {
			circuit.Pk52 = *pkG2Affine
		} else if k == 52 {
			circuit.Pk53 = *pkG2Affine
		} else if k == 53 {
			circuit.Pk54 = *pkG2Affine
		} else if k == 54 {
			circuit.Pk55 = *pkG2Affine
		} else if k == 55 {
			circuit.Pk56 = *pkG2Affine
		} else if k == 56 {
			circuit.Pk57 = *pkG2Affine
		} else if k == 57 {
			circuit.Pk58 = *pkG2Affine
		} else if k == 58 {
			circuit.Pk59 = *pkG2Affine
		} else if k == 59 {
			circuit.Pk60 = *pkG2Affine
		} else if k == 60 {
			circuit.Pk61 = *pkG2Affine
		} else if k == 61 {
			circuit.Pk62 = *pkG2Affine
		} else if k == 62 {
			circuit.Pk63 = *pkG2Affine
		} else if k == 63 {
			circuit.Pk64 = *pkG2Affine
		} else if k == 64 {
			circuit.Pk65 = *pkG2Affine
		} else if k == 65 {
			circuit.Pk66 = *pkG2Affine
		} else if k == 66 {
			circuit.Pk67 = *pkG2Affine
		} else if k == 67 {
			circuit.Pk68 = *pkG2Affine
		} else if k == 68 {
			circuit.Pk69 = *pkG2Affine
		} else if k == 69 {
			circuit.Pk70 = *pkG2Affine
		} else if k == 70 {
			circuit.Pk71 = *pkG2Affine
		} else if k == 71 {
			circuit.Pk72 = *pkG2Affine
		} else if k == 72 {
			circuit.Pk73 = *pkG2Affine
		} else if k == 73 {
			circuit.Pk74 = *pkG2Affine
		} else if k == 74 {
			circuit.Pk75 = *pkG2Affine
		} else if k == 75 {
			circuit.Pk76 = *pkG2Affine
		} else if k == 76 {
			circuit.Pk77 = *pkG2Affine
		} else if k == 77 {
			circuit.Pk78 = *pkG2Affine
		} else if k == 78 {
			circuit.Pk79 = *pkG2Affine
		} else if k == 79 {
			circuit.Pk80 = *pkG2Affine
		} else if k == 80 {
			circuit.Pk81 = *pkG2Affine
		} else if k == 81 {
			circuit.Pk82 = *pkG2Affine
		} else if k == 82 {
			circuit.Pk83 = *pkG2Affine
		} else if k == 83 {
			circuit.Pk84 = *pkG2Affine
		} else if k == 84 {
			circuit.Pk85 = *pkG2Affine
		} else if k == 85 {
			circuit.Pk86 = *pkG2Affine
		} else if k == 86 {
			circuit.Pk87 = *pkG2Affine
		} else if k == 87 {
			circuit.Pk88 = *pkG2Affine
		} else if k == 88 {
			circuit.Pk89 = *pkG2Affine
		} else if k == 89 {
			circuit.Pk90 = *pkG2Affine
		} else if k == 90 {
			circuit.Pk91 = *pkG2Affine
		} else if k == 91 {
			circuit.Pk92 = *pkG2Affine
		} else if k == 92 {
			circuit.Pk93 = *pkG2Affine
		} else if k == 93 {
			circuit.Pk94 = *pkG2Affine
		} else if k == 94 {
			circuit.Pk95 = *pkG2Affine
		} else if k == 95 {
			circuit.Pk96 = *pkG2Affine
		} else if k == 96 {
			circuit.Pk97 = *pkG2Affine
		} else if k == 97 {
			circuit.Pk98 = *pkG2Affine
		} else if k == 98 {
			circuit.Pk99 = *pkG2Affine
		} else if k == 99 {
			circuit.Pk100 = *pkG2Affine
		} else if k == 100 {
			circuit.Pk101 = *pkG2Affine
		} else if k == 101 {
			circuit.Pk102 = *pkG2Affine
		} else if k == 102 {
			circuit.Pk103 = *pkG2Affine
		} else if k == 103 {
			circuit.Pk104 = *pkG2Affine
		} else if k == 104 {
			circuit.Pk105 = *pkG2Affine
		} else if k == 105 {
			circuit.Pk106 = *pkG2Affine
		} else if k == 106 {
			circuit.Pk107 = *pkG2Affine
		} else if k == 107 {
			circuit.Pk108 = *pkG2Affine
		} else if k == 108 {
			circuit.Pk109 = *pkG2Affine
		} else if k == 109 {
			circuit.Pk110 = *pkG2Affine
		} else if k == 110 {
			circuit.Pk111 = *pkG2Affine
		} else if k == 111 {
			circuit.Pk112 = *pkG2Affine
		} else if k == 112 {
			circuit.Pk113 = *pkG2Affine
		} else if k == 113 {
			circuit.Pk114 = *pkG2Affine
		} else if k == 114 {
			circuit.Pk115 = *pkG2Affine
		} else if k == 115 {
			circuit.Pk116 = *pkG2Affine
		} else if k == 116 {
			circuit.Pk117 = *pkG2Affine
		} else if k == 117 {
			circuit.Pk118 = *pkG2Affine
		} else if k == 118 {
			circuit.Pk119 = *pkG2Affine
		} else if k == 119 {
			circuit.Pk120 = *pkG2Affine
		} else if k == 120 {
			circuit.Pk121 = *pkG2Affine
		} else if k == 121 {
			circuit.Pk122 = *pkG2Affine
		} else if k == 122 {
			circuit.Pk123 = *pkG2Affine
		} else if k == 123 {
			circuit.Pk124 = *pkG2Affine
		} else if k == 124 {
			circuit.Pk125 = *pkG2Affine
		} else if k == 125 {
			circuit.Pk126 = *pkG2Affine
		} else if k == 126 {
			circuit.Pk127 = *pkG2Affine
		} else if k == 127 {
			circuit.Pk128 = *pkG2Affine
		}
	}

	//fmt.Printf("signature2: %v\n", signature)

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

func main() {
	//checkBlsSignature64()

	checkBlsSignature128()
}
