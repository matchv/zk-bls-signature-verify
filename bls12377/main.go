// Welcome to the gnark playground!
package main

import (
	"encoding/json"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
	bls12377 "github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"log"
)

func init() {
	// In-circuit pairing computation needs a SNARK friendly 2-chains of elliptic curves.
	// That is: the base field of one curve ("inner curve)"
	// is equal to the scalar field of the other ("outter curve").
	// This example use the pair of curves BW6_761 / BLS12_377
	// More details on the curves here https://eprint.iacr.org/2021/1359
	// Overrides the default playground curve (BN254) with the curve BW6_761
	//Curve = ecc.BW6_761
}

// CubicCircuit Boneh-Lynn-Shacham (BLS) signature verification
// e(sig, g2) * e(hm, pk) == 1
// where:
//   - Sig (in G1) the signature
//   - G2 (in G2) the public generator of G2
//   - Hm (in G1) the hashed-to-curve message
//   - Pk (in G2) the public key of the signer
type CubicCircuit struct {
	Sig bls12377.G1Affine
	G2  bls12377.G2Affine
	Hm  bls12377.G1Affine
	Pk  bls12377.G2Affine
}

// Define e(sig,g2) * e(hm,pk) == 1
func (circuit *CubicCircuit) Define(api frontend.API) error {
	// performs the Miller loops
	ml, _ := bls12377.MillerLoop(api, []bls12377.G1Affine{circuit.Sig, circuit.Hm}, []bls12377.G2Affine{circuit.G2, circuit.Pk})
	var one fields_bls12377.E12
	one.SetOne()

	// performs the final expo
	e := bls12377.FinalExponentiation(api, ml)
	e.AssertIsEqual(api, one)

	return nil
}

var j = `
{
    "Sig": {
        "X": "142653276895993031000006916266724122521221908004256063457362569275298456307915314952948497516099307719409858077584",
        "Y": "124869013296681382405525048387381943745958348199556996371954051753620340892927007930177100403663166477748695189485"
    },
    "G2": {
        "X": {
            "A0": "233578398248691099356572568220835526895379068987715365179118596935057653620464273615301663571204657964920925606294",
            "A1": "140913150380207355837477652521042157274541796891053068589147167627541651775299824604154852141315666357241556069118"
        },
        "Y": {
            "A0": "63160294768292073209381361943935198908131692476676907196754037919244929611450776219210369229519898517858833747423",
            "A1": "149157405641012693445398062341192467754805999074082136895788947234480009303640899064710353187729182149407503257491"
        }
    },
    "Hm": {
        "X": "81937999373150964239938255573465948239988671502647976594219695644855304257327692006745978603320413799295628339695",
        "Y": "17397676153253620270863855454307851802466321586312764156125140564607560990561071773762088186709545111705113293147"
    },
    "Pk": {
        "X": {
            "A0": "219564603530812897662626723532119871126025986455221517258692924146720701350966061579326121792267180830577562566009",
            "A1": "184624156959816253153212691059252753251414060022257016743873452235807427608305571427957272308982089732460045225308"
        },
        "Y": {
            "A0": "183390023131802300769587703273946623618493162536337034672377497825442095098047279060444611635423015435359400970794",
            "A1": "137006181065015237533186569405795438258126659550846636415327489699198493880440637650517929480195536789466736841218"
        }
    }
}`

func main() {

	circuit := CubicCircuit{}

	ccs, _ := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)

	if err := json.Unmarshal([]byte(j), &circuit); err != nil {
		log.Fatal(err)
	}

	// witness definition
	witness, _ := frontend.NewWitness(&circuit, ecc.BW6_761.ScalarField())

	publicWitness, _ := witness.Public()

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)

}
