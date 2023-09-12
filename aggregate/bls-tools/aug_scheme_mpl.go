package bls_tools

import (
	"errors"
	"gnark/aggregate/bls12377"
)

var (
	AugSchemeDst = []byte("BLS_SIG_bls12377G2_XMD:SHA-256_SSWU_RO_AUG_")
)

type AugSchemeMPL struct{}

func (asm *AugSchemeMPL) Sign(sk PrivateKey, message []byte) []byte {
	return bls12377.NewG2().ToCompressed(coreSignMpl(sk, sk.GetPublicKey(), message, AugSchemeDst))
}

func (asm *AugSchemeMPL) SignWithPrependPK(sk PrivateKey, prependPK PublicKey, message []byte) []byte {
	return bls12377.NewG2().ToCompressed(coreSignMpl(sk, prependPK, message, AugSchemeDst))
}

func (asm *AugSchemeMPL) Verify(pk PublicKey, message []byte, sig []byte) bool {
	return coreVerifyMpl(
		pk,
		append(pk.Bytes(), message...),
		sig,
		AugSchemeDst,
	)
}

func (asm *AugSchemeMPL) Aggregate(signatures ...[]byte) ([]byte, error) {
	return coreAggregateMpl(signatures...)
}

func (asm *AugSchemeMPL) AggregateVerify(pks [][]byte, messages [][]byte, sig []byte) bool {
	return coreAggregateVerify(pks, messages, sig, AugSchemeDst)
}

func coreSignMpl(sk PrivateKey, pk PublicKey, message, dst []byte) *bls12377.PointG2 {
	g2Map := bls12377.NewG2()

	q, _ := g2Map.HashToCurve(append(pk.Bytes(), message...), dst)

	return g2Map.MulScalar(g2Map.New(), q, bls12377.NewFr().FromBytes(sk.Bytes()))
}

func coreVerifyMpl(pk PublicKey, message []byte, sig, dst []byte) bool {

	g2Map := bls12377.NewG2()
	q, _ := g2Map.HashToCurve(message, dst)

	signature, err := bls12377.NewG2().FromCompressed(sig)
	if err != nil {
		return false
	}

	engine := bls12377.NewEngine()

	g1Neg := new(bls12377.PointG1)
	g1Neg = bls12377.NewG1().Neg(g1Neg, G1Generator())

	engine = engine.AddPair(pk.G1(), q)
	engine = engine.AddPair(g1Neg, signature)

	return engine.Check()
}

func coreAggregateMpl(signatures ...[]byte) ([]byte, error) {
	if len(signatures) < 1 {
		return nil, errors.New("Must aggregate at least 1 signature ")
	}

	newG2 := bls12377.NewG2()
	aggSig := newG2.New()

	for _, sig := range signatures {
		g2, err := bls12377.NewG2().FromCompressed(sig)
		if err != nil {
			return nil, err
		}
		aggSig = bls12377.NewG2().Add(newG2.New(), aggSig, g2)
	}

	return bls12377.NewG2().ToCompressed(aggSig), nil
}

func coreAggregateVerify(pks, messages [][]byte, sig, dst []byte) bool {
	pksLen := len(pks)

	if pksLen != len(messages) && pksLen < 1 {
		return false
	}

	g1Neg := new(bls12377.PointG1)
	g1Neg = bls12377.NewG1().Neg(g1Neg, G1Generator())

	signature, err := bls12377.NewG2().FromCompressed(sig)
	if err != nil {
		return false
	}

	engine := bls12377.NewEngine()
	engine.AddPair(g1Neg, signature)

	for index, pk := range pks {
		p, err := bls12377.NewG1().FromCompressed(pk)
		if err != nil {
			return false
		}

		g2Map := bls12377.NewG2()
		q, err := g2Map.HashToCurve(append(pks[index], messages[index]...), dst)
		if err != nil {
			return false
		}

		engine.AddPair(p, q)
	}
	return engine.Check()
}
