package bdn

import (
	"fmt"
	"testing"

	"github.com/corestario/kyber"
	"github.com/corestario/kyber/pairing"
	curve "github.com/corestario/kyber/pairing/bls12381"
	"github.com/corestario/kyber/sign"
	"github.com/corestario/kyber/sign/bls"
	"github.com/corestario/kyber/util/random"
	"github.com/stretchr/testify/require"
)

const SEED = "somestandart_seed_with_32_length"

var suite = curve.NewBLS12381Suite([]byte(SEED))
var two = suite.Scalar().Add(suite.Scalar().One(), suite.Scalar().One())
var three = suite.Scalar().Add(two, suite.Scalar().One())

// Reference test for other languages
func TestBDN_HashPointToR_BLS12381(t *testing.T) {
	p1 := suite.Point().Base()
	p2 := suite.Point().Mul(two, suite.Point().Base())
	p3 := suite.Point().Mul(three, suite.Point().Base())

	coefs, err := hashPointToR([]kyber.Point{p1, p2, p3})

	require.NoError(t, err)
	require.Equal(t, "1ad6a4986b95997561882f038ff08bd6", coefs[0].String())
	require.Equal(t, "a067df38969dce8d54a4d9f35ac504a0", coefs[1].String())
	require.Equal(t, "1607c6dcb5e0c6dbee30b1a2edb61a1c", coefs[2].String())
	require.Equal(t, 16, coefs[0].MarshalSize())

	mask, _ := sign.NewMask(suite.(pairing.Suite), []kyber.Point{p1, p2, p3}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)
	mask.SetBit(2, true)

	agg, err := AggregatePublicKeys(suite.((pairing.Suite)), mask)
	require.NoError(t, err)

	buf, err := agg.MarshalBinary()
	require.NoError(t, err)
	ref := "823c2c5e536dc393bec982c57a7c4c070a508aa23d673466553486d918a7288ba80368854174dcda90d700754ef9d84b"
	require.Equal(t, ref, fmt.Sprintf("%x", buf))
}

func TestBDN_AggregateSignatures(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := curve.NewBLS12381Suite([]byte(SEED)).(pairing.Suite)
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.NoError(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)

	_, err = AggregateSignatures(suite, [][]byte{sig1}, mask)
	require.Error(t, err)

	aggregatedSig, err := AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := AggregatePublicKeys(suite, mask)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.NoError(t, err)

	mask.SetBit(1, false)
	aggregatedKey, err = AggregatePublicKeys(suite, mask)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.Error(t, err)
}

func TestBDN_SubsetSignature(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := curve.NewBLS12381Suite([]byte(SEED)).(pairing.Suite)
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	_, public3 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg)
	require.NoError(t, err)
	sig2, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public3, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(2, true)

	aggregatedSig, err := AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	require.NoError(t, err)

	aggregatedKey, err := AggregatePublicKeys(suite, mask)

	sig, err := aggregatedSig.MarshalBinary()
	require.NoError(t, err)

	err = Verify(suite, aggregatedKey, msg, sig)
	require.NoError(t, err)
}

func TestBDN_RogueAttack(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := curve.NewBLS12381Suite([]byte(SEED)).(pairing.Suite)
	// honest
	_, public1 := NewKeyPair(suite, random.New())
	// attacker
	private2, public2 := NewKeyPair(suite, random.New())

	// create a forged public-key for public1
	rogue := public1.Clone().Sub(public2, public1)

	pubs := []kyber.Point{public1, rogue}

	sig, err := Sign(suite, private2, msg)
	require.NoError(t, err)

	// Old scheme not resistant to the attack
	agg := bls.AggregatePublicKeys(suite, pubs...)
	require.NoError(t, bls.Verify(suite, agg, msg, sig))

	// New scheme that should detect
	mask, _ := sign.NewMask(suite, pubs, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, true)
	agg, err = AggregatePublicKeys(suite, mask)
	require.NoError(t, err)
	require.Error(t, Verify(suite, agg, msg, sig))
}

func Benchmark_BDN_AggregateSigs(b *testing.B) {
	suite := curve.NewBLS12381Suite([]byte(SEED)).(pairing.Suite)
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := Sign(suite, private1, msg)
	require.Nil(b, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(b, err)

	mask, _ := sign.NewMask(suite, []kyber.Point{public1, public2}, nil)
	mask.SetBit(0, true)
	mask.SetBit(1, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AggregateSignatures(suite, [][]byte{sig1, sig2}, mask)
	}
}
