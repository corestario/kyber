package tbls

import (
	"testing"

	curve "github.com/corestario/kyber/pairing/bls12381"
	"github.com/corestario/kyber/share"
	"github.com/corestario/kyber/sign/bls"
	prysmBLS "github.com/prysmaticlabs/prysm/shared/bls"
	"github.com/stretchr/testify/require"
)

func TestTBLS(test *testing.T) {
	var err error
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := curve.NewBLS12381Suite()
	n := 10
	t := n/2 + 1
	secret := suite.G2().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G1(), t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G1().Point().Base())
	sigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, err := Sign(suite, x, msg)
		require.Nil(test, err)
		sigShares = append(sigShares, sig)
	}
	sig, err := Recover(suite, pubPoly, msg, sigShares, t, n)
	require.Nil(test, err)
	err = bls.Verify(suite, pubPoly.Commit(), msg, sig)
	require.Nil(test, err)
}

func TestTBLSFail(test *testing.T) {
	var err error
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := curve.NewBLS12381Suite()
	n := 10
	t := n/2 + 1
	secret := suite.G2().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G1(), t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G1().Point().Base())
	sigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, err := Sign(suite, x, msg)
		require.Nil(test, err)
		sigShares = append(sigShares, sig)
	}
	sig, err := Recover(suite, pubPoly, msg, sigShares, t-1, n)
	require.Nil(test, err)
	if bls.Verify(suite, pubPoly.Commit(), msg, sig) == nil {
		test.Fatal("bls: verification succeeded unexpectedly")
	}
}

func TestPrismCompatibility(test *testing.T) {
	var err error
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := curve.NewBLS12381Suite()
	n := 10
	t := n/2 + 1
	secret := suite.G2().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G1(), t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G1().Point().Base())
	sigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, err := Sign(suite, x, msg)
		require.Nil(test, err)
		sigShares = append(sigShares, sig)
	}
	sig, err := Recover(suite, pubPoly, msg, sigShares, t, n)
	require.Nil(test, err)

	pubKeyBytes, err := pubPoly.Commit().MarshalBinary()
	require.Nil(test, err)

	_, err = prysmBLS.PublicKeyFromBytes(pubKeyBytes)
	require.Nil(test, err)

	_, err = prysmBLS.SignatureFromBytes(sig)
	require.Nil(test, err)

	priBytes, err := priPoly.Secret().MarshalBinary()
	require.Nil(test, err)
	_, err = prysmBLS.SecretKeyFromBytes(priBytes)
	require.Nil(test, err)
}
