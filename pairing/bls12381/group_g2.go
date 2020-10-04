package bls12381

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/corestario/kyber"
	"github.com/corestario/kyber/group/mod"
	bls "github.com/kilic/bls12-381"
)

// Domain comes from the ciphersuite used by the RFC of this name compatible
// with the paired library > v18
var Domain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

// pointG2 is a kyber.Point holding a G2 point on BLS12-381 curve
type pointG2 struct {
	p *bls.PointG2
}

func newPointG2() *pointG2 {
	var p bls.PointG2
	return toPointG2(&p)
}

func toPointG2(p *bls.PointG2) *pointG2 {
	return &pointG2{p: p}
}

func (k *pointG2) Equal(k2 kyber.Point) bool {
	return bls.NewG2().Equal(k.p, k2.(*pointG2).p)
}

func (k *pointG2) Null() kyber.Point {
	k.Set(toPointG2(bls.NewG2().Zero()))
	return k
}

func (k *pointG2) Base() kyber.Point {
	k.Set(toPointG2(bls.NewG2().One()))
	return k
}

func (k *pointG2) Pick(rand cipher.Stream) kyber.Point {
	s := mod.NewInt64(0, bls.NewG2().Q()).Pick(rand)
	k.Mul(s, nil)
	return k
}

func (k *pointG2) Set(q kyber.Point) kyber.Point {
	k.p.Set(q.(*pointG2).p)
	return k
}

func (k *pointG2) Clone() kyber.Point {
	var p bls.PointG2
	p.Set(k.p)
	return toPointG2(&p)
}

func (k *pointG2) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (k *pointG2) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (k *pointG2) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (k *pointG2) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*pointG2)
	bb := b.(*pointG2)
	bls.NewG2().Add(k.p, aa.p, bb.p)
	return k
}

func (k *pointG2) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*pointG2)
	bb := b.(*pointG2)
	bls.NewG2().Sub(k.p, aa.p, bb.p)
	return k
}

func (k *pointG2) Neg(a kyber.Point) kyber.Point {
	aa := a.(*pointG2)
	bls.NewG2().Neg(k.p, aa.p)
	return k
}

func (k *pointG2) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = newPointG2().Base()
	}
	bls.NewG2().MulScalar(k.p, q.(*pointG2).p, &s.(*mod.Int).V)
	return k
}

func (k *pointG2) MarshalBinary() ([]byte, error) {
	return bls.NewG2().ToCompressed(k.p), nil
}

func (k *pointG2) UnmarshalBinary(buff []byte) error {
	var err error
	k.p, err = bls.NewG2().FromCompressed(buff)
	return err
}

func (k *pointG2) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (k *pointG2) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *pointG2) MarshalSize() int {
	return 96
}

func (k *pointG2) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.G1: " + hex.EncodeToString(b)
}

func (k *pointG2) Hash(m []byte) kyber.Point {
	pg2, _ := bls.NewG2().HashToCurve(m, Domain)
	k.p = pg2
	return k
}

func sha256Hash(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}

func (k *pointG2) IsInCorrectGroup() bool {
	return bls.NewG2().InCorrectSubgroup(k.p)
}
