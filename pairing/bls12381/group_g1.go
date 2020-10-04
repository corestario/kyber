package bls12381

import (
	"crypto/cipher"
	"encoding/hex"
	"io"

	"github.com/corestario/kyber"
	"github.com/corestario/kyber/group/mod"
	bls "github.com/kilic/bls12-381"
)

// pointG1 is a kyber.Point holding a G1 point on BLS12-381 curve
type pointG1 struct {
	p *bls.PointG1
}

func newPointG1() *pointG1 {
	var p bls.PointG1
	return toPointG1(&p)
}

func toPointG1(p *bls.PointG1) *pointG1 {
	return &pointG1{p: p}
}

func (k *pointG1) Equal(k2 kyber.Point) bool {
	return bls.NewG1().Equal(k.p, k2.(*pointG1).p)
}

func (k *pointG1) Null() kyber.Point {
	k.Set(toPointG1(bls.NewG1().Zero()))
	return k
}

func (k *pointG1) Base() kyber.Point {
	k.Set(toPointG1(bls.NewG1().One()))
	return k
}

func (k *pointG1) Pick(rand cipher.Stream) kyber.Point {
	s := mod.NewInt64(0, bls.NewG1().Q()).Pick(rand)
	k.Mul(s, nil)
	return k
}

func (k *pointG1) Set(q kyber.Point) kyber.Point {
	k.p.Set(q.(*pointG1).p)
	return k
}

func (k *pointG1) Clone() kyber.Point {
	var p bls.PointG1
	p.Set(k.p)
	return toPointG1(&p)
}

func (k *pointG1) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (k *pointG1) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (k *pointG1) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (k *pointG1) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*pointG1)
	bb := b.(*pointG1)
	bls.NewG1().Add(k.p, aa.p, bb.p)
	return k
}

func (k *pointG1) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*pointG1)
	bb := b.(*pointG1)
	bls.NewG1().Sub(k.p, aa.p, bb.p)
	return k
}

func (k *pointG1) Neg(a kyber.Point) kyber.Point {
	aa := a.(*pointG1)
	bls.NewG1().Neg(k.p, aa.p)
	return k
}

func (k *pointG1) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = newPointG1().Base()
	}
	bls.NewG1().MulScalar(k.p, q.(*pointG1).p, &s.(*mod.Int).V)
	return k
}

func (k *pointG1) MarshalBinary() ([]byte, error) {
	return bls.NewG1().ToCompressed(k.p), nil
}

func (k *pointG1) UnmarshalBinary(buff []byte) error {
	var err error
	k.p, err = bls.NewG1().FromCompressed(buff)
	return err
}

func (k *pointG1) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (k *pointG1) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *pointG1) MarshalSize() int {
	return 48
}

func (k *pointG1) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.G1: " + hex.EncodeToString(b)
}

func (k *pointG1) Hash(m []byte) kyber.Point {
	p, _ := bls.NewG1().HashToCurve(m, Domain)
	k.p = p
	return k

}

func (k *pointG1) IsInCorrectGroup() bool {
	return bls.NewG1().InCorrectSubgroup(k.p)
}
