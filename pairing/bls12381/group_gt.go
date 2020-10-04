package bls12381

import (
	"crypto/cipher"
	"encoding/hex"
	"io"

	"github.com/corestario/kyber"
	"github.com/corestario/kyber/group/mod"
	bls "github.com/kilic/bls12-381"
)

// pointGT is a kyber.Point holding a G1 point on BLS12-381 curve
type pointGT struct {
	f *bls.E
}

func newPointGT() *pointGT {
	return toPointGT(bls.NewGT().New())
}
func toPointGT(f *bls.E) *pointGT {
	return &pointGT{
		f: f,
	}
}

func (k *pointGT) Equal(kk kyber.Point) bool {
	return k.f.Equal(kk.(*pointGT).f)
}

const gtLength = 576

func (k *pointGT) Null() kyber.Point {
	k.f = bls.NewGT().New()
	return k
}

func (k *pointGT) Base() kyber.Point {
	g1 := bls.NewG1().One()
	g2 := bls.NewG2().One()
	e := bls.NewEngine()
	e.AddPair(g1, g2)
	k.f = e.Result()
	return k
}

func (k *pointGT) Pick(rand cipher.Stream) kyber.Point {
	s := mod.NewInt64(0, bls.NewGT().Q()).Pick(rand)
	k.Base()
	bls.NewGT().Exp(k.f, k.f, &s.(*mod.Int).V)
	return k
}

func (k *pointGT) Set(q kyber.Point) kyber.Point {
	k.f.Set(q.(*pointGT).f)
	return k
}

func (k *pointGT) Clone() kyber.Point {
	kk := newPointGT()
	kk.Set(k)
	return kk
}

func (k *pointGT) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*pointGT)
	bb := b.(*pointGT)
	bls.NewGT().Mul(k.f, aa.f, bb.f)
	return k
}

func (k *pointGT) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*pointGT)
	bb := b.(*pointGT)
	bls.NewGT().Inverse(k.f, bb.f)
	bls.NewGT().Mul(k.f, aa.f, k.f)
	return k
}

func (k *pointGT) Neg(q kyber.Point) kyber.Point {
	aa := q.(*pointGT)
	bls.NewGT().Inverse(k.f, aa.f)
	return k
}

func (k *pointGT) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = newPointGT().Base()
	}
	bls.NewGT().Exp(k.f, q.(*pointGT).f, &s.(*mod.Int).V)
	return k
}

func (k *pointGT) MarshalBinary() ([]byte, error) {
	return bls.NewGT().ToBytes(k.f), nil
}

func (k *pointGT) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (k *pointGT) UnmarshalBinary(buf []byte) error {
	fe12, err := bls.NewGT().FromBytes(buf)
	k.f = fe12
	return err
}

func (k *pointGT) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *pointGT) MarshalSize() int {
	return 576
}

func (k *pointGT) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.GT: " + hex.EncodeToString(b)
}

func (k *pointGT) EmbedLen() int {
	panic("bls12-381.GT.EmbedLen(): unsupported operation")
}

func (k *pointGT) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bls12-381.GT.Embed(): unsupported operation")
}

func (k *pointGT) Data() ([]byte, error) {
	panic("bls12-381.GT.Data(): unsupported operation")
}
