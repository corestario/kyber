// Package dkg implements a general distributed key generation (DKG) framework.
// This package serves two functionalities: (1) to run a fresh new DKG from
// scratch and (2) to reshare old shares to a potentially distinct new set of
// nodes (the "resharing" protocol). The former protocol is described in "A
// threshold cryptosystem without a trusted party" by Torben Pryds Pedersen.
// https://dl.acm.org/citation.cfm?id=1754929. The latter protocol is
// implemented in "Verifiable Secret Redistribution for Threshold Signing
// Schemes", by T. Wong et
// al.(https://www.cs.cmu.edu/~wing/publications/Wong-Wing02b.pdf)
package dkg

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/corestario/kyber"
	"github.com/corestario/kyber/util/random"

	"github.com/corestario/kyber/share"
	vss "github.com/corestario/kyber/share/vss/pedersen"
	"github.com/corestario/kyber/sign/schnorr"
)

// Suite wraps the functionalities needed by the dkg package
type Suite vss.Suite

// Config holds all required information to run a fresh DKG protocol or a
// resharing protocol. In the case of a new fresh DKG protocol, one must fill
// the following fields: Suite, Longterm, NewNodes, Threshold (opt). In the case
// of a resharing protocol, one must fill the following: Suite, Longterm,
// OldNodes, NewNodes. If the node using this config is creating new shares
// (i.e. it belongs to the current group), the Share field must be filled in
// with the current share of the node. If the node using this config is a new
// addition and thus has no current share, the PublicCoeffs field be must be
// filled in.
type Config struct {
	Suite Suite

	// Longterm is the longterm secret key.
	Longterm kyber.Scalar

	// Current group of share holders. It will be nil for new DKG. These nodes
	// will have invalid shares after the protocol has been run. To be able to issue
	// new shares to a new group, the group member's public key must be inside this
	// list and in the Share field. Keys can be disjoint or not with respect to the
	// NewNodes list.
	OldNodes []kyber.Point

	// PublicCoeffs are the coefficients of the distributed polynomial needed
	// during the resharing protocol. The first coefficient is the key. It is
	// required for new share holders.  It should be nil for a new DKG.
	PublicCoeffs []kyber.Point

	// Expected new group of share holders. These public-key designated nodes
	// will be in possession of new shares after the protocol has been run. To be a
	// receiver of a new share, one's public key must be inside this list. Keys
	// can be disjoint or not with respect to the OldNodes list.
	NewNodes []kyber.Point

	// Share to refresh. It must be nil for a new node wishing to
	// join or create a group. To be able to issue new fresh shares to a new group,
	// one's share must be specified here, along with the public key inside the
	// OldNodes field.
	Share *DistKeyShare

	// The threshold to use in order to reconstruct the secret with the produced
	// shares. This threshold is with respect to the number of nodes in the
	// NewNodes list. If unspecified, default is set to
	// `vss.MinimumT(len(NewNodes))`. This threshold indicates the degree of the
	// polynomials used to create the shares, and the minimum number of
	// verification required for each deal.
	Threshold int

	// OldThreshold holds the threshold value that was used in the previous
	// configuration. This field MUST be specified when doing resharing, but is
	// not needed when doing a fresh DKG. This value is required to gather a
	// correct number of valid deals before creating the distributed key share.
	// NOTE: this field is always required (instead of taking the default when
	// absent) when doing a resharing to avoid a downgrade attack, where a resharing
	// the number of deals required is less than what it is supposed to be.
	OldThreshold int

	// Reader is an optional field that can hold a user-specified entropy source.
	// If it is set, Reader's data will be combined with random data from crypto/rand
	// to create a random stream which will pick the dkg's secret coefficient. Otherwise,
	// the random stream will only use crypto/rand's entropy.
	Reader io.Reader

	// When UserReaderOnly it set to true, only the user-specified entropy source
	// Reader will be used. This should only be used in tests, allowing reproducibility.
	UserReaderOnly bool
}

type Verifiers map[uint32]*vss.Verifier

// DistKeyGenerator is the struct that runs the DKG protocol.
type DistKeyGenerator struct {
	// config driving the behavior of DistKeyGenerator
	C     *Config
	Suite Suite

	Long   kyber.Scalar
	Pub    kyber.Point
	Dpub   *share.PubPoly
	Dealer *vss.Dealer
	// VerifiersMap indexed by Dealer index
	VerifiersMap map[uint32]*vss.Verifier
	// performs the part of the response verification for old nodes
	OldAggregators map[uint32]*vss.Aggregator
	// index in the old list of nodes
	Oidx int
	// index in the new list of nodes
	Nidx int
	// old threshold used in the previous DKG
	OldT int
	// new threshold to use in this round
	NewT int
	// indicates whether we are in the re-sharing protocol or basic DKG
	IsResharing bool
	// indicates whether we are able to issue shares or not
	CanIssue bool
	// Indicates whether we are able to receive a new share or not
	CanReceive bool
	// indicates whether the node holding the Pub key is present in the new list
	NewPresent bool
	// indicates whether the node is present in the old list
	OldPresent bool
	// already Processed our own deal
	Processed bool
	// did the Timeout / period / already occured or not
	Timeout bool
}

// NewDistKeyHandler takes a Config and returns a DistKeyGenerator that is able
// to drive the DKG or resharing protocol.
func NewDistKeyHandler(c *Config) (*DistKeyGenerator, error) {
	if c.NewNodes == nil && c.OldNodes == nil {
		return nil, errors.New("dkg: can't run with empty node list")
	}

	var isResharing bool
	if c.Share != nil || c.PublicCoeffs != nil {
		isResharing = true
	}
	if isResharing {
		if c.OldNodes == nil {
			return nil, errors.New("dkg: resharing config needs old nodes list")
		}
		if c.OldThreshold == 0 {
			return nil, errors.New("dkg: resharing case needs old threshold field")
		}
	}
	// CanReceive is true by default since in the default DKG mode everyone
	// participates
	var canReceive = true
	pub := c.Suite.Point().Mul(c.Longterm, nil)
	oidx, oldPresent := findPub(c.OldNodes, pub)
	nidx, newPresent := findPub(c.NewNodes, pub)
	if !oldPresent && !newPresent {
		return nil, errors.New("dkg: public key not found in old list or new list")
	}

	var newThreshold int
	if c.Threshold != 0 {
		newThreshold = c.Threshold
	} else {
		newThreshold = vss.MinimumT(len(c.NewNodes))
	}

	var dealer *vss.Dealer
	var err error
	var canIssue bool
	if c.Share != nil {
		// resharing case
		secretCoeff := c.Share.Share.V
		dealer, err = vss.NewDealer(c.Suite, c.Longterm, secretCoeff, c.NewNodes, newThreshold)
		canIssue = true
	} else if !isResharing && newPresent {
		// fresh DKG case
		randomStream := random.New()
		// if the user provided a reader, use it alone or combined with crypto/rand
		if c.Reader != nil && !c.UserReaderOnly {
			randomStream = random.New(c.Reader, rand.Reader)
		} else if c.Reader != nil && c.UserReaderOnly {
			randomStream = random.New(c.Reader)
		}
		secretCoeff := c.Suite.Scalar().Pick(randomStream)
		dealer, err = vss.NewDealer(c.Suite, c.Longterm, secretCoeff, c.NewNodes, newThreshold)
		canIssue = true
		c.OldNodes = c.NewNodes
		oidx, oldPresent = findPub(c.OldNodes, pub)
	}

	if err != nil {
		return nil, err
	}

	var dpub *share.PubPoly
	var oldThreshold int
	if !newPresent {
		// if we are not in the new list of nodes, then we definitely can't
		// receive anything
		canReceive = false
	} else if isResharing && newPresent {
		if c.PublicCoeffs == nil && c.Share == nil {
			return nil, errors.New("dkg: can't receive new shares without the public polynomial")
		} else if c.PublicCoeffs != nil {
			dpub = share.NewPubPoly(c.Suite, c.Suite.Point().Base(), c.PublicCoeffs)
		} else if c.Share != nil {
			// take the commits of the share, no need to duplicate information
			c.PublicCoeffs = c.Share.Commits
			dpub = share.NewPubPoly(c.Suite, c.Suite.Point().Base(), c.PublicCoeffs)
		}
		// oldThreshold is only useful in the context of a new share holder, to
		// make sure there are enough correct deals from the old nodes.
		canReceive = true
		oldThreshold = len(c.PublicCoeffs)
	}
	dkg := &DistKeyGenerator{
		Dealer:         dealer,
		OldAggregators: make(map[uint32]*vss.Aggregator),
		Suite:          c.Suite,
		Long:           c.Longterm,
		Pub:            pub,
		CanReceive:     canReceive,
		CanIssue:       canIssue,
		IsResharing:    isResharing,
		Dpub:           dpub,
		Oidx:           oidx,
		Nidx:           nidx,
		C:              c,
		OldT:           oldThreshold,
		NewT:           newThreshold,
		NewPresent:     newPresent,
		OldPresent:     oldPresent,
	}
	if newPresent {
		err = dkg.initVerifiers(c)
	}
	return dkg, err
}

// NewDistKeyGenerator returns a dist key generator ready to create a fresh
// distributed key with the regular DKG protocol.
func NewDistKeyGenerator(suite Suite, longterm kyber.Scalar, participants []kyber.Point, t int) (*DistKeyGenerator, error) {
	c := &Config{
		Suite:     suite,
		Longterm:  longterm,
		NewNodes:  participants,
		Threshold: t,
	}
	return NewDistKeyHandler(c)
}

func (d *DistKeyGenerator) GetConfig() *Config {
	return d.C
}

func (d *DistKeyGenerator) GetDealer() *vss.Dealer {
	return d.Dealer
}

// Deals returns all the deals that must be broadcasted to all participants in
// the new list. The deal corresponding to this DKG is already added to this DKG
// and is ommitted from the returned map. To know which participant a deal
// belongs to, loop over the keys as indices in the list of new participants:
//
//   for i,dd := range distDeals {
//      sendTo(participants[i],dd)
//   }
//
// If this method cannot process its own Deal, that indicates a
// severe problem with the configuration or implementation and
// results in a panic.
func (d *DistKeyGenerator) Deals() (map[int]*Deal, error) {
	if !d.CanIssue {
		// We do not hold a share, so we cannot make a deal, so
		// return an empty map and no error. This makes callers not
		// need to care if they are in a resharing context or not.
		return nil, nil
	}
	deals, err := d.Dealer.EncryptedDeals()
	if err != nil {
		return nil, err
	}
	dd := make(map[int]*Deal)
	for i := range d.C.NewNodes {
		distd := &Deal{
			Index: uint32(d.Oidx),
			Deal:  deals[i],
		}
		// sign the deal
		buff, err := distd.MarshalBinary()
		if err != nil {
			return nil, err
		}
		distd.Signature, err = schnorr.Sign(d.Suite, d.Long, buff)
		if err != nil {
			return nil, err
		}

		if i == int(d.Nidx) && d.NewPresent {
			if d.Processed {
				continue
			}
			d.Processed = true
			if resp, err := d.ProcessDeal(distd); err != nil {
				panic("dkg: cannot process own deal: " + err.Error())
			} else if resp.Response.Status != vss.StatusApproval {
				panic("dkg: own deal gave a complaint")
			}
			continue
		}
		dd[i] = distd
	}
	return dd, nil
}

// ProcessDeal takes a Deal created by Deals() and stores and verifies it. It
// returns a Response to broadcast to every other participant, including the old
// participants. It returns an error in case the deal has already been stored,
// or if the deal is incorrect (see vss.Verifier.ProcessEncryptedDeal).
func (d *DistKeyGenerator) ProcessDeal(dd *Deal) (*Response, error) {
	if !d.NewPresent {
		return nil, errors.New("dkg: unexpected deal for unlisted Dealer in new list")
	}
	var pub kyber.Point
	var ok bool
	if d.IsResharing {
		pub, ok = getPub(d.C.OldNodes, dd.Index)
	} else {
		pub, ok = getPub(d.C.NewNodes, dd.Index)
	}
	// public key of the Dealer
	if !ok {
		return nil, errors.New("dkg: dist deal out of bounds index")
	}

	// verify signature
	buff, err := dd.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err := schnorr.Verify(d.Suite, pub, buff, dd.Signature); err != nil {
		return nil, err
	}

	ver, _ := d.VerifiersMap[dd.Index]

	resp, err := ver.ProcessEncryptedDeal(dd.Deal)
	if err != nil {
		return nil, err
	}

	reject := func() (*Response, error) {
		idx, present := findPub(d.C.NewNodes, pub)
		if present {
			// the Dealer is present in both list, so we set its own response
			// (as a verifier) to a complaint since he won't do it himself
			d.VerifiersMap[uint32(dd.Index)].UnsafeSetResponseDKG(uint32(idx), vss.StatusComplaint)
		}
		// indicate to VSS that this dkg's new status is complaint for this
		// deal
		d.VerifiersMap[uint32(dd.Index)].UnsafeSetResponseDKG(uint32(d.Nidx), vss.StatusComplaint)
		resp.Status = vss.StatusComplaint
		s, err := schnorr.Sign(d.Suite, d.Long, resp.Hash(d.Suite))
		if err != nil {
			return nil, err
		}
		resp.Signature = s
		return &Response{
			Index:    dd.Index,
			Response: resp,
		}, nil
	}

	if d.IsResharing && d.CanReceive {
		// verify share integrity wrt to the dist. secret
		dealCommits := ver.Commits()
		// Check that the received committed share is equal to the one we
		// generate from the known public polynomial
		expectedPubShare := d.Dpub.Eval(int(dd.Index))
		if !expectedPubShare.V.Equal(dealCommits[0]) {
			return reject()
		}
	}

	// if the Dealer in the old list is also present in the new list, then set
	// his response to approval since he won't issue his own response for his
	// own deal
	newIdx, found := findPub(d.C.NewNodes, pub)
	if found {
		d.VerifiersMap[dd.Index].UnsafeSetResponseDKG(uint32(newIdx), vss.StatusApproval)
	}

	return &Response{
		Index:    dd.Index,
		Response: resp,
	}, nil
}

// ProcessResponse takes a response from every other peer.  If the response
// designates the deal of another participant than this dkg, this dkg stores it
// and returns nil with a possible error regarding the validity of the response.
// If the response designates a deal this dkg has issued, then the dkg will process
// the response, and returns a justification.
func (d *DistKeyGenerator) ProcessResponse(resp *Response) (*Justification, error) {
	if d.IsResharing && d.CanIssue && !d.NewPresent {
		return d.processResharingResponse(resp)
	}
	v, ok := d.VerifiersMap[resp.Index]
	if !ok {
		return nil, fmt.Errorf("dkg: responses received for unknown Dealer %d", resp.Index)
	}

	if err := v.ProcessResponse(resp.Response); err != nil {
		return nil, err
	}

	myIdx := uint32(d.Oidx)
	if !d.CanIssue || resp.Index != myIdx {
		// no justification if we dont issue deals or the deal's not from us
		return nil, nil
	}

	j, err := d.Dealer.ProcessResponse(resp.Response)
	if err != nil {
		return nil, err
	}
	if j == nil {
		return nil, nil
	}
	if err := v.ProcessJustification(j); err != nil {
		return nil, err
	}

	return &Justification{
		Index:         uint32(d.Oidx),
		Justification: j,
	}, nil
}

// special case when an node that is present in the old list but not in the
// new,i.e. leaving the group. This node does not have any VerifiersMap since it
// can't receive shares. This function makes some check on the response and
// returns a justification if the response is invalid.
func (d *DistKeyGenerator) processResharingResponse(resp *Response) (*Justification, error) {
	agg, present := d.OldAggregators[resp.Index]
	if !present {
		agg = vss.NewEmptyAggregator(d.Suite, d.C.NewNodes)
		d.OldAggregators[resp.Index] = agg
	}

	err := agg.ProcessResponse(resp.Response)
	if int(resp.Index) != d.Oidx {
		return nil, err
	}

	if resp.Response.Status == vss.StatusApproval {
		return nil, nil
	}

	// status is complaint and it is about our deal
	deal, err := d.Dealer.PlaintextDeal(int(resp.Response.Index))
	if err != nil {
		return nil, errors.New("dkg: resharing response can't get deal. BUG - REPORT")
	}
	j := &Justification{
		Index: uint32(d.Oidx),
		Justification: &vss.Justification{
			SessionID: d.Dealer.SessionID(),
			Index:     resp.Response.Index, // good index because of signature check
			Deal:      deal,
		},
	}
	return j, nil
}

// ProcessJustification takes a justification and validates it. It returns an
// error in case the justification is wrong.
func (d *DistKeyGenerator) ProcessJustification(j *Justification) error {
	v, ok := d.VerifiersMap[j.Index]
	if !ok {
		return errors.New("dkg: Justification received but no deal for it")
	}
	return v.ProcessJustification(j.Justification)
}

// SetTimeout triggers the Timeout on all VerifiersMap, and thus makes sure
// all VerifiersMap have either responded, or have a StatusComplaint response.
func (d *DistKeyGenerator) SetTimeout() {
	d.Timeout = true
	for _, v := range d.VerifiersMap {
		v.SetTimeout()
	}
}

// ThresholdCertified returns true if a THRESHOLD of deals are certified. To know the
// list of correct receiver, one can call d.QUAL()
// NOTE:
// This method should only be used after a certain Timeout - mimicking the
// synchronous assumption of the Pedersen's protocol. One can call
// `Certified()` to check if the DKG is finished and stops it pre-emptively
// if all deals are correct.  If called *before* the Timeout, there may be
// inconsistencies in the shares produced. For example, node 1 could have
// aggregated shares from 1, 2, 3 and node 2 could have aggregated shares from
// 2, 3 and 4.
func (d *DistKeyGenerator) ThresholdCertified() bool {
	if d.IsResharing {
		// in resharing case, we have two threshold. Here we want the number of
		// deals to be at least what the old threshold was. (and for each deal,
		// we want the number of approval to be a least what the new threshold
		// is).
		return len(d.QUAL()) >= d.C.OldThreshold
	}
	// in dkg case, the threshold is symmetric -> # VerifiersMap = # dealers
	return len(d.QUAL()) >= d.C.Threshold
}

// Certified returns true if *all* deals are certified. This method should
// be called before the Timeout occurs, as to pre-emptively stop the DKG
// protocol if it is already finished before the Timeout.
func (d *DistKeyGenerator) Certified() bool {
	var good []int
	if d.IsResharing && d.CanIssue && !d.NewPresent {
		d.oldQualIter(func(i uint32, v *vss.Aggregator) bool {
			if len(v.MissingResponses()) > 0 {
				return false
			}
			good = append(good, int(i))
			return true
		})
	} else {
		d.qualIter(func(i uint32, v *vss.Verifier) bool {
			if len(v.MissingResponses()) > 0 {
				return false
			}
			good = append(good, int(i))
			return true
		})
	}
	return len(good) >= len(d.C.OldNodes)
}

// QualifiedShares returns the set of shares holder index that are considered
// valid. In particular, it computes the list of common share holders that
// replied with an approval (or with a complaint later on justified) for each
// deal received. These indexes represent the new share holders with valid (or
// justified) shares from certified deals.  Detailled explanation:
// To compute this list, we consider the scenario where a share holder replied
// to one share but not the other, as invalid, as the library is not currently
// equipped to deal with that scenario.
// 1.  If there is a valid complaint non-justified for a deal, the deal is deemed
// invalid
// 2. if there are no response from a share holder, the share holder is
// removed from the list.
func (d *DistKeyGenerator) QualifiedShares() []int {
	var invalidSh = make(map[int]bool)
	var invalidDeals = make(map[int]bool)
	// compute list of invalid deals according to 1.
	for dealerIndex, verifier := range d.VerifiersMap {
		responses := verifier.Responses()
		if len(responses) == 0 {
			// don't analyzes "empty" deals - i.e. dealers that never sent
			// their deal in the first place.
			invalidDeals[int(dealerIndex)] = true
		}
		for holderIndex := range d.C.NewNodes {
			resp, ok := responses[uint32(holderIndex)]
			if ok && resp.Status == vss.StatusComplaint {
				// 1. rule
				invalidDeals[int(dealerIndex)] = true
				break
			}
		}
	}

	// compute list of invalid share holders for valid deals
	for dealerIndex, verifier := range d.VerifiersMap {
		// skip analyze of invalid deals
		if _, present := invalidDeals[int(dealerIndex)]; present {
			continue
		}
		responses := verifier.Responses()
		for holderIndex := range d.C.NewNodes {
			_, ok := responses[uint32(holderIndex)]
			if !ok {
				// 2. rule - absent response
				invalidSh[holderIndex] = true
			}
		}
	}

	var validHolders []int
	for i := range d.C.NewNodes {
		if _, included := invalidSh[i]; included {
			continue
		}
		validHolders = append(validHolders, i)
	}
	return validHolders
}

// ExpectedDeals returns the number of deals that this node will
// receive from the other participants.
func (d *DistKeyGenerator) ExpectedDeals() int {
	switch {
	case d.NewPresent && d.OldPresent:
		return len(d.C.OldNodes) - 1
	case d.NewPresent && !d.OldPresent:
		return len(d.C.OldNodes)
	default:
		return 0
	}
}

// QUAL returns the index in the list of participants that forms the QUALIFIED
// set, i.e. the list of Certified deals.
// It does NOT take into account any malicious share holder which share may have
// been revealed, due to invalid complaint.
func (d *DistKeyGenerator) QUAL() []int {
	var good []int
	if d.IsResharing && d.CanIssue && !d.NewPresent {
		d.oldQualIter(func(i uint32, v *vss.Aggregator) bool {
			good = append(good, int(i))
			return true
		})
		return good
	}
	d.qualIter(func(i uint32, v *vss.Verifier) bool {
		good = append(good, int(i))
		return true
	})
	return good
}

func (d *DistKeyGenerator) isInQUAL(idx uint32) bool {
	var found bool
	d.qualIter(func(i uint32, v *vss.Verifier) bool {
		if i == idx {
			found = true
			return false
		}
		return true
	})
	return found
}

func (d *DistKeyGenerator) qualIter(fn func(idx uint32, v *vss.Verifier) bool) {
	for i, v := range d.VerifiersMap {
		if v.DealCertified() {
			if !fn(i, v) {
				break
			}
		}
	}
}

func (d *DistKeyGenerator) oldQualIter(fn func(idx uint32, v *vss.Aggregator) bool) {
	for i, v := range d.OldAggregators {
		if v.DealCertified() {
			if !fn(i, v) {
				break
			}
		}
	}
}

// DistKeyShare generates the distributed key relative to this receiver.
// It throws an error if something is wrong such as not enough deals received.
// The shared secret can be computed when all deals have been sent and
// basically consists of a public point and a share. The public point is the sum
// of all aggregated individual public commits of each individual secrets.
// The share is evaluated from the global Private Polynomial, basically SUM of
// fj(i) for a receiver i.
func (d *DistKeyGenerator) DistKeyShare() (*DistKeyShare, error) {
	if !d.ThresholdCertified() {
		return nil, errors.New("dkg: distributed key not certified")
	}
	if !d.CanReceive {
		return nil, errors.New("dkg: should not expect to compute any dist. share")
	}

	if d.IsResharing {
		return d.resharingKey()
	}

	return d.dkgKey()
}

func (d *DistKeyGenerator) dkgKey() (*DistKeyShare, error) {
	sh := d.Suite.Scalar().Zero()
	var pub *share.PubPoly
	var err error
	d.qualIter(func(i uint32, v *vss.Verifier) bool {
		// share of dist. secret = sum of all share received.
		deal := v.Deal()
		s := deal.SecShare.V
		sh = sh.Add(sh, s)
		// Dist. public key = sum of all revealed commitments
		poly := share.NewPubPoly(d.Suite, d.Suite.Point().Base(), deal.Commitments)
		if pub == nil {
			// first polynomial we see (instead of generating n empty commits)
			pub = poly
			return true
		}
		pub, err = pub.Add(poly)
		return err == nil
	})

	if err != nil {
		return nil, err
	}
	_, commits := pub.Info()

	return &DistKeyShare{
		Commits: commits,
		Share: &share.PriShare{
			I: int(d.Nidx),
			V: sh,
		},
		PrivatePoly: d.Dealer.PrivatePoly().Coefficients(),
	}, nil

}

func (d *DistKeyGenerator) resharingKey() (*DistKeyShare, error) {
	// only old nodes sends shares
	shares := make([]*share.PriShare, len(d.C.OldNodes))
	coeffs := make([][]kyber.Point, len(d.C.OldNodes))
	d.qualIter(func(i uint32, v *vss.Verifier) bool {
		deal := v.Deal()
		coeffs[int(i)] = deal.Commitments
		// share of dist. secret. Invertion of rows/column
		deal.SecShare.I = int(i)
		shares[int(i)] = deal.SecShare
		return true
	})

	// the private polynomial is generated from the old nodes, thus inheriting
	// the old threshold condition
	priPoly, err := share.RecoverPriPoly(d.Suite, shares, d.OldT, len(d.C.OldNodes))
	if err != nil {
		return nil, err
	}
	privateShare := &share.PriShare{
		I: int(d.Nidx),
		V: priPoly.Secret(),
	}

	// recover public polynomial by interpolating coefficient-wise all
	// polynomials
	// the new public polynomial must however have "NewT" coefficients since it
	// will be held by the new nodes.
	finalCoeffs := make([]kyber.Point, d.NewT)
	for i := 0; i < d.NewT; i++ {
		tmpCoeffs := make([]*share.PubShare, len(coeffs))
		// take all i-th coefficients
		for j := range coeffs {
			if coeffs[j] == nil {
				continue
			}
			tmpCoeffs[j] = &share.PubShare{I: j, V: coeffs[j][i]}
		}

		// using the old threshold / length because there are at most
		// len(d.C.OldNodes) i-th coefficients since they are the one generating one
		// each, thus using the old threshold.
		coeff, err := share.RecoverCommit(d.Suite, tmpCoeffs, d.OldT, len(d.C.OldNodes))
		if err != nil {
			return nil, err
		}
		finalCoeffs[i] = coeff
	}

	// Reconstruct the final public polynomial
	pubPoly := share.NewPubPoly(d.Suite, nil, finalCoeffs)

	if !pubPoly.Check(privateShare) {
		return nil, errors.New("dkg: share do not correspond to public polynomial ><")
	}
	return &DistKeyShare{
		Commits:     finalCoeffs,
		Share:       privateShare,
		PrivatePoly: priPoly.Coefficients(),
	}, nil
}

// verifiers returns the VerifiersMap keeping state of each deals
func (d *DistKeyGenerator) Verifiers() map[uint32]*vss.Verifier {
	return d.VerifiersMap
}

func (d *DistKeyGenerator) initVerifiers(c *Config) error {
	var alreadyTaken = make(map[string]bool)
	verifierList := c.NewNodes
	dealerList := c.OldNodes
	verifiers := make(map[uint32]*vss.Verifier)
	for i, pub := range dealerList {
		if _, exists := alreadyTaken[pub.String()]; exists {
			return errors.New("duplicate public key in NewNodes list")
		}
		alreadyTaken[pub.String()] = true
		ver, err := vss.NewVerifier(c.Suite, c.Longterm, pub, verifierList)
		if err != nil {
			return err
		}
		// set that the number of approval for this deal must be at the given
		// threshold regarding the new nodes. (see config.
		ver.SetThreshold(c.Threshold)
		verifiers[uint32(i)] = ver
	}
	d.VerifiersMap = verifiers
	return nil
}

//Renew adds the new distributed key share g (with secret 0) to the distributed key share d.
func (d *DistKeyShare) Renew(suite Suite, g *DistKeyShare) (*DistKeyShare, error) {
	// Check G(0) = 0*G.
	if !g.Public().Equal(suite.Point().Base().Mul(suite.Scalar().Zero(), nil)) {
		return nil, errors.New("wrong renewal function")
	}

	// Check whether they have the same index
	if d.Share.I != g.Share.I {
		return nil, errors.New("not the same party")
	}

	newShare := suite.Scalar().Add(d.Share.V, g.Share.V)
	newCommits := make([]kyber.Point, len(d.Commits))
	for i := range newCommits {
		newCommits[i] = suite.Point().Add(d.Commits[i], g.Commits[i])
	}
	return &DistKeyShare{
		Commits: newCommits,
		Share: &share.PriShare{
			I: d.Share.I,
			V: newShare,
		},
	}, nil
}

func getPub(list []kyber.Point, i uint32) (kyber.Point, bool) {
	if i >= uint32(len(list)) {
		return nil, false
	}
	return list[i], true
}

func findPub(list []kyber.Point, toFind kyber.Point) (int, bool) {
	for i, p := range list {
		if p.Equal(toFind) {
			return i, true
		}
	}
	return 0, false
}

func checksDealCertified(i uint32, v *vss.Verifier) bool {
	return v.DealCertified()
}
