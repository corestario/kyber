package dkg

import (
	"crypto/rand"
	"fmt"
	mathRand "math/rand"
	"strings"
	"testing"

	"github.com/corestario/kyber"
	"github.com/corestario/kyber/group/edwards25519"
	"github.com/corestario/kyber/share"
	vss "github.com/corestario/kyber/share/vss/pedersen"
	"github.com/stretchr/testify/require"
)

var suite = edwards25519.NewBlakeSHA256Ed25519()

const defaultN = 5

var defaultT = vss.MinimumT(defaultN)

func generate(n, t int) (partPubs []kyber.Point, partSec []kyber.Scalar, dkgs []*DistKeyGenerator) {
	partPubs = make([]kyber.Point, n)
	partSec = make([]kyber.Scalar, n)
	for i := 0; i < n; i++ {
		sec, pub := genPair()
		partPubs[i] = pub
		partSec[i] = sec
	}
	dkgs = make([]*DistKeyGenerator, n)
	for i := 0; i < n; i++ {
		dkg, err := NewDistKeyGenerator(suite, partSec[i], partPubs, t)
		if err != nil {
			panic(err)
		}
		dkgs[i] = dkg
	}
	return
}

func TestDKGNewDistKeyGenerator(t *testing.T) {
	partPubs, partSec, _ := generate(defaultN, defaultT)

	long := partSec[0]
	dkg, err := NewDistKeyGenerator(suite, long, partPubs, defaultT)
	require.Nil(t, err)
	require.NotNil(t, dkg.Dealer)
	require.True(t, dkg.CanIssue)
	require.True(t, dkg.CanReceive)
	require.True(t, dkg.NewPresent)
	// because we set old = new
	require.True(t, dkg.OldPresent)
	require.True(t, dkg.CanReceive)
	require.False(t, dkg.IsResharing)

	sec, _ := genPair()
	_, err = NewDistKeyGenerator(suite, sec, partPubs, defaultT)
	require.Error(t, err)
}

func TestDKGDeal(t *testing.T) {
	_, _, dkgs := generate(defaultN, defaultT)
	dkg := dkgs[0]

	dks, err := dkg.DistKeyShare()
	require.Error(t, err)
	require.Nil(t, dks)

	deals, err := dkg.Deals()
	require.Nil(t, err)
	require.Len(t, deals, defaultN-1)

	for i := range deals {
		require.NotNil(t, deals[i])
		require.Equal(t, uint32(0), deals[i].Index)
	}

	v, ok := dkg.verifiersMap[uint32(dkg.Nidx)]
	require.True(t, ok)
	require.NotNil(t, v)
}

func TestDKGProcessDeal(t *testing.T) {
	_, _, dkgs := generate(defaultN, defaultT)
	dkg := dkgs[0]
	deals, err := dkg.Deals()
	require.Nil(t, err)

	rec := dkgs[1]
	deal := deals[1]
	require.Equal(t, int(deal.Index), 0)
	require.Equal(t, 1, rec.Nidx)

	// verifier don't find itself
	goodP := rec.C.NewNodes
	rec.C.NewNodes = make([]kyber.Point, 0)
	resp, err := rec.ProcessDeal(deal)
	require.Nil(t, resp)
	require.Error(t, err)
	rec.C.NewNodes = goodP

	// good deal
	resp, err = rec.ProcessDeal(deal)
	require.NotNil(t, resp)
	require.Equal(t, vss.StatusApproval, resp.Response.Status)
	require.Nil(t, err)
	_, ok := rec.verifiersMap[deal.Index]
	require.True(t, ok)
	require.Equal(t, uint32(0), resp.Index)

	// duplicate
	resp, err = rec.ProcessDeal(deal)
	require.Nil(t, resp)
	require.Error(t, err)

	// wrong index
	goodIdx := deal.Index
	deal.Index = uint32(defaultN + 1)
	resp, err = rec.ProcessDeal(deal)
	require.Nil(t, resp)
	require.Error(t, err)
	deal.Index = goodIdx

	// wrong deal
	goodSig := deal.Deal.Signature
	deal.Deal.Signature = randomBytes(len(deal.Deal.Signature))
	resp, err = rec.ProcessDeal(deal)
	require.Nil(t, resp)
	require.Error(t, err)
	deal.Deal.Signature = goodSig

}

func TestDKGProcessResponse(t *testing.T) {
	// first peer generates wrong deal
	// second peer processes it and returns a complaint
	// first peer process the complaint

	_, _, dkgs := generate(defaultN, defaultT)
	dkg := dkgs[0]
	idxRec := 1
	rec := dkgs[idxRec]
	deal, err := dkg.Dealer.PlaintextDeal(idxRec)
	require.Nil(t, err)

	// give a wrong deal
	goodSecret := deal.SecShare.V
	deal.SecShare.V = suite.Scalar().Zero()
	dd, err := dkg.Deals()
	encD := dd[idxRec]
	require.Nil(t, err)
	resp, err := rec.ProcessDeal(encD)
	require.Nil(t, err)
	require.NotNil(t, resp)
	require.Equal(t, vss.StatusComplaint, resp.Response.Status)
	deal.SecShare.V = goodSecret
	dd, _ = dkg.Deals()
	encD = dd[idxRec]

	// no verifier tied to Response
	v, ok := dkg.verifiersMap[0]
	require.NotNil(t, v)
	require.True(t, ok)
	require.NotNil(t, v)
	delete(dkg.verifiersMap, 0)
	j, err := dkg.ProcessResponse(resp)
	require.Nil(t, j)
	require.NotNil(t, err)
	dkg.verifiersMap[0] = v

	// invalid response
	goodSig := resp.Response.Signature
	resp.Response.Signature = randomBytes(len(goodSig))
	j, err = dkg.ProcessResponse(resp)
	require.Nil(t, j)
	require.Error(t, err)
	resp.Response.Signature = goodSig

	// valid complaint from our deal
	j, err = dkg.ProcessResponse(resp)
	require.NotNil(t, j)
	require.Nil(t, err)

	// valid complaint from another deal from another peer
	dkg2 := dkgs[2]
	require.Nil(t, err)
	// fake a wrong deal
	// deal20, err := dkg2.dealer.PlaintextDeal(0)
	// require.Nil(t, err)
	deal21, err := dkg2.Dealer.PlaintextDeal(1)
	require.Nil(t, err)
	goodRnd21 := deal21.SecShare.V
	deal21.SecShare.V = suite.Scalar().Zero()
	deals2, err := dkg2.Deals()
	require.Nil(t, err)

	resp12, err := rec.ProcessDeal(deals2[idxRec])
	require.NotNil(t, resp)
	require.Equal(t, vss.StatusComplaint, resp12.Response.Status)
	require.Equal(t, deals2[idxRec].Index, uint32(dkg2.Nidx))
	require.Equal(t, resp12.Index, uint32(dkg2.Nidx))
	require.Equal(t, vss.StatusComplaint, rec.verifiersMap[uint32(dkg2.Oidx)].Responses()[uint32(rec.Nidx)].Status)

	deal21.SecShare.V = goodRnd21
	deals2, err = dkg2.Deals()
	require.Nil(t, err)

	// give it to the first peer
	// process dealer 2's deal
	r, err := dkg.ProcessDeal(deals2[0])
	require.Nil(t, err)
	require.NotNil(t, r)

	// process response from peer 1
	j, err = dkg.ProcessResponse(resp12)
	require.Nil(t, j)
	require.Nil(t, err)

	// Justification part:
	// give the complaint to the dealer
	j, err = dkg2.ProcessResponse(resp12)
	require.Nil(t, err)
	require.NotNil(t, j)

	// hack because all is local, and resp has been modified locally by dkg2's
	// dealer, the status has became "justified"
	resp12.Response.Status = vss.StatusComplaint
	err = dkg.ProcessJustification(j)
	require.Nil(t, err)

	// remove verifiersMap
	v = dkg.verifiersMap[j.Index]
	delete(dkg.verifiersMap, j.Index)
	err = dkg.ProcessJustification(j)
	require.Error(t, err)
	dkg.verifiersMap[j.Index] = v

}

// Test Resharing to a group with one mode node BUT only a threshold of dealers
// are present during the resharing.
func TestDKGResharingThreshold(t *testing.T) {
	n := 7
	oldT := vss.MinimumT(n)
	publics, _, dkgs := generate(n, oldT)
	fullExchange(t, dkgs, true)

	newN := len(dkgs) + 1
	newT := vss.MinimumT(newN)
	shares := make([]*DistKeyShare, len(dkgs))
	sshares := make([]*share.PriShare, len(dkgs))
	for i, dkg := range dkgs {
		share, err := dkg.DistKeyShare()
		require.NoError(t, err)
		shares[i] = share
		sshares[i] = shares[i].Share
	}

	newPubs := make([]kyber.Point, newN)
	for i := range dkgs {
		newPubs[i] = dkgs[i].Pub
	}
	newPriv, newPub := genPair()
	newPubs[len(dkgs)] = newPub
	newDkgs := make([]*DistKeyGenerator, newN)
	var err error
	for i := range dkgs {
		c := &Config{
			Suite:        suite,
			Longterm:     dkgs[i].C.Longterm,
			OldNodes:     publics,
			NewNodes:     newPubs,
			Share:        shares[i],
			Threshold:    newT,
			OldThreshold: oldT,
		}
		newDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
	}
	newDkgs[len(dkgs)], err = NewDistKeyHandler(&Config{
		Suite:        suite,
		Longterm:     newPriv,
		OldNodes:     publics,
		NewNodes:     newPubs,
		PublicCoeffs: shares[0].Commits,
		Threshold:    newT,
		OldThreshold: oldT,
	})
	require.NoError(t, err)

	selectedDkgs := make([]*DistKeyGenerator, 0, newT)
	selected := make(map[string]bool)
	// add the new node
	selectedDkgs = append(selectedDkgs, newDkgs[len(dkgs)])
	selected[selectedDkgs[0].Long.String()] = true
	// select a subset of the new group
	for len(selected) < newT+1 {
		idx := mathRand.Intn(len(newDkgs))
		str := newDkgs[idx].Long.String()
		if selected[str] {
			continue
		}
		selected[str] = true
		selectedDkgs = append(selectedDkgs, newDkgs[idx])
	}

	deals := make([]map[int]*Deal, 0, newN*newN)
	for _, dkg := range selectedDkgs {
		if !dkg.OldPresent {
			continue
		}
		localDeals, err := dkg.Deals()
		require.NoError(t, err)
		deals = append(deals, localDeals)
	}

	resps := make(map[int][]*Response)
	for i, localDeals := range deals {
		for j, d := range localDeals {
			for _, dkg := range selectedDkgs {
				if dkg.NewPresent && dkg.Nidx == j {
					resp, err := dkg.ProcessDeal(d)
					require.Nil(t, err)
					require.Equal(t, vss.StatusApproval, resp.Response.Status)
					resps[i] = append(resps[i], resp)
				}
			}
		}
	}

	for _, dealResponses := range resps {
		for _, resp := range dealResponses {
			for _, dkg := range selectedDkgs {
				// Ignore messages from ourselves
				if resp.Response.Index == uint32(dkg.Nidx) {
					continue
				}
				j, err := dkg.ProcessResponse(resp)
				if err != nil {
					fmt.Printf("old dkg at (Oidx %d, Nidx %d) has received response from idx %d for dealer idx %d\n", dkg.Oidx, dkg.Nidx, resp.Response.Index, resp.Index)
				}
				require.Nil(t, err)
				require.Nil(t, j)
			}
		}
	}

	for _, dkg := range selectedDkgs {
		dkg.SetTimeout()
	}

	dkss := make([]*DistKeyShare, 0, len(selectedDkgs))
	newShares := make([]*share.PriShare, 0, len(selectedDkgs))
	for _, dkg := range selectedDkgs {
		if !dkg.NewPresent {
			continue
		}
		require.False(t, dkg.Certified())
		require.True(t, dkg.ThresholdCertified())
		dks, err := dkg.DistKeyShare()
		require.NoError(t, err)
		dkss = append(dkss, dks)
		newShares = append(newShares, dks.Share)
		qualShares := dkg.QualifiedShares()
		for _, dkg2 := range selectedDkgs {
			if !dkg.NewPresent {
				continue
			}
			require.Contains(t, qualShares, dkg2.Nidx)
		}
	}

	// check
	// 1. shares are different between the two rounds
	// 2. shares reconstruct to the same secret
	// 3. public polynomial is different but for the first coefficient /public
	// key/

	for _, newDks := range dkss {
		for _, oldDks := range shares {
			require.NotEqual(t, newDks.Share.V.String(), oldDks.Share.V.String())
		}
	}
	//// 2.
	oldSecret, err := share.RecoverSecret(suite, sshares, oldT, n)
	require.NoError(t, err)
	newSecret, err := share.RecoverSecret(suite, newShares, newT, newN)
	require.NoError(t, err)
	require.Equal(t, oldSecret.String(), newSecret.String())

}

// TestDKGThreshold tests the "threshold dkg" where only a subset of nodes succeed
// at the DKG
func TestDKGThreshold(t *testing.T) {
	n := 7
	// should succeed with only this number of nodes
	newTotal := vss.MinimumT(n)

	dkgs := make([]*DistKeyGenerator, n)
	privates := make([]kyber.Scalar, n)
	publics := make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		priv, pub := genPair()
		privates[i] = priv
		publics[i] = pub
	}

	for i := 0; i < n; i++ {
		dkg, err := NewDistKeyGenerator(suite, privates[i], publics, newTotal)
		if err != nil {
			panic(err)
		}
		dkgs[i] = dkg
	}

	// only take a threshold of them
	thrDKGs := make(map[uint32]*DistKeyGenerator)
	alreadyTaken := make(map[int]bool)
	for len(thrDKGs) < newTotal {
		idx := mathRand.Intn(defaultN)
		if alreadyTaken[idx] {
			continue
		}
		alreadyTaken[idx] = true
		dkg := dkgs[idx]
		thrDKGs[uint32(dkg.Nidx)] = dkg
	}

	// full secret sharing exchange
	// 1. broadcast deals
	resps := make([]*Response, 0, newTotal*newTotal)
	for _, dkg := range thrDKGs {
		deals, err := dkg.Deals()
		require.Nil(t, err)
		for i, d := range deals {
			// give the deal anyway - simpler
			recipient, exists := thrDKGs[uint32(i)]
			if !exists {
				// one of the "offline" dkg
				continue
			}
			resp, err := recipient.ProcessDeal(d)
			require.Nil(t, err)
			require.Equal(t, vss.StatusApproval, resp.Response.Status)
			resps = append(resps, resp)
		}
	}

	// 2. Broadcast responses
	for _, resp := range resps {
		for _, dkg := range thrDKGs {
			if resp.Response.Index == uint32(dkg.Nidx) {
				// skip the responses this dkg sent out
				continue
			}
			j, err := dkg.ProcessResponse(resp)
			require.Nil(t, err)
			require.Nil(t, j)
		}
	}

	// 3. make sure nobody has a QUAL set
	for _, dkg := range thrDKGs {
		require.False(t, dkg.Certified())
		require.Equal(t, 0, len(dkg.QUAL()))
		for _, dkg2 := range thrDKGs {
			require.False(t, dkg.isInQUAL(uint32(dkg2.Nidx)))
		}
	}

	for _, dkg := range thrDKGs {
		for i, v := range dkg.verifiersMap {
			var app int
			for _, r := range v.Responses() {
				if r.Status == vss.StatusApproval {
					app++
				}
			}
			if alreadyTaken[int(i)] {
				require.Equal(t, len(alreadyTaken), app)
			} else {
				require.Equal(t, 0, app)
			}
		}
		dkg.SetTimeout()
	}

	for _, dkg := range thrDKGs {
		require.Equal(t, newTotal, len(dkg.QUAL()))
		require.True(t, dkg.ThresholdCertified())
		require.False(t, dkg.Certified())
		qualShares := dkg.QualifiedShares()
		for _, dkg2 := range thrDKGs {
			require.Contains(t, qualShares, dkg2.Nidx)
		}
		_, err := dkg.DistKeyShare()
		require.NoError(t, err)
		for _, dkg2 := range thrDKGs {
			require.True(t, dkg.isInQUAL(uint32(dkg2.Nidx)))
		}
	}

}

func TestDistKeyShare(t *testing.T) {
	_, _, dkgs := generate(defaultN, defaultT)
	fullExchange(t, dkgs, true)

	for _, dkg := range dkgs {
		require.True(t, dkg.Certified())
	}
	// verify integrity of shares etc
	dkss := make([]*DistKeyShare, defaultN)
	var poly *share.PriPoly
	for i, dkg := range dkgs {
		dks, err := dkg.DistKeyShare()
		require.Nil(t, err)
		require.NotNil(t, dks)
		require.NotNil(t, dks.PrivatePoly)
		dkss[i] = dks
		require.Equal(t, dkg.Nidx, dks.Share.I)

		pripoly := share.CoefficientsToPriPoly(suite, dks.PrivatePoly)
		if poly == nil {
			poly = pripoly
			continue
		}
		poly, err = poly.Add(pripoly)
		require.NoError(t, err)
	}

	shares := make([]*share.PriShare, defaultN)
	for i, dks := range dkss {
		require.True(t, checkDks(dks, dkss[0]), "dist key share not equal %d vs %d", dks.Share.I, 0)
		shares[i] = dks.Share
	}

	secret, err := share.RecoverSecret(suite, shares, defaultN, defaultN)
	require.Nil(t, err)

	secretCoeffs := poly.Coefficients()
	require.Equal(t, secret.String(), secretCoeffs[0].String())

	commitSecret := suite.Point().Mul(secret, nil)
	require.Equal(t, dkss[0].Public().String(), commitSecret.String())
}

func genPair() (kyber.Scalar, kyber.Point) {
	sc := suite.Scalar().Pick(suite.RandomStream())
	return sc, suite.Point().Mul(sc, nil)
}

func randomBytes(n int) []byte {
	var buff = make([]byte, n)
	_, _ = rand.Read(buff[:])
	return buff
}
func checkDks(dks1, dks2 *DistKeyShare) bool {
	if len(dks1.Commits) != len(dks2.Commits) {
		return false
	}
	for i, p := range dks1.Commits {
		if !p.Equal(dks2.Commits[i]) {
			return false
		}
	}
	return true
}

func fullExchange(t *testing.T, dkgs []*DistKeyGenerator, checkQUAL bool) {
	// full secret sharing exchange
	// 1. broadcast deals
	n := len(dkgs)
	resps := make([]*Response, 0, n*n)
	for _, dkg := range dkgs {
		deals, err := dkg.Deals()
		require.Nil(t, err)
		for i, d := range deals {
			resp, err := dkgs[i].ProcessDeal(d)
			require.Nil(t, err)
			require.Equal(t, vss.StatusApproval, resp.Response.Status)
			resps = append(resps, resp)
		}
	}
	// 2. Broadcast responses
	for _, resp := range resps {
		for _, dkg := range dkgs {
			// Ignore messages about ourselves
			if resp.Response.Index == uint32(dkg.Nidx) {
				continue
			}
			j, err := dkg.ProcessResponse(resp)
			require.Nil(t, err)
			require.Nil(t, j)
		}
	}

	if checkQUAL {
		// 3. make sure everyone has the same QUAL set
		for _, dkg := range dkgs {
			for _, dkg2 := range dkgs {
				require.True(t, dkg.isInQUAL(uint32(dkg2.Nidx)))
			}
		}
	}
}

// Test resharing of a DKG to the same set of nodes
func TestDKGResharing(t *testing.T) {
	oldT := vss.MinimumT(defaultN)
	publics, secrets, dkgs := generate(defaultN, oldT)
	fullExchange(t, dkgs, true)

	shares := make([]*DistKeyShare, len(dkgs))
	sshares := make([]*share.PriShare, len(dkgs))
	for i, dkg := range dkgs {
		share, err := dkg.DistKeyShare()
		require.NoError(t, err)
		shares[i] = share
		sshares[i] = shares[i].Share
	}
	// start resharing within the same group
	newDkgs := make([]*DistKeyGenerator, len(dkgs))
	var err error
	for i := range dkgs {
		c := &Config{
			Suite:        suite,
			Longterm:     secrets[i],
			OldNodes:     publics,
			NewNodes:     publics,
			Share:        shares[i],
			OldThreshold: oldT,
		}
		newDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
	}
	fullExchange(t, newDkgs, true)
	newShares := make([]*DistKeyShare, len(dkgs))
	newSShares := make([]*share.PriShare, len(dkgs))
	for i := range newDkgs {
		dks, err := newDkgs[i].DistKeyShare()
		require.NoError(t, err)
		newShares[i] = dks
		newSShares[i] = newShares[i].Share
	}
	// check
	// 1. shares are different between the two rounds
	// 2. shares reconstruct to the same secret
	// 3. public polynomial is different but for the first coefficient /public
	// key/
	// 1.
	for i := 0; i < len(dkgs); i++ {
		require.False(t, shares[i].Share.V.Equal(newShares[i].Share.V))
	}
	thr := vss.MinimumT(defaultN)
	// 2.
	oldSecret, err := share.RecoverSecret(suite, sshares, thr, defaultN)
	require.NoError(t, err)
	newSecret, err := share.RecoverSecret(suite, newSShares, thr, defaultN)
	require.NoError(t, err)
	require.Equal(t, oldSecret.String(), newSecret.String())
}

// Test resharing functionality with one node less
func TestDKGResharingRemoveNode(t *testing.T) {
	oldT := vss.MinimumT(defaultN)
	publics, secrets, dkgs := generate(defaultN, oldT)
	fullExchange(t, dkgs, true)

	newN := len(publics) - 1
	shares := make([]*DistKeyShare, len(dkgs))
	sshares := make([]*share.PriShare, len(dkgs))
	for i, dkg := range dkgs {
		share, err := dkg.DistKeyShare()
		require.NoError(t, err)
		shares[i] = share
		sshares[i] = shares[i].Share
	}

	// start resharing within the same group
	newDkgs := make([]*DistKeyGenerator, len(dkgs))
	var err error
	for i := range dkgs {
		c := &Config{
			Suite:        suite,
			Longterm:     secrets[i],
			OldNodes:     publics,
			NewNodes:     publics[:newN],
			Share:        shares[i],
			OldThreshold: oldT,
		}
		newDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
	}

	fullExchange(t, newDkgs, false)
	newShares := make([]*DistKeyShare, len(dkgs))
	newSShares := make([]*share.PriShare, len(dkgs)-1)
	for i := range newDkgs[:newN] {
		dks, err := newDkgs[i].DistKeyShare()
		require.NoError(t, err)
		newShares[i] = dks
		newSShares[i] = newShares[i].Share
	}

	// check
	// 1. shares are different between the two rounds
	// 2. shares reconstruct to the same secret
	// 3. public polynomial is different but for the first coefficient /public
	// key/

	// 1.
	for i := 0; i < newN; i++ {
		require.False(t, shares[i].Share.V.Equal(newShares[i].Share.V))
	}
	thr := vss.MinimumT(defaultN)
	// 2.
	oldSecret, err := share.RecoverSecret(suite, sshares[:newN], thr, newN)
	require.NoError(t, err)
	newSecret, err := share.RecoverSecret(suite, newSShares, thr, newN)
	require.NoError(t, err)
	require.Equal(t, oldSecret.String(), newSecret.String())
}

// Test to reshare to a different set of nodes with only a threshold of the old
// nodes present
func TestDKGResharingNewNodesThreshold(t *testing.T) {
	oldN := defaultN
	oldT := vss.MinimumT(oldN)
	oldPubs, oldPrivs, dkgs := generate(oldN, oldT)
	fullExchange(t, dkgs, true)

	shares := make([]*DistKeyShare, len(dkgs))
	sshares := make([]*share.PriShare, len(dkgs))
	for i, dkg := range dkgs {
		share, err := dkg.DistKeyShare()
		require.NoError(t, err)
		shares[i] = share
		sshares[i] = shares[i].Share
	}
	// start resharing to a different group
	newN := oldN + 3
	newT := oldT + 2
	newPrivs := make([]kyber.Scalar, newN)
	newPubs := make([]kyber.Point, newN)
	for i := 0; i < newN; i++ {
		newPrivs[i], newPubs[i] = genPair()
	}

	// creating the old dkgs and new dkgs
	oldDkgs := make([]*DistKeyGenerator, oldN)
	newDkgs := make([]*DistKeyGenerator, newN)
	var err error
	for i := 0; i < oldN; i++ {
		c := &Config{
			Suite:        suite,
			Longterm:     oldPrivs[i],
			OldNodes:     oldPubs,
			NewNodes:     newPubs,
			Share:        shares[i],
			Threshold:    newT,
			OldThreshold: oldT,
		}
		oldDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
		require.False(t, oldDkgs[i].CanReceive)
		require.True(t, oldDkgs[i].CanIssue)
		require.True(t, oldDkgs[i].IsResharing)
		require.False(t, oldDkgs[i].NewPresent)
		require.Equal(t, oldDkgs[i].Oidx, i)
	}

	for i := 0; i < newN; i++ {
		c := &Config{
			Suite:        suite,
			Longterm:     newPrivs[i],
			OldNodes:     oldPubs,
			NewNodes:     newPubs,
			PublicCoeffs: shares[0].Commits,
			Threshold:    newT,
			OldThreshold: oldT,
		}
		newDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
		require.True(t, newDkgs[i].CanReceive)
		require.False(t, newDkgs[i].CanIssue)
		require.True(t, newDkgs[i].IsResharing)
		require.True(t, newDkgs[i].NewPresent)
		require.Equal(t, newDkgs[i].Nidx, i)
	}

	//alive := OldT - 1
	alive := oldT
	oldSelected := make([]*DistKeyGenerator, 0, alive)
	selected := make(map[string]bool)
	for len(selected) < alive {
		i := mathRand.Intn(len(oldDkgs))
		str := oldDkgs[i].Pub.String()
		if _, exists := selected[str]; exists {
			continue
		}
		selected[str] = true
		oldSelected = append(oldSelected, oldDkgs[i])
	}

	// 1. broadcast deals
	deals := make([]map[int]*Deal, 0, newN*newN)
	for _, dkg := range oldSelected {
		localDeals, err := dkg.Deals()
		require.Nil(t, err)
		deals = append(deals, localDeals)
	}

	resps := make(map[int][]*Response)
	for i, localDeals := range deals {
		for j, d := range localDeals {
			dkg := newDkgs[j]
			resp, err := dkg.ProcessDeal(d)
			require.Nil(t, err)
			require.Equal(t, vss.StatusApproval, resp.Response.Status)
			resps[i] = append(resps[i], resp)
		}
	}

	// 2. Broadcast responses
	for _, dealResponses := range resps {
		for _, resp := range dealResponses {
			// dispatch to old selected dkgs
			for _, dkg := range oldSelected {
				// Ignore messages from ourselves
				if resp.Response.Index == uint32(dkg.Nidx) {
					continue
				}
				j, err := dkg.ProcessResponse(resp)
				//fmt.Printf("old dkg %d process responses from new dkg %d about deal %d\n", dkg.Oidx, dkg.Nidx, resp.Index)
				if err != nil {
					fmt.Printf("old dkg at (Oidx %d, Nidx %d) has received response from idx %d for dealer idx %d\n", dkg.Oidx, dkg.Nidx, resp.Response.Index, resp.Index)
				}
				require.Nil(t, err)
				require.Nil(t, j)
			}
			// dispatch to the new dkgs
			for _, dkg := range newDkgs {
				// Ignore messages from ourselves
				if resp.Response.Index == uint32(dkg.Nidx) {
					continue
				}
				j, err := dkg.ProcessResponse(resp)
				//fmt.Printf("new dkg %d process responses from new dkg %d about deal %d\n", dkg.Nidx, dkg.Nidx, resp.Index)
				if err != nil {
					fmt.Printf("new dkg at Nidx %d has received response from idx %d for deal %d\n", dkg.Nidx, resp.Response.Index, resp.Index)
				}
				require.Nil(t, err)
				require.Nil(t, j)
			}

		}
	}

	for _, dkg := range newDkgs {
		for _, oldDkg := range oldSelected {
			idx := oldDkg.Oidx
			require.True(t, dkg.verifiersMap[uint32(idx)].DealCertified(), "new dkg %d has not certified deal %d => %v", dkg.Nidx, idx, dkg.verifiersMap[uint32(idx)].Responses())
		}
	}

	// 3. make sure everyone has the same QUAL set
	for _, dkg := range newDkgs {
		require.Equal(t, alive, len(dkg.QUAL()))
		for _, dkg2 := range oldSelected {
			require.True(t, dkg.isInQUAL(uint32(dkg2.Oidx)), "new dkg %d has not in qual old dkg %d (qual = %v)", dkg.Nidx, dkg2.Oidx, dkg.QUAL())
		}
	}

	newShares := make([]*DistKeyShare, newN)
	newSShares := make([]*share.PriShare, newN)
	for i := range newDkgs {
		dks, err := newDkgs[i].DistKeyShare()
		require.NoError(t, err)
		newShares[i] = dks
		newSShares[i] = newShares[i].Share
	}
	// check shares reconstruct to the same secret
	oldSecret, err := share.RecoverSecret(suite, sshares, oldT, oldN)
	require.NoError(t, err)
	newSecret, err := share.RecoverSecret(suite, newSShares, newT, newN)
	require.NoError(t, err)
	require.Equal(t, oldSecret.String(), newSecret.String())

}

// Test resharing to a different set of nodes with one common
func TestDKGResharingNewNodes(t *testing.T) {
	oldPubs, oldPrivs, dkgs := generate(defaultN, vss.MinimumT(defaultN))
	fullExchange(t, dkgs, true)

	shares := make([]*DistKeyShare, len(dkgs))
	sshares := make([]*share.PriShare, len(dkgs))
	for i, dkg := range dkgs {
		share, err := dkg.DistKeyShare()
		require.NoError(t, err)
		shares[i] = share
		sshares[i] = shares[i].Share
	}
	// start resharing to a different group
	oldN := defaultN
	oldT := len(shares[0].Commits)
	newN := oldN + 1
	newT := oldT + 1
	newPrivs := make([]kyber.Scalar, newN)
	newPubs := make([]kyber.Point, newN)
	newPrivs[0] = oldPrivs[oldN-1]
	newPubs[0] = oldPubs[oldN-1]
	for i := 1; i < newN; i++ {
		newPrivs[i], newPubs[i] = genPair()
	}

	// creating the old dkgs and new dkgs
	oldDkgs := make([]*DistKeyGenerator, oldN)
	newDkgs := make([]*DistKeyGenerator, newN)
	var err error
	for i := 0; i < oldN; i++ {
		c := &Config{
			Suite:        suite,
			Longterm:     oldPrivs[i],
			OldNodes:     oldPubs,
			NewNodes:     newPubs,
			Share:        shares[i],
			Threshold:    newT,
			OldThreshold: oldT,
		}
		oldDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
		if i == oldN-1 {
			require.True(t, oldDkgs[i].CanReceive)
			require.True(t, oldDkgs[i].CanIssue)
			require.True(t, oldDkgs[i].IsResharing)
			require.True(t, oldDkgs[i].NewPresent)
			require.Equal(t, oldDkgs[i].Oidx, i)
			require.Equal(t, 0, oldDkgs[i].Nidx)
			continue
		}
		require.False(t, oldDkgs[i].CanReceive)
		require.True(t, oldDkgs[i].CanIssue)
		require.True(t, oldDkgs[i].IsResharing)
		require.False(t, oldDkgs[i].NewPresent)
		require.Equal(t, oldDkgs[i].Oidx, i)
	}
	// the first one is the last old one
	newDkgs[0] = oldDkgs[oldN-1]
	for i := 1; i < newN; i++ {
		c := &Config{
			Suite:        suite,
			Longterm:     newPrivs[i],
			OldNodes:     oldPubs,
			NewNodes:     newPubs,
			PublicCoeffs: shares[0].Commits,
			Threshold:    newT,
			OldThreshold: oldT,
		}
		newDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
		require.True(t, newDkgs[i].CanReceive)
		require.False(t, newDkgs[i].CanIssue)
		require.True(t, newDkgs[i].IsResharing)
		require.True(t, newDkgs[i].NewPresent)
		require.Equal(t, newDkgs[i].Nidx, i)
	}

	// full secret sharing exchange
	// 1. broadcast deals
	deals := make([]map[int]*Deal, 0, newN*newN)
	for _, dkg := range oldDkgs {
		localDeals, err := dkg.Deals()
		require.Nil(t, err)
		deals = append(deals, localDeals)
		v, exists := dkg.verifiersMap[uint32(dkg.Oidx)]
		if dkg.CanReceive && dkg.Nidx == 0 {
			// this node should save its own response for its own deal
			lenResponses := len(v.Aggregator.Responses())
			require.Equal(t, 1, lenResponses)
		} else {
			// no verifiersMap since these dkg are not in in the new list
			require.False(t, exists)
		}
	}

	// the index key indicates the dealer index for which the responses are for
	resps := make(map[int][]*Response)
	for i, localDeals := range deals {
		for j, d := range localDeals {
			dkg := newDkgs[j]
			resp, err := dkg.ProcessDeal(d)
			require.Nil(t, err)
			require.Equal(t, vss.StatusApproval, resp.Response.Status)
			resps[i] = append(resps[i], resp)
		}
	}

	// all new dkgs should have the same length of verifiersMap map
	for _, dkg := range newDkgs {
		// one deal per old participants
		require.Equal(t, oldN, len(dkg.verifiersMap), "dkg Nidx %d failing", dkg.Nidx)
	}

	// 2. Broadcast responses
	for _, dealResponses := range resps {
		for _, resp := range dealResponses {
			for _, dkg := range oldDkgs {
				// Ignore messages from ourselves
				if resp.Response.Index == uint32(dkg.Nidx) {
					continue
				}
				j, err := dkg.ProcessResponse(resp)
				//fmt.Printf("old dkg %d process responses from new dkg %d about deal %d\n", dkg.Oidx, dkg.Nidx, resp.Index)
				if err != nil {
					fmt.Printf("old dkg at (Oidx %d, Nidx %d) has received response from idx %d for dealer idx %d\n", dkg.Oidx, dkg.Nidx, resp.Response.Index, resp.Index)
				}
				require.Nil(t, err)
				require.Nil(t, j)
			}

			for _, dkg := range newDkgs[1:] {
				// Ignore messages from ourselves
				if resp.Response.Index == uint32(dkg.Nidx) {
					continue
				}
				j, err := dkg.ProcessResponse(resp)
				//fmt.Printf("new dkg %d process responses from new dkg %d about deal %d\n", dkg.Nidx, dkg.Nidx, resp.Index)
				if err != nil {
					fmt.Printf("new dkg at Nidx %d has received response from idx %d for deal %d\n", dkg.Nidx, resp.Response.Index, resp.Index)
				}
				require.Nil(t, err)
				require.Nil(t, j)
			}

		}
	}

	for _, dkg := range newDkgs {
		for i := 0; i < oldN; i++ {
			require.True(t, dkg.verifiersMap[uint32(i)].DealCertified(), "new dkg %d has not certified deal %d => %v", dkg.Nidx, i, dkg.verifiersMap[uint32(i)].Responses())
		}
	}

	// 3. make sure everyone has the same QUAL set
	for _, dkg := range newDkgs {
		for _, dkg2 := range oldDkgs {
			require.True(t, dkg.isInQUAL(uint32(dkg2.Oidx)), "new dkg %d has not in qual old dkg %d (qual = %v)", dkg.Nidx, dkg2.Oidx, dkg.QUAL())
		}
	}

	newShares := make([]*DistKeyShare, newN)
	newSShares := make([]*share.PriShare, newN)
	for i := range newDkgs {
		dks, err := newDkgs[i].DistKeyShare()
		require.NoError(t, err)
		newShares[i] = dks
		newSShares[i] = newShares[i].Share
	}
	// check shares reconstruct to the same secret
	oldSecret, err := share.RecoverSecret(suite, sshares, oldT, oldN)
	require.NoError(t, err)
	newSecret, err := share.RecoverSecret(suite, newSShares, newT, newN)
	require.NoError(t, err)
	require.Equal(t, oldSecret.String(), newSecret.String())
}

func TestDKGResharingPartialNewNodes(t *testing.T) {
	oldPubs, oldPrivs, dkgs := generate(defaultN, vss.MinimumT(defaultN))
	fullExchange(t, dkgs, true)

	shares := make([]*DistKeyShare, len(dkgs))
	sshares := make([]*share.PriShare, len(dkgs))
	for i, dkg := range dkgs {
		share, err := dkg.DistKeyShare()
		require.NoError(t, err)
		shares[i] = share
		sshares[i] = shares[i].Share
	}
	// start resharing to a different group
	oldN := defaultN
	oldT := len(shares[0].Commits)
	newN := oldN + 1
	newT := oldT + 1
	total := oldN + 2
	newOffset := oldN - 1 // idx at which a new key is added to the group

	newPrivs := make([]kyber.Scalar, 0, newN)
	newPubs := make([]kyber.Point, 0, newN)
	for _, priv := range oldPrivs[1:] {
		newPrivs = append(newPrivs, priv)
	}
	for _, pub := range oldPubs[1:] {
		newPubs = append(newPubs, pub)
	}
	// add two new nodes
	priv1, pub1 := genPair()
	priv2, pub2 := genPair()
	newPrivs = append(newPrivs, []kyber.Scalar{priv1, priv2}...)
	newPubs = append(newPubs, []kyber.Point{pub1, pub2}...)

	// creating all dkgs
	totalDkgs := make([]*DistKeyGenerator, total)
	var err error
	for i := 0; i < oldN; i++ {
		c := &Config{
			Suite:        suite,
			Longterm:     oldPrivs[i],
			OldNodes:     oldPubs,
			NewNodes:     newPubs,
			Share:        shares[i],
			Threshold:    newT,
			OldThreshold: oldT,
		}
		totalDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
		if i >= 1 {
			require.True(t, totalDkgs[i].CanReceive)
			require.True(t, totalDkgs[i].CanIssue)
			require.True(t, totalDkgs[i].IsResharing)
			require.True(t, totalDkgs[i].NewPresent)
			require.Equal(t, totalDkgs[i].Oidx, i)
			require.Equal(t, i-1, totalDkgs[i].Nidx)
			continue
		}
		require.False(t, totalDkgs[i].CanReceive)
		require.True(t, totalDkgs[i].CanIssue)
		require.True(t, totalDkgs[i].IsResharing)
		require.False(t, totalDkgs[i].NewPresent)
		require.Equal(t, totalDkgs[i].Oidx, i)
	}
	// the first one is the last old one
	for i := oldN; i < total; i++ {
		newIdx := i - oldN + newOffset
		c := &Config{
			Suite:        suite,
			Longterm:     newPrivs[newIdx],
			OldNodes:     oldPubs,
			NewNodes:     newPubs,
			PublicCoeffs: shares[0].Commits,
			Threshold:    newT,
			OldThreshold: oldT,
		}
		totalDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
		require.True(t, totalDkgs[i].CanReceive)
		require.False(t, totalDkgs[i].CanIssue)
		require.True(t, totalDkgs[i].IsResharing)
		require.True(t, totalDkgs[i].NewPresent)
		require.Equal(t, totalDkgs[i].Nidx, newIdx)
	}
	newDkgs := totalDkgs[1:]
	oldDkgs := totalDkgs[:oldN]
	require.Equal(t, oldN, len(oldDkgs))
	require.Equal(t, newN, len(newDkgs))

	// full secret sharing exchange
	// 1. broadcast deals
	deals := make([]map[int]*Deal, 0, newN*newN)
	for _, dkg := range oldDkgs {
		localDeals, err := dkg.Deals()
		require.Nil(t, err)
		deals = append(deals, localDeals)
		v, exists := dkg.verifiersMap[uint32(dkg.Oidx)]
		if dkg.CanReceive && dkg.NewPresent {
			// this node should save its own response for its own deal
			lenResponses := len(v.Aggregator.Responses())
			require.True(t, exists)
			require.Equal(t, 1, lenResponses)
		} else {
			require.False(t, exists)
		}
	}

	// the index key indicates the dealer index for which the responses are for
	resps := make(map[int][]*Response)
	for i, localDeals := range deals {
		for j, d := range localDeals {
			dkg := newDkgs[j]
			resp, err := dkg.ProcessDeal(d)
			require.Nil(t, err)
			require.Equal(t, vss.StatusApproval, resp.Response.Status)
			resps[i] = append(resps[i], resp)
			if i == 0 {
				//fmt.Printf("dealer (Oidx %d, Nidx %d) processing deal to %d from %d\n", newDkgs[i].Oidx, newDkgs[i].Nidx, i, d.Index)
			}
		}
	}

	// all new dkgs should have the same length of verifiersMap map
	for _, dkg := range newDkgs {
		// one deal per old participants
		require.Equal(t, oldN, len(dkg.verifiersMap), "dkg Nidx %d failing", dkg.Nidx)
	}

	// 2. Broadcast responses
	for _, dealResponses := range resps {
		for _, resp := range dealResponses {
			for _, dkg := range totalDkgs {
				// Ignore messages from ourselves
				if dkg.CanReceive && resp.Response.Index == uint32(dkg.Nidx) {
					continue
				}
				j, err := dkg.ProcessResponse(resp)
				//fmt.Printf("old dkg %d process responses from new dkg %d about deal %d\n", dkg.Oidx, dkg.Nidx, resp.Index)
				if err != nil {
					fmt.Printf("old dkg at (Oidx %d, Nidx %d) has received response from idx %d for dealer idx %d\n", dkg.Oidx, dkg.Nidx, resp.Response.Index, resp.Index)
				}
				require.Nil(t, err)
				require.Nil(t, j)
			}
		}
	}
	for _, dkg := range newDkgs {
		for i := 0; i < oldN; i++ {
			require.True(t, dkg.verifiersMap[uint32(i)].DealCertified(), "new dkg %d has not certified deal %d => %v", dkg.Nidx, i, dkg.verifiersMap[uint32(i)].Responses())
		}
	}

	// 3. make sure everyone has the same QUAL set
	for _, dkg := range newDkgs {
		for _, dkg2 := range oldDkgs {
			require.True(t, dkg.isInQUAL(uint32(dkg2.Oidx)), "new dkg %d has not in qual old dkg %d (qual = %v)", dkg.Nidx, dkg2.Oidx, dkg.QUAL())
		}
	}

	newShares := make([]*DistKeyShare, newN)
	newSShares := make([]*share.PriShare, newN)
	for i := range newDkgs {
		dks, err := newDkgs[i].DistKeyShare()
		require.NoError(t, err)
		newShares[i] = dks
		newSShares[i] = newShares[i].Share
	}
	// check shares reconstruct to the same secret
	oldSecret, err := share.RecoverSecret(suite, sshares, oldT, oldN)
	require.NoError(t, err)
	newSecret, err := share.RecoverSecret(suite, newSShares, newT, newN)
	require.NoError(t, err)
	require.Equal(t, oldSecret.String(), newSecret.String())
}

func TestReaderMixedEntropy(t *testing.T) {
	seed := "some stream to be used with crypto/rand"
	partPubs, partSec, _ := generate(defaultN, defaultT)
	long := partSec[0]
	r := strings.NewReader(seed)
	c := &Config{
		Suite:     suite,
		Longterm:  long,
		NewNodes:  partPubs,
		Threshold: defaultT,
		Reader:    r,
	}
	dkg, err := NewDistKeyHandler(c)
	require.Nil(t, err)
	require.NotNil(t, dkg.Dealer)
}

func TestUserOnlyFlagTrueBehavior(t *testing.T) {
	seed := "String to test reproducibility with"
	partPubs, partSec, _ := generate(defaultN, defaultT)
	long := partSec[0]

	r1 := strings.NewReader(seed)
	c1 := &Config{
		Suite:          suite,
		Longterm:       long,
		NewNodes:       partPubs,
		Threshold:      defaultT,
		Reader:         r1,
		UserReaderOnly: true,
	}
	dkg1, err := NewDistKeyHandler(c1)
	require.Nil(t, err)
	require.NotNil(t, dkg1.Dealer)

	r2 := strings.NewReader(seed)
	c2 := &Config{
		Suite:          suite,
		Longterm:       long,
		NewNodes:       partPubs,
		Threshold:      defaultT,
		Reader:         r2,
		UserReaderOnly: true,
	}
	dkg2, err := NewDistKeyHandler(c2)
	require.Nil(t, err)
	require.NotNil(t, dkg2.Dealer)

	require.True(t, dkg1.Dealer.PrivatePoly().Secret().Equal(dkg2.Dealer.PrivatePoly().Secret()))
}

func TestUserOnlyFlagFalseBehavior(t *testing.T) {
	seed := "String to test reproducibility with"
	partPubs, partSec, _ := generate(defaultN, defaultT)
	long := partSec[0]

	r1 := strings.NewReader(seed)
	c1 := &Config{
		Suite:          suite,
		Longterm:       long,
		NewNodes:       partPubs,
		Threshold:      defaultT,
		Reader:         r1,
		UserReaderOnly: false,
	}
	dkg1, err := NewDistKeyHandler(c1)
	require.Nil(t, err)
	require.NotNil(t, dkg1.Dealer)

	r2 := strings.NewReader(seed)
	c2 := &Config{
		Suite:          suite,
		Longterm:       long,
		NewNodes:       partPubs,
		Threshold:      defaultT,
		Reader:         r2,
		UserReaderOnly: false,
	}
	dkg2, err := NewDistKeyHandler(c2)
	require.Nil(t, err)
	require.NotNil(t, dkg2.Dealer)

	require.False(t, dkg1.Dealer.PrivatePoly().Secret().Equal(dkg2.Dealer.PrivatePoly().Secret()))
}
