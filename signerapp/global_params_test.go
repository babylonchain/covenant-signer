package signerapp_test

import (
	"encoding/hex"
	"math"
	"math/rand"
	"testing"

	bbndatagen "github.com/babylonchain/babylon/testutil/datagen"

	"github.com/babylonchain/covenant-signer/signerapp"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/stretchr/testify/require"
)

var (
	initialCapMin, _ = btcutil.NewAmount(100)
	tag              = hex.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04})
	quorum           = 2
)

func generateInitParams(t *testing.T, r *rand.Rand) *signerapp.VersionedGlobalParams {
	var pks []string

	for i := 0; i < quorum+1; i++ {
		privkey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		pks = append(pks, hex.EncodeToString(privkey.PubKey().SerializeCompressed()))
	}

	gp := signerapp.VersionedGlobalParams{
		Version:          0,
		ActivationHeight: 0,
		StakingCap:       uint64(r.Int63n(int64(initialCapMin)) + int64(initialCapMin)),
		Tag:              tag,
		CovenantPks:      pks,
		CovenantQuorum:   uint64(quorum),
		UnbondingTime:    uint64(r.Int63n(100) + 100),
		UnbondingFee:     uint64(r.Int63n(100000) + 100000),
		MaxStakingAmount: uint64(r.Int63n(100000000) + 100000000),
		MinStakingAmount: uint64(r.Int63n(1000000) + 1000000),
		MaxStakingTime:   math.MaxUint16,
		MinStakingTime:   uint64(r.Int63n(10000) + 10000),
	}

	return &gp
}

func genValidGlobalParam(
	t *testing.T,
	r *rand.Rand,
	num uint32,
) *signerapp.GlobalParams {
	require.True(t, num > 0)

	initParams := generateInitParams(t, r)

	if num == 1 {
		return &signerapp.GlobalParams{
			Versions: []*signerapp.VersionedGlobalParams{initParams},
		}
	}

	var versions []*signerapp.VersionedGlobalParams
	versions = append(versions, initParams)

	for i := 1; i < int(num); i++ {
		prev := versions[i-1]
		next := generateInitParams(t, r)
		next.ActivationHeight = prev.ActivationHeight + uint64(r.Int63n(100)+100)
		next.Version = prev.Version + 1
		next.StakingCap = prev.StakingCap + uint64(r.Int63n(1000000000)+1)
		versions = append(versions, next)
	}

	return &signerapp.GlobalParams{
		Versions: versions,
	}
}

// PROPERTY: Every valid global params should be parsed successfully
func FuzzParseValidParams(f *testing.F) {
	bbndatagen.AddRandomSeedsToFuzzer(f, 10)
	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))
		numVersions := uint32(r.Int63n(50) + 10)
		globalParams := genValidGlobalParam(t, r, numVersions)
		parsedParams, err := signerapp.ParseGlobalParams(globalParams)
		require.NoError(t, err)
		require.NotNil(t, parsedParams)
		require.Len(t, parsedParams.Versions, int(numVersions))
		for i, p := range parsedParams.Versions {
			require.Equal(t, globalParams.Versions[i].Version, p.Version)
			require.Equal(t, globalParams.Versions[i].ActivationHeight, p.ActivationHeight)
			require.Equal(t, globalParams.Versions[i].StakingCap, uint64(p.StakingCap))
			require.Equal(t, globalParams.Versions[i].Tag, hex.EncodeToString(p.Tag))
			require.Equal(t, globalParams.Versions[i].CovenantQuorum, uint64(p.CovenantQuorum))
			require.Equal(t, globalParams.Versions[i].UnbondingTime, uint64(p.UnbondingTime))
			require.Equal(t, globalParams.Versions[i].UnbondingFee, uint64(p.UnbondingFee))
			require.Equal(t, globalParams.Versions[i].MaxStakingAmount, uint64(p.MaxStakingAmount))
			require.Equal(t, globalParams.Versions[i].MinStakingAmount, uint64(p.MinStakingAmount))
			require.Equal(t, globalParams.Versions[i].MaxStakingTime, uint64(p.MaxStakingTime))
			require.Equal(t, globalParams.Versions[i].MinStakingTime, uint64(p.MinStakingTime))
		}
	})
}

