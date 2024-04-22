package config

import (
	"encoding/hex"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
)

type ParamsConfig struct {
	CovenantPublicKeys []string `mapstructure:"covenant_public_keys"`
	CovenantQuorum     uint32   `mapstructure:"covenant_quorum"`
	MagicBytes         string   `mapstructure:"magic_bytes"`
	W                  uint32   `mapstructure:"w"`
	UnbondingTime      uint32   `mapstructure:"unbonding_time"`
	UnbondingFee       uint32   `mapstructure:"unbonding_fee"`
}

type ParsedParamsConfig struct {
	CovenantPublicKeys []*btcec.PublicKey
	CovenantQuorum     uint32
	MagicBytes         []byte
	W                  uint32
	UnbondingTime      uint16
	UnbondingFee       btcutil.Amount
}

func (c *ParamsConfig) Parse() (*ParsedParamsConfig, error) {
	var covenantPublicKeys []*btcec.PublicKey

	for _, key := range c.CovenantPublicKeys {
		decodedBytes, err := hex.DecodeString(key)

		if err != nil {
			return nil, err
		}

		pk, err := btcec.ParsePubKey(decodedBytes)
		if err != nil {
			return nil, err
		}
		covenantPublicKeys = append(covenantPublicKeys, pk)
	}

	magicBytes, err := hex.DecodeString(c.MagicBytes)

	if err != nil {
		return nil, err
	}

	if len(magicBytes) != 4 {
		return nil, fmt.Errorf("invalid magic bytes length. Magic bytes should be 4 bytes long")
	}

	if c.UnbondingTime > math.MaxUint16 {
		return nil, fmt.Errorf("invalid unbonding time. Unbonding time should be less than 65535")
	}

	return &ParsedParamsConfig{
		CovenantPublicKeys: covenantPublicKeys,
		CovenantQuorum:     c.CovenantQuorum,
		MagicBytes:         magicBytes,
		W:                  c.W,
		UnbondingTime:      uint16(c.UnbondingTime),
		UnbondingFee:       btcutil.Amount(c.UnbondingFee),
	}, nil
}

func DefaultParamsConfig() *ParamsConfig {
	return &ParamsConfig{
		CovenantPublicKeys: []string{},
		CovenantQuorum:     0,
		MagicBytes:         "01020304",
		W:                  100,
		UnbondingTime:      100,
		UnbondingFee:       10000,
	}
}
