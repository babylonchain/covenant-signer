//go:build e2e
// +build e2e

package e2etest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/babylonchain/babylon/btcstaking"
	staking "github.com/babylonchain/babylon/btcstaking"

	"github.com/babylonchain/covenant-signer/btcclient"
	"github.com/babylonchain/covenant-signer/config"
	"github.com/babylonchain/covenant-signer/itest/containers"
	"github.com/babylonchain/covenant-signer/logger"
	"github.com/babylonchain/covenant-signer/signerapp"
	"github.com/babylonchain/covenant-signer/signerservice"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

var (
	netParams              = &chaincfg.RegressionNetParams
	eventuallyPollInterval = 100 * time.Millisecond
	eventuallyTimeout      = 10 * time.Second
)

type TestManager struct {
	t                   *testing.T
	bitcoindHandler     *BitcoindTestHandler
	walletPass          string
	btcClient           *btcclient.BtcClient
	localCovenantPubKey *btcec.PublicKey
	allCovenantKeys     []*btcec.PublicKey
	covenantQuorum      uint32
	finalityProviderKey *btcec.PrivateKey
	stakerAddress       btcutil.Address
	stakerPubKey        *btcec.PublicKey
	magicBytes          []byte
	signerConfig        *config.Config
	app                 *signerapp.SignerApp
	server              *signerservice.SigningServer
}

type stakingData struct {
	stakingAmount  btcutil.Amount
	stakingTime    uint16
	stakingFeeRate btcutil.Amount
	unbondingTime  uint16
	unbondingFee   btcutil.Amount
}

func defaultStakingData() *stakingData {
	return &stakingData{
		stakingAmount:  btcutil.Amount(100000),
		stakingTime:    10000,
		stakingFeeRate: btcutil.Amount(5000), //feeRatePerKb
		unbondingTime:  100,
		unbondingFee:   btcutil.Amount(10000),
	}
}

func (d *stakingData) unbondingAmount() btcutil.Amount {
	return d.stakingAmount - d.unbondingFee
}

func getNewPubKeyInWallet(t *testing.T, c *btcclient.BtcClient, name string) *btcec.PublicKey {
	addr, err := c.RpcClient.GetNewAddress(name)
	require.NoError(t, err)
	info, err := c.RpcClient.GetAddressInfo(addr.EncodeAddress())
	require.NoError(t, err)
	pubKeyBytes, err := hex.DecodeString(*info.PubKey)
	require.NoError(t, err)
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	require.NoError(t, err)
	return pubKey
}

func StartManager(
	t *testing.T,
	numMatureOutputsInWallet uint32) *TestManager {
	logger := logger.DefaultLogger()
	m, err := containers.NewManager()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = m.ClearResources()
	})

	h := NewBitcoindHandler(t, m)
	h.Start()

	// Give some time to launch and bitcoind
	time.Sleep(2 * time.Second)

	passphrase := "pass"
	_ = h.CreateWallet("test-wallet", passphrase)
	// only outputs which are 100 deep are mature
	_ = h.GenerateBlocks(int(numMatureOutputsInWallet) + 100)

	appConfig := config.DefaultConfig()
	appConfig.BtcNodeConfig.Host = "127.0.0.1:18443"
	appConfig.BtcNodeConfig.User = "user"
	appConfig.BtcNodeConfig.Pass = "pass"
	appConfig.BtcNodeConfig.Network = netParams.Name

	fakeParsedConfig, err := appConfig.Parse()
	require.NoError(t, err)
	// Client for testing purposes
	client, err := btcclient.NewBtcClient(fakeParsedConfig.BtcNodeConfig)
	require.NoError(t, err)

	outputs, err := client.ListOutputs(true)
	require.NoError(t, err)
	require.Len(t, outputs, int(numMatureOutputsInWallet))

	// easiest way to get address controlled by wallet is to retrive address from one
	// of the outputs
	output := outputs[0]
	walletAddress, err := btcutil.DecodeAddress(output.Address, netParams)
	require.NoError(t, err)

	// Unlock wallet for all tests 60min
	err = client.UnlockWallet(60*60*60, passphrase)
	require.NoError(t, err)

	stakerPubKeyInfo, err := client.RpcClient.GetAddressInfo(walletAddress.EncodeAddress())
	require.NoError(t, err)
	stakerPubKeyBytes, err := hex.DecodeString(*stakerPubKeyInfo.PubKey)
	require.NoError(t, err)
	stakerPubKey, err := btcec.ParsePubKey(stakerPubKeyBytes)
	require.NoError(t, err)
	fpKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	covAddress, err := client.RpcClient.GetNewAddress("covenant")
	require.NoError(t, err)
	info, err := client.RpcClient.GetAddressInfo(covAddress.EncodeAddress())
	require.NoError(t, err)
	covenantPubKeyBytes, err := hex.DecodeString(*info.PubKey)
	require.NoError(t, err)
	localCovenantKey, err := btcec.ParsePubKey(covenantPubKeyBytes)
	require.NoError(t, err)

	remoteCovenantKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	mb := []byte{0x0, 0x1, 0x2, 0x3}
	appConfig.Server.Host = "127.0.0.1"
	appConfig.Server.Port = 10090
	appConfig.Params.CovenantQuorum = 1
	appConfig.Params.MagicBytes = hex.EncodeToString(mb)
	appConfig.Params.W = 1
	appConfig.Params.CovenantPublicKeys = []string{
		hex.EncodeToString(localCovenantKey.SerializeCompressed()),
		hex.EncodeToString(remoteCovenantKey.PubKey().SerializeCompressed()),
	}

	parsedconfig, err := appConfig.Parse()
	require.NoError(t, err)

	// In e2e test we are using the same node for signing as for indexing funcitonalities
	chainInfo := signerapp.NewBitcoindChainInfo(client)
	signer := signerapp.NewPsbtSigner(client)
	paramsGetter := signerapp.NewConfigParamsRetriever(parsedconfig.ParamsConfig)

	app := signerapp.NewSignerApp(
		logger,
		signer,
		chainInfo,
		paramsGetter,
		netParams,
	)

	server, err := signerservice.New(
		context.Background(),
		logger,
		parsedconfig,
		app,
	)

	require.NoError(t, err)

	go func() {
		_ = server.Start()
	}()

	// Give some time to launch server
	time.Sleep(3 * time.Second)

	t.Cleanup(func() {
		_ = server.Stop(context.TODO())
	})

	return &TestManager{
		t:                   t,
		bitcoindHandler:     h,
		walletPass:          passphrase,
		btcClient:           client,
		localCovenantPubKey: localCovenantKey,
		allCovenantKeys:     parsedconfig.ParamsConfig.CovenantPublicKeys,
		covenantQuorum:      appConfig.Params.CovenantQuorum,
		finalityProviderKey: fpKey,
		stakerAddress:       walletAddress,
		stakerPubKey:        stakerPubKey,
		magicBytes:          mb,
		signerConfig:        appConfig,
		app:                 app,
		server:              server,
	}
}

func (tm *TestManager) covenantPubKeys() []*btcec.PublicKey {
	return tm.allCovenantKeys
}

func (tm *TestManager) SigningServerUrl() string {
	return fmt.Sprintf("http://%s:%d", tm.signerConfig.Server.Host, tm.signerConfig.Server.Port)
}

type stakingTxSigInfo struct {
	stakingTxHash *chainhash.Hash
	stakingOutput *wire.TxOut
	stakingInfo   *btcstaking.IdentifiableStakingInfo
}

func (tm *TestManager) sendStakingTxToBtc(d *stakingData) *stakingTxSigInfo {
	info, err := staking.BuildV0IdentifiableStakingOutputs(
		tm.magicBytes,
		tm.stakerPubKey,
		tm.finalityProviderKey.PubKey(),
		tm.covenantPubKeys(),
		tm.covenantQuorum,
		d.stakingTime,
		d.stakingAmount,
		netParams,
	)
	require.NoError(tm.t, err)

	// staking output will always have index 0
	tx, err := tm.btcClient.CreateAndSignTx(
		[]*wire.TxOut{info.StakingOutput, info.OpReturnOutput},
		d.stakingFeeRate,
		tm.stakerAddress,
	)
	require.NoError(tm.t, err)

	hash, err := tm.btcClient.SendTx(tx)
	require.NoError(tm.t, err)
	// generate blocks to make sure tx will be included into chain
	_ = tm.bitcoindHandler.GenerateBlocks(2)
	return &stakingTxSigInfo{
		stakingTxHash: hash,
		stakingOutput: info.StakingOutput,
		stakingInfo:   info,
	}
}

type unbondingTxWithMetadata struct {
	unbondingTx *wire.MsgTx
}

func (tm *TestManager) createUnbondingTx(
	si *stakingTxSigInfo,
	d *stakingData,
) *unbondingTxWithMetadata {

	unbondingInfo, err := staking.BuildUnbondingInfo(
		tm.stakerPubKey,
		[]*btcec.PublicKey{tm.finalityProviderKey.PubKey()},
		tm.covenantPubKeys(),
		tm.covenantQuorum,
		d.unbondingTime,
		d.unbondingAmount(),
		netParams,
	)
	require.NoError(tm.t, err)
	unbondingTx := wire.NewMsgTx(2)
	unbondingTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(si.stakingTxHash, 0), nil, nil))
	unbondingTx.AddTxOut(unbondingInfo.UnbondingOutput)

	return &unbondingTxWithMetadata{
		unbondingTx: unbondingTx,
	}
}

func (tm *TestManager) createNUnbondingTransactions(n int, d *stakingData) ([]*unbondingTxWithMetadata, []*wire.MsgTx) {
	var infos []*stakingTxSigInfo
	var sendStakingTransactions []*wire.MsgTx

	for i := 0; i < n; i++ {
		sInfo := tm.sendStakingTxToBtc(d)
		conf, status, err := tm.btcClient.TxDetails(sInfo.stakingTxHash, sInfo.stakingOutput.PkScript)
		require.NoError(tm.t, err)
		require.Equal(tm.t, btcclient.TxInChain, status)
		infos = append(infos, sInfo)
		sendStakingTransactions = append(sendStakingTransactions, conf.Tx)
	}

	var unbondingTxs []*unbondingTxWithMetadata
	for _, i := range infos {
		info := i
		ubs := tm.createUnbondingTx(
			info,
			d,
		)
		unbondingTxs = append(unbondingTxs, ubs)
	}

	return unbondingTxs, sendStakingTransactions
}

func ATestSigningUnbondingTx(t *testing.T) {
	tm := StartManager(t, 100)

	stakingData := defaultStakingData()

	stakingTxInfo := tm.sendStakingTxToBtc(stakingData)

	unb := tm.createUnbondingTx(stakingTxInfo, stakingData)

	sig, err := signerservice.RequestCovenantSignaure(
		context.Background(),
		tm.SigningServerUrl(),
		10*time.Second,
		unb.unbondingTx,
		tm.localCovenantPubKey,
		stakingTxInfo.stakingOutput.PkScript,
	)

	require.NoError(t, err)
	require.NotNil(t, sig)

	unbondingPathInfo, err := stakingTxInfo.stakingInfo.UnbondingPathSpendInfo()
	require.NoError(t, err)

	// check if signature provided by covenant signer is valid signature over unbonding
	// path
	err = btcstaking.VerifyTransactionSigWithOutput(
		unb.unbondingTx,
		stakingTxInfo.stakingOutput,
		unbondingPathInfo.GetPkScriptPath(),
		tm.localCovenantPubKey,
		sig.Serialize(),
	)
	require.NoError(t, err)
}

func TestDebugPsbtSigning(t *testing.T) {
	// Setup bitcoind
	m, err := containers.NewManager()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = m.ClearResources()
	})

	h := NewBitcoindHandler(t, m)
	h.Start()

	// Setup Wallet
	passphrase := "pass"
	_ = h.CreateWallet("test-wallet", passphrase)
	// only outputs which are 100 deep are mature
	_ = h.GenerateBlocks(int(100) + 100)

	appConfig := config.DefaultConfig()
	appConfig.BtcNodeConfig.Host = "127.0.0.1:18443"
	appConfig.BtcNodeConfig.User = "user"
	appConfig.BtcNodeConfig.Pass = "pass"
	appConfig.BtcNodeConfig.Network = netParams.Name

	fakeParsedConfig, err := appConfig.Parse()
	require.NoError(t, err)
	// Client for testing purposes
	client, err := btcclient.NewBtcClient(fakeParsedConfig.BtcNodeConfig)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Unlock wallet for whole tests
	err = client.UnlockWallet(60*60*60, passphrase)
	require.NoError(t, err)

	// prepare all parameters outside of covenant wallet
	stakerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	require.NotNil(t, stakerKey)

	fpKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	require.NotNil(t, fpKey)

	stakingAmount := btcutil.Amount(100000)
	stakingTime := uint16(10000)

	localCovenantMemberPubKey := getNewPubKeyInWallet(t, client, "covenant")

	remoteCovenantKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	require.NotNil(t, remoteCovenantKey)

	covenantKeys := []*btcec.PublicKey{
		localCovenantMemberPubKey,
		// TODO: Figure out how enable signing with multiple covenant members through
		// psbt's
		// remoteCovenantKey.PubKey(),
	}

	stakingInfo, err := btcstaking.BuildStakingInfo(
		stakerKey.PubKey(),
		[]*btcec.PublicKey{fpKey.PubKey()},
		covenantKeys,
		1,
		stakingTime,
		stakingAmount,
		netParams,
	)
	require.NoError(t, err)
	require.NotNil(t, stakingInfo)

	stakingTransaction := wire.NewMsgTx(2)
	fakeHashBytes := sha256.Sum256([]byte{1})
	fakeHash, err := chainhash.NewHash(fakeHashBytes[:])
	require.NoError(t, err)

	fakeInput := wire.NewOutPoint(fakeHash, 0)
	stakingTransaction.AddTxIn(wire.NewTxIn(fakeInput, nil, nil))
	stakingTransaction.AddTxOut(stakingInfo.StakingOutput)
	stakingTxHash := stakingTransaction.TxHash()

	stakingPathInfo, err := stakingInfo.TimeLockPathSpendInfo()
	require.NoError(t, err)
	require.NotNil(t, stakingPathInfo)
	stakingPathControlBytes, err := stakingPathInfo.ControlBlock.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, stakingPathControlBytes)

	unbondingPathInfo, err := stakingInfo.UnbondingPathSpendInfo()
	require.NoError(t, err)
	unbondingPathCtrlBlockBytes, err := unbondingPathInfo.ControlBlock.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, unbondingPathCtrlBlockBytes)
	unbondingPathLeafHash := unbondingPathInfo.RevealedLeaf.TapHash()

	slashingPathInfo, err := stakingInfo.SlashingPathSpendInfo()
	require.NoError(t, err)
	require.NotNil(t, slashingPathInfo)
	slashingPathLeafHash := slashingPathInfo.RevealedLeaf.TapHash()
	slashingPathControlBytes, err := slashingPathInfo.ControlBlock.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, slashingPathControlBytes)

	tree := txscript.AssembleTaprootScriptTree(
		stakingPathInfo.RevealedLeaf,
		unbondingPathInfo.RevealedLeaf,
		slashingPathInfo.RevealedLeaf,
	)
	require.NotNil(t, tree)
	treeRootNode := tree.RootNode.TapHash()
	// client.RpcClient.GetDescriptorInfo()
	unbondingInfo, err := btcstaking.BuildUnbondingInfo(
		stakerKey.PubKey(),
		[]*btcec.PublicKey{fpKey.PubKey()},
		covenantKeys,
		1,
		100,
		stakingAmount-2000,
		netParams,
	)
	require.NoError(t, err)
	require.NotNil(t, unbondingInfo)

	rawUnbondingTx := wire.NewMsgTx(2)
	rawUnbondingTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&stakingTxHash, 0), nil, nil))
	rawUnbondingTx.AddTxOut(unbondingInfo.UnbondingOutput)

	// build unbonding transactions via psbt packet
	psbtPacket, err := psbt.New(
		[]*wire.OutPoint{wire.NewOutPoint(&stakingTxHash, 0)},
		[]*wire.TxOut{unbondingInfo.UnbondingOutput},
		2,
		0,
		[]uint32{0},
	)
	require.NoError(t, err)
	require.NotNil(t, psbtPacket)

	// Fill data for signign as covenant member
	psbtPacket.Inputs[0].SighashType = txscript.SigHashDefault
	psbtPacket.Inputs[0].WitnessUtxo = stakingInfo.StakingOutput
	psbtPacket.Inputs[0].WitnessScript = unbondingPathInfo.RevealedLeaf.Script
	psbtPacket.Inputs[0].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
		{
			XOnlyPubKey: schnorr.SerializePubKey(localCovenantMemberPubKey),
			LeafHashes: [][]byte{
				unbondingPathLeafHash.CloneBytes(),
				slashingPathLeafHash.CloneBytes(),
			},
		},
		{
			XOnlyPubKey: schnorr.SerializePubKey(remoteCovenantKey.PubKey()),
			LeafHashes: [][]byte{
				unbondingPathLeafHash.CloneBytes(),
				slashingPathLeafHash.CloneBytes(),
			},
		},
	}
	psbtPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: unbondingPathCtrlBlockBytes,
			Script:       unbondingPathInfo.RevealedLeaf.Script,
			LeafVersion:  unbondingPathInfo.RevealedLeaf.LeafVersion,
		},
	}

	psbtPacket.Inputs[0].TaprootMerkleRoot = treeRootNode.CloneBytes()
	psbtPacket.Inputs[0].TaprootInternalKey = schnorr.SerializePubKey(unbondingPathInfo.ControlBlock.InternalKey)

	signedPacket, err := client.SignPsbt(psbtPacket)
	require.NoError(t, err)
	require.NotNil(t, signedPacket)

	schnorrSigs := signedPacket.Inputs[0].TaprootScriptSpendSig
	require.Len(t, schnorrSigs, 1)

	covenantMemberSchnorrSig, err := schnorr.ParseSignature(schnorrSigs[0].Signature)
	require.NoError(t, err)
	require.NotNil(t, covenantMemberSchnorrSig)

	err = btcstaking.VerifyTransactionSigWithOutput(
		psbtPacket.UnsignedTx,
		stakingInfo.StakingOutput,
		unbondingPathInfo.RevealedLeaf.Script,
		localCovenantMemberPubKey,
		covenantMemberSchnorrSig.Serialize(),
	)
	require.NoError(t, err)
}
