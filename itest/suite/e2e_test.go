//go:build e2e
// +build e2e

package suite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	"github.com/btcsuite/btcd/btcjson"
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

const (
	// Point with unknown discrete logarithm defined in: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
	// using it as internal public key effectively disables taproot key spends
	unspendableKeyPath = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)

var (
	unspendableKeyPathKey = unspendableKeyPathInternalPubKeyInternal(unspendableKeyPath)
)

func unspendableKeyPathInternalPubKeyInternal(keyHex string) btcec.PublicKey {
	keyBytes, err := hex.DecodeString(keyHex)

	if err != nil {
		panic(fmt.Sprintf("unexpected error: %v", err))
	}

	// We are using btcec here, as key is 33 byte compressed format.
	pubKey, err := btcec.ParsePubKey(keyBytes)

	if err != nil {
		panic(fmt.Sprintf("unexpected error: %v", err))
	}
	return *pubKey
}

func unspendableKeyPathInternalPubKey() btcec.PublicKey {
	return unspendableKeyPathKey
}

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

func getNewPubKeyInWallet(t *testing.T, c *btcclient.BtcClient, name string) (*btcec.PublicKey, btcutil.Address, uint32) {
	addr, err := c.RpcClient.GetNewAddress(name)
	require.NoError(t, err)
	info, err := c.RpcClient.GetAddressInfo(addr.EncodeAddress())
	require.NoError(t, err)
	fmt.Println("address descriptor")
	fmt.Println(*info.Descriptor)
	fmt.Println("master finger")
	fmt.Println(*info.HDMasterFingerprint)
	pubKeyBytes, err := hex.DecodeString(*info.PubKey)
	require.NoError(t, err)
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	require.NoError(t, err)
	return pubKey, addr, keyFingerPrint(t, *info.HDMasterFingerprint)
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

type Descriptor struct {
	Desc      string `json:"desc"`
	Timestamp string `json:"timestamp"`
}

type ImportDescriptorsCmd struct {
	Descriptors []Descriptor
}

// (*CreateRawTransactionCmd)(nil)
func init() {
	btcjson.MustRegisterCmd("importdescriptors", (*ImportDescriptorsCmd)(nil), btcjson.UsageFlag(0))
}

func ImportDescriptors(c *btcclient.BtcClient, descriptor string) ([]byte, error) {

	descriptorObj := []Descriptor{
		{
			Desc:      descriptor,
			Timestamp: "now",
		},
	}

	bytes, err := json.Marshal(descriptorObj)

	if err != nil {
		return nil, err
	}

	return c.RpcClient.RawRequest("importdescriptors", []json.RawMessage{bytes})
}

func buildPathsInfo(t *testing.T, s *btcstaking.StakingInfo) (*btcstaking.SpendInfo, *btcstaking.SpendInfo, *btcstaking.SpendInfo) {
	stakingPathInfo, err := s.TimeLockPathSpendInfo()
	require.NoError(t, err)
	unbondingPathInfo, err := s.UnbondingPathSpendInfo()
	require.NoError(t, err)
	slashingPathInfo, err := s.SlashingPathSpendInfo()
	require.NoError(t, err)
	return stakingPathInfo, unbondingPathInfo, slashingPathInfo
}

func builldFakeStakingTx(t *testing.T, s *btcstaking.StakingInfo) *wire.MsgTx {
	stakingTransaction := wire.NewMsgTx(2)
	fakeHashBytes := sha256.Sum256([]byte{1})
	fakeHash, err := chainhash.NewHash(fakeHashBytes[:])
	require.NoError(t, err)

	fakeInput := wire.NewOutPoint(fakeHash, 0)
	stakingTransaction.AddTxIn(wire.NewTxIn(fakeInput, nil, nil))
	stakingTransaction.AddTxOut(s.StakingOutput)
	return stakingTransaction
}

func mustGetControlBlockBytes(t *testing.T, s *btcstaking.SpendInfo) []byte {
	controlBlockBytes, err := s.ControlBlock.ToBytes()
	require.NoError(t, err)
	return controlBlockBytes
}

func mustGetLeafHash(t *testing.T, s *btcstaking.SpendInfo) []byte {
	tap := s.RevealedLeaf.TapHash()
	return tap.CloneBytes()
}

func keyFingerPrint(t *testing.T, stringBytes string) uint32 {
	decoded, err := hex.DecodeString(stringBytes)
	require.NoError(t, err)

	return binary.LittleEndian.Uint32(decoded)
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
	_ = h.GenerateBlocks(int(100) + 100)

	// _ = h.CreateWallet("covenant-wallet", "foo")

	// prepare all staking  parameters outside of covenant wallet
	// ***************************************

	stakerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	require.NotNil(t, stakerKey)

	fpKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	require.NotNil(t, fpKey)

	remoteCovenantKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	require.NotNil(t, remoteCovenantKey)

	stakingAmount := btcutil.Amount(100000)
	stakingTime := uint16(10000)

	// ***************************************

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

	localCovenantMemberPubKey, localCovenantAddress, fingerPrint := getNewPubKeyInWallet(t, client, "covenant")
	covPkScript, err := txscript.PayToAddrScript(localCovenantAddress)
	require.NoError(t, err)
	require.NotNil(t, covPkScript)
	require.NotNil(t, &fingerPrint)

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

	stakingTransaction := builldFakeStakingTx(t, stakingInfo)
	stakingTxHash := stakingTransaction.TxHash()
	stakingPathInfo, unbondingPathInfo, slashingPathInfo := buildPathsInfo(t, stakingInfo)
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

	paytToCovenantOutpout := wire.NewTxOut(int64(stakingAmount-2000), covPkScript)
	require.NotNil(t, paytToCovenantOutpout)

	psbtPacket, err := psbt.New(
		[]*wire.OutPoint{wire.NewOutPoint(&stakingTxHash, 0)},
		[]*wire.TxOut{paytToCovenantOutpout},
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
		// {
		// 	XOnlyPubKey: schnorr.SerializePubKey(stakerKey.PubKey()),
		// 	LeafHashes: [][]byte{
		// 		mustGetLeafHash(t, unbondingPathInfo),
		// 		// mustGetLeafHash(t, slashingPathInfo),
		// 	},
		// },
		{
			XOnlyPubKey: schnorr.SerializePubKey(localCovenantMemberPubKey),
			// LeafHashes: [][]byte{
			// 	mustGetLeafHash(t, unbondingPathInfo),
			// 	mustGetLeafHash(t, slashingPathInfo),
			// },
			// MasterKeyFingerprint: fingerPrint,
		},
		// {
		// 	XOnlyPubKey: schnorr.SerializePubKey(remoteCovenantKey.PubKey()),
		// 	LeafHashes: [][]byte{
		// 		mustGetLeafHash(t, unbondingPathInfo),
		// 		// slashingPathLeafHash.CloneBytes(),
		// 	},
		// },
	}
	psbtPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		// {
		// 	ControlBlock: mustGetControlBlockBytes(t, stakingPathInfo),
		// 	Script:       stakingPathInfo.RevealedLeaf.Script,
		// 	LeafVersion:  stakingPathInfo.RevealedLeaf.LeafVersion,
		// },
		{
			ControlBlock: mustGetControlBlockBytes(t, unbondingPathInfo),
			Script:       unbondingPathInfo.RevealedLeaf.Script,
			LeafVersion:  unbondingPathInfo.RevealedLeaf.LeafVersion,
		},
		// {
		// 	ControlBlock: mustGetControlBlockBytes(t, slashingPathInfo),
		// 	Script:       slashingPathInfo.RevealedLeaf.Script,
		// 	LeafVersion:  slashingPathInfo.RevealedLeaf.LeafVersion,
		// },
	}

	psbtPacket.Inputs[0].TaprootMerkleRoot = treeRootNode.CloneBytes()
	psbtPacket.Inputs[0].TaprootInternalKey = schnorr.SerializePubKey(unbondingPathInfo.ControlBlock.InternalKey)

	fmt.Println("Internal key ")
	fmt.Println(hex.EncodeToString(schnorr.SerializePubKey(unbondingPathInfo.ControlBlock.InternalKey)))

	signedPacket, err := client.SignPsbt(psbtPacket)
	require.NoError(t, err)
	require.NotNil(t, signedPacket)

	time.Sleep(1 * time.Minute)

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

func ATestXxx(t *testing.T) {

	beforeUpdate := "cHNidP8BAF4CAAAAAVCHLYClfaFZONfY81p810Fq670T2UEcdAFozpOXQWFEAAAAAAAAAAAAAdB+AQAAAAAAIlEgJa/utiRq8XLgrdrlIE6hzZI+lh9eCiqA1ttPV6/zCXUAAAAAAAEBK6CGAQAAAAAAIlEgM72Vu1Q7KGYK7WhA6Pn8F0GUkC+nBknrJfVPdmYkxQYBBWggfsNxrE4elsMH2sRywe8w2FWMGOdcS+RoQiRXiyQkUpCtILKRFvK4WLYezDuOWdO3Tme+xOoTtLuvDdW1oPfnYegCrCDd3hLg3uXWLP8iz3NXXPyQ6zKHpHU/QbdB+oooFc1GE7pRokIVwVCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrAJU48K6Wfhd4f4bdaHO4WbUzXjmf6rNlfNAFMMo2PFbuLIH7DcaxOHpbDB9rEcsHvMNhVjBjnXEvkaEIkV4skJFKQrSBNtoTuxA0lzJ/LoiGBv7oAs0rvoflQZqJQM69wWi/E9a0gspEW8rhYth7MO45Z07dOZ77E6hO0u68N1bWg9+dh6AKsIN3eEuDe5dYs/yLPc1dc/JDrMoekdT9Bt0H6iigVzUYTulGiwGIVwVCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrA6fqTS/GAC8LQvsLBVc2ioSEzf98QVvAtiEdZRGOmcu24qTE/cSEV0lpCaNjctdluqU260C5mOkXSo5ZvCZhEHWkgfsNxrE4elsMH2sRywe8w2FWMGOdcS+RoQiRXiyQkUpCtILKRFvK4WLYezDuOWdO3Tme+xOoTtLuvDdW1oPfnYegCrCDd3hLg3uXWLP8iz3NXXPyQ6zKHpHU/QbdB+oooFc1GE7pRosBiFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wO2w7wQqYl2pn5P/4WvnAh8AazRfKyAiguKj7XjAx9VsuKkxP3EhFdJaQmjY3LXZbqlNutAuZjpF0qOWbwmYRB0nIH7DcaxOHpbDB9rEcsHvMNhVjBjnXEvkaEIkV4skJFKQrQIQJ7LAIRaykRbyuFi2Hsw7jlnTt05nvsTqE7S7rw3VtaD352HoAkUC7bDvBCpiXamfk//ha+cCHwBrNF8rICKC4qPteMDH1Wy4qTE/cSEV0lpCaNjctdluqU260C5mOkXSo5ZvCZhEHQAAAAAhFt3eEuDe5dYs/yLPc1dc/JDrMoekdT9Bt0H6iigVzUYTRQLtsO8EKmJdqZ+T/+Fr5wIfAGs0XysgIoLio+14wMfVbLipMT9xIRXSWkJo2Ny12W6pTbrQLmY6RdKjlm8JmEQdAAAAAAEXIFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrAARggXSYTWW1VliT3Egk3gHfxxF2uctZNNgpcWWK1h80buL8AAA=="
	afterUpdate := "cHNidP8BAF4CAAAAAVCHLYClfaFZONfY81p810Fq670T2UEcdAFozpOXQWFEAAAAAAAAAAAAAdB+AQAAAAAAIlEgJa/utiRq8XLgrdrlIE6hzZI+lh9eCiqA1ttPV6/zCXUAAAAAAAEBK6CGAQAAAAAAIlEgM72Vu1Q7KGYK7WhA6Pn8F0GUkC+nBknrJfVPdmYkxQYBBWggfsNxrE4elsMH2sRywe8w2FWMGOdcS+RoQiRXiyQkUpCtILKRFvK4WLYezDuOWdO3Tme+xOoTtLuvDdW1oPfnYegCrCDd3hLg3uXWLP8iz3NXXPyQ6zKHpHU/QbdB+oooFc1GE7pRomIVwVCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrA7bDvBCpiXamfk//ha+cCHwBrNF8rICKC4qPteMDH1Wy4qTE/cSEV0lpCaNjctdluqU260C5mOkXSo5ZvCZhEHScgfsNxrE4elsMH2sRywe8w2FWMGOdcS+RoQiRXiyQkUpCtAhAnssBCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wCVOPCuln4XeH+G3WhzuFm1M145n+qzZXzQBTDKNjxW7iyB+w3GsTh6WwwfaxHLB7zDYVYwY51xL5GhCJFeLJCRSkK0gTbaE7sQNJcyfy6Ihgb+6ALNK76H5UGaiUDOvcFovxPWtILKRFvK4WLYezDuOWdO3Tme+xOoTtLuvDdW1oPfnYegCrCDd3hLg3uXWLP8iz3NXXPyQ6zKHpHU/QbdB+oooFc1GE7pRosBiFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wOn6k0vxgAvC0L7CwVXNoqEhM3/fEFbwLYhHWURjpnLtuKkxP3EhFdJaQmjY3LXZbqlNutAuZjpF0qOWbwmYRB1pIH7DcaxOHpbDB9rEcsHvMNhVjBjnXEvkaEIkV4skJFKQrSCykRbyuFi2Hsw7jlnTt05nvsTqE7S7rw3VtaD352HoAqwg3d4S4N7l1iz/Is9zV1z8kOsyh6R1P0G3QfqKKBXNRhO6UaLAIRaykRbyuFi2Hsw7jlnTt05nvsTqE7S7rw3VtaD352HoAkUCuKkxP3EhFdJaQmjY3LXZbqlNutAuZjpF0qOWbwmYRB3tsO8EKmJdqZ+T/+Fr5wIfAGs0XysgIoLio+14wMfVbAAAAAAhFt3eEuDe5dYs/yLPc1dc/JDrMoekdT9Bt0H6iigVzUYTRQK4qTE/cSEV0lpCaNjctdluqU260C5mOkXSo5ZvCZhEHe2w7wQqYl2pn5P/4WvnAh8AazRfKyAiguKj7XjAx9VsAAAAAAEXIFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrAARggXSYTWW1VliT3Egk3gHfxxF2uctZNNgpcWWK1h80buL8AAA=="

	decodedBytes, err := base64.StdEncoding.DecodeString(afterUpdate)
	require.NoError(t, err)

	decoded, err := psbt.NewFromRawBytes(bytes.NewReader(decodedBytes), false)
	require.NoError(t, err)

	decBytesBeforeUpdate, err := base64.StdEncoding.DecodeString(beforeUpdate)
	require.NoError(t, err)

	decodedBeforeUpdate, err := psbt.NewFromRawBytes(bytes.NewReader(decBytesBeforeUpdate), false)
	require.NoError(t, err)

	fmt.Println("****************** Before update ******************")
	fmt.Println(decodedBeforeUpdate.Inputs[0])

	fmt.Println("****************** After update ******************")
	fmt.Println(decoded.Inputs[0])

}
