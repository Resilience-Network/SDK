// Installed exclusively as a temporary test in the immutable pinned RPC package.
// Uses its production Handler/API/state and existing test-only mockChain/policy.
package rpc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	chaincrypto "github.com/resilience-network/chain/crypto"
	"github.com/resilience-network/chain/internal/db"
	"github.com/resilience-network/chain/internal/state"
	"github.com/resilience-network/chain/pkg/config"
	"github.com/resilience-network/chain/pkg/sessionauth"
	"github.com/resilience-network/chain/pkg/types"
)

type sdkRPCFixture struct {
	Scenario string          `json:"scenario"`
	Method   string          `json:"method"`
	Params   any             `json:"params"`
	Response json.RawMessage `json:"response"`
	Identity json.RawMessage `json:"identity"`
}

type sdkRPCEnvelopeFixture struct {
	Scenario string          `json:"scenario"`
	Source   string          `json:"source"`
	Request  json.RawMessage `json:"request"`
	Response json.RawMessage `json:"response"`
}

func sdkEnvelopeFixtures(t *testing.T, handler *Handler) []sdkRPCEnvelopeFixture {
	t.Helper()
	var fixtures []sdkRPCEnvelopeFixture
	capture := func(scenario, source string, request any) {
		t.Helper()
		wire, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		response := handler.Handle(wire)
		if !json.Valid(response) {
			t.Fatalf("invalid response: %s", scenario)
		}
		fixtures = append(fixtures, sdkRPCEnvelopeFixture{scenario, source, wire, response})
	}
	request := func(id int, method string, args ...any) map[string]any {
		if args == nil {
			args = []any{}
		}
		return map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": args}
	}
	missing := (types.Hash{31: 0xff}).Hex()
	for _, method := range []string{"rsc_getTransactionByHash", "eth_getTransactionByHash", "rsc_getTransactionReceipt", "eth_getTransactionReceipt", "rsc_getBlockByHash", "eth_getBlockByHash"} {
		args := []any{missing}
		if method == "rsc_getBlockByHash" || method == "eth_getBlockByHash" {
			args = append(args, false)
		}
		capture(method+"-absent", "public-api", request(17, method, args...))
	}
	capture("invalid-params", "public-api", request(31, "rsc_getTransactionReceipt"))
	capture("unknown-method", "production-dispatch", request(9, "sdk_missing_method"))
	var pointer *int
	var slice []int
	var object map[string]int
	probes := []struct {
		name  string
		value any
	}{
		{"nil", nil}, {"typed-pointer", pointer}, {"typed-slice", slice}, {"typed-map", object},
		{"false", false}, {"zero", 0}, {"empty-string", ""}, {"empty-list", []int{}}, {"empty-map", map[string]int{}},
	}
	for _, probe := range probes {
		handler.Register("sdk_probe_"+strings.ReplaceAll(probe.name, "-", "_"), func(json.RawMessage) (any, *RPCError) { return probe.value, nil })
		capture(probe.name, "production-handler-test-probe", request(42, "sdk_probe_"+strings.ReplaceAll(probe.name, "-", "_")))
	}
	capture("mixed-public-batch", "public-api", []any{
		request(19, "rsc_getTransactionReceipt", missing), request(3, "rsc_getTransactionReceipt"), request(11, "rsc_gasPrice"),
	})
	capture("mixed-probe-batch", "production-handler-test-probe", []any{
		request(7, "sdk_probe_false"), request(1, "sdk_missing_method"), request(25, "sdk_probe_nil"), request(13, "sdk_probe_zero"), request(29, "sdk_probe_empty_string"),
	})
	return fixtures
}

func TestSDKPinnedRPCContracts(t *testing.T) {
	var fixtures []sdkRPCFixture
	context := sessionauth.ChainContext{ChainID: 1337, GenesisHash: types.Hash{31: 0xaa}}
	params := config.DefaultChainParams()
	params.ChainID, params.GenesisHash = context.ChainID, context.GenesisHash
	params.GasLimit, params.MinGasPrice, params.SlotsPerEpoch, params.SlotDuration = 30_000_000, big.NewInt(1), 64, 6*time.Second
	capture := func(api *API, scenario, method string, args ...string) {
		t.Helper()
		handler := NewHandler()
		api.RegisterRoutes(handler)
		if args == nil {
			args = []string{}
		}
		request, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": args})
		if err != nil {
			t.Fatal(err)
		}
		response := handler.Handle(request)
		identity := handler.Handle([]byte(`{"jsonrpc":"2.0","id":1,"method":"rsc_getAuthorizationFinalityStatus","params":[]}`))
		var check map[string]json.RawMessage
		if err := json.Unmarshal(response, &check); err != nil {
			t.Fatal(err)
		}
		if check["result"] == nil && check["error"] == nil {
			t.Fatalf("missing outcome for %s", method)
		}
		fixtures = append(fixtures, sdkRPCFixture{scenario, method, args, response, identity})
	}
	for _, scheme := range []sessionauth.KeyScheme{sessionauth.KeySchemeEd25519, sessionauth.KeySchemeP256} {
		store := db.NewMemDB()
		defer store.Close()
		stateDB := state.NewStateDB(store, chaincrypto.ZeroHash)
		owner := types.Address{19: 1}
		rootPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
		var rootKey [32]byte
		copy(rootKey[:], rootPrivate.Public().(ed25519.PublicKey))
		if err := stateDB.AddBalance(owner, new(big.Int).Mul(big.NewInt(100), big.NewInt(1_000_000_000_000_000_000))); err != nil {
			t.Fatal(err)
		}
		authority := &sessionauth.RootAuthority{Version: 1, AuthEpoch: 1, Config: sessionauth.RootConfig{Version: 1, Threshold: 1, Keys: []sessionauth.RootKey{{KeyScheme: 1, PublicKey: rootKey}}}, SecurityReserve: sessionauth.MinimumSecurityReserve()}
		if err := stateDB.ActivateAuthorization(owner, 0, authority); err != nil {
			t.Fatal(err)
		}
		sessionPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
		var public [64]byte
		if scheme == sessionauth.KeySchemeEd25519 {
			copy(public[:], sessionPrivate.Public().(ed25519.PublicKey))
		} else {
			x, y := elliptic.P256().ScalarBaseMult([]byte{3})
			x.FillBytes(public[:32])
			y.FillBytes(public[32:])
		}
		policy := rpcAuthorizationPolicy()
		policy.Transfer.Limits.ValueTokenBucket = &sessionauth.TokenBucketConfig{Capacity: sessionauth.Uint256FromUint64(1_000), RefillPerBlock: sessionauth.Uint256FromUint64(20)}
		policy.Fee.FeeTokenBucket = &sessionauth.TokenBucketConfig{Capacity: sessionauth.Uint256FromUint64(1_000_000), RefillPerBlock: sessionauth.Uint256FromUint64(100)}
		spec := &sessionauth.GrantSpec{KeyScheme: scheme, PublicKey: public, ValidAfterHeight: 11, ValidUntilHeight: 100, Policy: *policy, StorageDeposit: sessionauth.StorageDepositMinimum()}
		grant, err := stateDB.CreateSessionGrant(context, owner, state.RootControlExpectation{AuthEpoch: 1}, 10, spec)
		if err != nil {
			t.Fatal(err)
		}
		root, err := stateDB.Commit()
		if err != nil {
			t.Fatal(err)
		}
		head := &types.Block{Header: &types.BlockHeader{Height: 11, Slot: 11, Timestamp: 67, StateRoot: root, GasLimit: params.GasLimit, BaseFee: big.NewInt(1)}}
		chain := &mockChain{height: 11, blocks: map[uint64]*types.Block{11: head}}
		api := NewAPI(chain, func(r types.Hash) StateBackend { return state.NewStateDB(store, chaincrypto.Hash32(r)) }, nil, nil, nil, params, nil)
		scenario := "ed25519"
		if scheme == sessionauth.KeySchemeP256 {
			scenario = "p256"
		}
		capture(api, scenario, "rsc_getAuthorizationFinalityStatus")
		capture(api, scenario, "rsc_getRootAuthority", owner.Hex())
		for _, method := range []string{"rsc_getSessionGrant", "rsc_getSessionNonce", "rsc_getSessionUsage"} {
			capture(api, scenario, method, owner.Hex(), grant.GrantID.Hex())
		}
		canonical, err := sessionauth.MarshalPolicy(policy)
		if err != nil {
			t.Fatal(err)
		}
		capture(api, scenario, "rsc_decodePolicy", EncodeHex(canonical))
		capture(api, scenario, "rsc_previewPolicy", EncodeHex(canonical))
		capture(api, scenario+"-unknown", "rsc_getSessionGrant", owner.Hex(), (types.Hash{31: 0xff}).Hex())
		if scheme == sessionauth.KeySchemeEd25519 {
			intent := &sessionauth.TxIntent{Version: 2, ChainID: context.ChainID, Sender: owner, ActionType: sessionauth.ActionTransfer, Destination: types.Address{19: 2}, Value: sessionauth.Uint256FromUint64(10), GasLimit: 50_000, MaxFeePerGas: sessionauth.Uint256FromUint64(1), MaxPriorityFeePerGas: sessionauth.Uint256FromUint64(1)}
			digest, err := sessionauth.SessionDigest(context, intent, sessionauth.SessionCredential{GrantID: grant.GrantID, AuthEpoch: 1, PolicyHash: grant.PolicyHash})
			if err != nil {
				t.Fatal(err)
			}
			witness := append(ed25519.Sign(sessionPrivate, digest[:]), 0)
			tx, err := sessionauth.NewSignedTransaction(context, intent, &sessionauth.AuthEnvelope{Version: 1, Mode: sessionauth.AuthModeSession, KeyScheme: scheme, CredentialID: grant.GrantID, AuthEpoch: 1, PolicyHash: grant.PolicyHash, Witness: witness})
			if err != nil {
				t.Fatal(err)
			}
			capture(api, "session", "rsc_estimateAuthorizationGas", EncodeHex(tx.Payload))
			capture(api, "session", "rsc_simulateAuthorizedTransaction", EncodeHex(tx.Payload))
			reloaded := state.NewStateDB(store, chaincrypto.Hash32(root))
			after, err := reloaded.GetSessionGrant(owner, grant.GrantID)
			if err != nil || after.SessionNonce != 0 || reloaded.GetBalance(intent.Destination).Sign() != 0 {
				t.Fatal("simulation leaked state")
			}
		}
		merkle := rpcAuthorizationPolicy()
		merkle.MaxAttempts = ^uint64(0)
		merkle.Transfer.Recipients = sessionauth.RecipientSet{Kind: sessionauth.RecipientSetMerkle, MerkleRoot: types.Hash{31: 1}, LeafCount: 3}
		canonical, err = sessionauth.MarshalPolicy(merkle)
		if err != nil {
			t.Fatal(err)
		}
		capture(api, scenario+"-warnings", "rsc_previewPolicy", EncodeHex(canonical))
		// Revoke-all is O(1); old grant/index records remain with a stale epoch.
		if err := stateDB.RevokeAllSessionGrants(owner, state.RootControlExpectation{AuthEpoch: 1, RootNonce: 1}); err != nil {
			t.Fatal(err)
		}
		revokedRoot, err := stateDB.Commit()
		if err != nil {
			t.Fatal(err)
		}
		head.Header.StateRoot = revokedRoot
		capture(api, scenario+"-revoked", "rsc_getRootAuthority", owner.Hex())
		for _, method := range []string{"rsc_getSessionGrant", "rsc_getSessionNonce", "rsc_getSessionUsage"} {
			capture(api, scenario+"-revoked", method, owner.Hex(), grant.GrantID.Hex())
		}
	}
	store := db.NewMemDB()
	defer store.Close()
	stateDB := state.NewStateDB(store, chaincrypto.ZeroHash)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	public := private.Public().(ed25519.PublicKey)
	chainPublic, err := chaincrypto.PublicKeyFromBytes(public)
	if err != nil {
		t.Fatal(err)
	}
	derived := chainPublic.Address()
	owner := types.AddressFromBytes(derived[:])
	if err := stateDB.AddBalance(owner, big.NewInt(1_000_000_000)); err != nil {
		t.Fatal(err)
	}
	root, err := stateDB.Commit()
	if err != nil {
		t.Fatal(err)
	}
	head := &types.Block{Header: &types.BlockHeader{Height: 0, Slot: 0, Timestamp: 1, StateRoot: root, GasLimit: params.GasLimit, BaseFee: big.NewInt(1)}}
	chain := &mockChain{height: 0, blocks: map[uint64]*types.Block{0: head}}
	api := NewAPI(chain, func(r types.Hash) StateBackend { return state.NewStateDB(store, chaincrypto.Hash32(r)) }, nil, nil, nil, params, nil)
	capture(api, "direct", "rsc_getRootAuthority", owner.Hex())
	capture(api, "direct", "rsc_gasPrice")
	capture(api, "direct", "rsc_maxPriorityFeePerGas")
	// feeHistory has a heterogeneous parameter array; use production Handler explicitly.
	h := NewHandler()
	api.RegisterRoutes(h)
	identity := h.Handle([]byte(`{"jsonrpc":"2.0","id":1,"method":"rsc_getAuthorizationFinalityStatus","params":[]}`))
	response := h.Handle([]byte(`{"jsonrpc":"2.0","id":1,"method":"rsc_feeHistory","params":["0x2","latest",[0,50,100]]}`))
	fixtures = append(fixtures, sdkRPCFixture{"direct", "rsc_feeHistory", []any{"0x2", "latest", []int{0, 50, 100}}, response, identity})
	intent := &sessionauth.TxIntent{Version: 2, ChainID: context.ChainID, Sender: owner, ActionType: sessionauth.ActionTransfer, Destination: types.Address{19: 0x99}, Value: sessionauth.Uint256FromUint64(10), GasLimit: 50_000, MaxFeePerGas: sessionauth.Uint256FromUint64(1), MaxPriorityFeePerGas: sessionauth.Uint256FromUint64(1)}
	digest, err := sessionauth.DirectDigest(context, intent, 0)
	if err != nil {
		t.Fatal(err)
	}
	witness := append(append([]byte{}, public...), ed25519.Sign(private, digest[:])...)
	tx, err := sessionauth.NewSignedTransaction(context, intent, &sessionauth.AuthEnvelope{Version: 1, Mode: 0, KeyScheme: 1, Witness: witness})
	if err != nil {
		t.Fatal(err)
	}
	capture(api, "direct", "rsc_estimateAuthorizationGas", EncodeHex(tx.Payload))
	capture(api, "direct", "rsc_simulateAuthorizedTransaction", EncodeHex(tx.Payload))
	witness[40] ^= 1
	invalid, err := sessionauth.NewSignedTransaction(context, intent, &sessionauth.AuthEnvelope{Version: 1, Mode: 0, KeyScheme: 1, Witness: witness})
	if err != nil {
		t.Fatal(err)
	}
	capture(api, "bad-signature", "rsc_estimateAuthorizationGas", EncodeHex(invalid.Payload))
	reloaded := state.NewStateDB(store, chaincrypto.Hash32(root))
	if reloaded.GetNonce(owner) != 0 || reloaded.GetBalance(intent.Destination).Sign() != 0 {
		t.Fatal("direct simulation leaked state")
	}
	output, err := json.MarshalIndent(fixtures, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("RSC_RPC_FIXTURE_OUTPUT")
	if path == "" {
		t.Fatal("RSC_RPC_FIXTURE_OUTPUT required")
	}
	if err := os.WriteFile(path, append(output, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	envelopes, err := json.MarshalIndent(sdkEnvelopeFixtures(t, h), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	envelopePath := os.Getenv("RSC_RPC_ENVELOPE_OUTPUT")
	if envelopePath == "" {
		t.Fatal("RSC_RPC_ENVELOPE_OUTPUT required")
	}
	if err := os.WriteFile(envelopePath, append(envelopes, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
