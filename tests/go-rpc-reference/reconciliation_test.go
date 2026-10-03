// Owned native policy/nonce/state observations and production RPC projections.
// Not a running node, funded block processor execution or independent finality.
package rpc

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	chaincrypto "github.com/resilience-network/chain/crypto"
	"github.com/resilience-network/chain/internal/blockchain"
	"github.com/resilience-network/chain/internal/db"
	"github.com/resilience-network/chain/internal/state"
	"github.com/resilience-network/chain/pkg/config"
	sa "github.com/resilience-network/chain/pkg/sessionauth"
	"github.com/resilience-network/chain/pkg/types"
	"math/big"
	"os"
	"testing"
	"time"
)

type sdkReconciliationFixture struct {
	Scenario        string          `json:"scenario"`
	Canonical       string          `json:"canonical"`
	TransactionHash string          `json:"transactionHash"`
	Identity        json.RawMessage `json:"identity"`
	Transaction     json.RawMessage `json:"transaction"`
	Receipt         json.RawMessage `json:"receipt"`
	Block           json.RawMessage `json:"block"`
	Root            json.RawMessage `json:"root"`
	AccountNonce    json.RawMessage `json:"accountNonce"`
	SponsorNonce    json.RawMessage `json:"sponsorNonce,omitempty"`
	Grant           json.RawMessage `json:"grant,omitempty"`
}

func sdkReconciliationFixtures(t *testing.T, originals []sdkReceiptFixture) {
	t.Helper()
	raw, err := os.ReadFile("../../reference/sessionauth/vectors/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string]json.RawMessage
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	var rootVector struct {
		Threshold  uint16 `json:"threshold"`
		SortedKeys []struct {
			PublicKey string `json:"publicKey"`
		} `json:"sortedKeys"`
	}
	if err = json.Unmarshal(vectors["root"], &rootVector); err != nil {
		t.Fatal(err)
	}
	var chainVector struct {
		GenesisHash string `json:"genesisHash"`
	}
	if err = json.Unmarshal(vectors["chain"], &chainVector); err != nil {
		t.Fatal(err)
	}
	genesis, err := types.HashFromHex(chainVector.GenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	ctx := sa.ChainContext{ChainID: 1337, GenesisHash: genesis}
	cfg := sa.RootConfig{Version: 1, Threshold: rootVector.Threshold}
	for _, key := range rootVector.SortedKeys {
		b, err := hex.DecodeString(key.PublicKey[2:])
		if err != nil {
			t.Fatal(err)
		}
		var public [32]byte
		copy(public[:], b)
		cfg.Keys = append(cfg.Keys, sa.RootKey{KeyScheme: 1, PublicKey: public})
	}
	var fixtures []sdkReconciliationFixture
	for _, original := range originals {
		canonical, err := hex.DecodeString(original.Canonical[2:])
		if err != nil {
			t.Fatal(err)
		}
		i, e, err := sa.UnmarshalTransaction(canonical)
		if err != nil {
			t.Fatal(err)
		}
		if original.Scenario == "sessionCancel-success" {
			digest, err := sa.SessionDigest(ctx, i, sa.SessionCredential{GrantID: e.CredentialID, AuthEpoch: e.AuthEpoch, PolicyHash: e.PolicyHash, Nonce: e.Nonce})
			if err != nil {
				t.Fatal(err)
			}
			seed := make([]byte, 32)
			for at := range seed {
				seed[at] = byte(64 + at)
			}
			e.Witness = append(ed25519.Sign(ed25519.NewKeyFromSeed(seed), digest[:]), 0)
		}
		height := uint64(101)
		if e.Mode == sa.AuthModeRoot {
			height = 100
		}
		if e.KeyScheme == sa.KeySchemeP256 {
			height = 201
		}
		tx, err := sa.NewSignedTransaction(ctx, i, e)
		if err != nil {
			t.Fatal(err)
		}
		store := db.NewMemDB()
		stateDB := state.NewStateDB(store, chaincrypto.ZeroHash)
		balance := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1_000_000_000_000_000_000))
		if err = stateDB.AddBalance(i.Sender, balance); err != nil {
			t.Fatal(err)
		}
		var receiptResponse struct {
			Result *RPCReceipt `json:"result"`
		}
		if err = json.Unmarshal(original.Receipt, &receiptResponse); err != nil {
			t.Fatal(err)
		}
		projected := receiptResponse.Result
		feeBytes, err := hex.DecodeString(projected.ActualFee[2:])
		if err != nil {
			t.Fatal(err)
		}
		var fee sa.Uint256
		copy(fee[:], feeBytes)
		success := projected.Status == "0x1"
		if e.Mode == sa.AuthModeDirect {
			stateDB.SetNonce(i.Sender, e.Nonce+1)
		} else {
			authority := &sa.RootAuthority{Version: 1, AuthEpoch: 1, Config: cfg, SecurityReserve: sa.Uint256FromUint64(5_000_000_000_000_000_000)}
			if err = stateDB.ActivateAuthorization(i.Sender, 0, authority); err != nil {
				t.Fatal(err)
			}
			if e.Mode == sa.AuthModeRoot {
				if success {
					d, err := sa.UnmarshalCreateGrantActionData(i.Data)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = stateDB.CreateSessionGrant(ctx, i.Sender, state.RootControlExpectation{AuthEpoch: 1, RootNonce: 0}, d.Grant.ValidAfterHeight-1, &d.Grant); err != nil {
						t.Fatal(err)
					}
				} else {
					if err = stateDB.SettleRootAuthorizationNonce(i.Sender, state.RootControlExpectation{AuthEpoch: 1, RootNonce: e.Nonce}); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				createName := "createGrant"
				if e.KeyScheme == sa.KeySchemeP256 {
					createName = "p256CreateGrant"
				}
				var vector struct {
					ActionData string `json:"actionData"`
				}
				if err = json.Unmarshal(vectors[createName], &vector); err != nil {
					t.Fatal(err)
				}
				b, err := hex.DecodeString(vector.ActionData[2:])
				if err != nil {
					t.Fatal(err)
				}
				d, err := sa.UnmarshalCreateGrantActionData(b)
				if err != nil {
					t.Fatal(err)
				}
				grant, err := stateDB.CreateSessionGrant(ctx, i.Sender, state.RootControlExpectation{AuthEpoch: 1, RootNonce: 0}, d.Grant.ValidAfterHeight-1, &d.Grant)
				if err != nil {
					t.Fatal(err)
				}
				if grant.GrantID != e.CredentialID {
					t.Fatalf("native grant ID does not match %s", original.Scenario)
				}
				decision, err := stateDB.EvaluateSessionAuthorization(state.SessionEvaluationContext{Chain: ctx, BlockHeight: height}, i, e)
				if err != nil {
					t.Fatalf("native evaluation %s: %v", original.Scenario, err)
				}
				if _, err = stateDB.SettleSessionAuthorizationAttempt(i.Sender, decision, height, fee, success, sa.Uint256{}); err != nil {
					t.Fatal(err)
				}
			}
		}
		if i.Sponsored() {
			if err = stateDB.AddBalance(i.Sponsor, balance); err != nil {
				t.Fatal(err)
			}
			stateDB.SetNonce(i.Sponsor, e.SponsorNonce+1)
		}
		root, err := stateDB.Commit()
		if err != nil {
			t.Fatal(err)
		}
		gas := uint64(21000)
		block := &types.Block{Header: &types.BlockHeader{Height: height, Slot: height, Timestamp: height*6 + 1, StateRoot: root, GasLimit: 30000000, GasUsed: gas, BaseFee: big.NewInt(2)}, Transactions: []*types.SignedTransaction{tx}}
		hash := blockchain.HashHeader(block.Header)
		receipt := &types.Receipt{TxHash: tx.Hash, BlockHash: hash, BlockHeight: height, TxIndex: 0, AuthorizationMode: uint8(e.Mode), CredentialID: e.CredentialID, AuthorizationEpoch: e.AuthEpoch, AuthorizationNonce: e.Nonce, PolicyHash: e.PolicyHash, Sponsor: i.Sponsor, AuthorizationGasUsed: 1000, ActualFee: types.Amount256(fee), BurnedFee: types.Amount256(sa.Uint256FromUint64(gas * 2)), GasUsed: gas, CumulativeGasUsed: gas, CounterDeltaHash: types.HashFromBytes(mustSDKDecodeHex(t, projected.CounterDeltaHash)), ActionStatus: types.ReceiptStatusSuccess}
		if !success {
			receipt.ActionStatus = types.ReceiptStatusFailed
			receipt.FailureCode = types.ReceiptFailureReverted
		}
		for _, projection := range projected.AuthorizationEvents {
			event, err := sa.UnmarshalAuthorizationEvent(&types.NativeEvent{Type: uint16(mustSDKQuantity(t, projection.Type)), Data: mustSDKDecodeHex(t, projection.Data)})
			if err != nil {
				t.Fatal(err)
			}
			event.BlockHeight = height
			event.TransactionID = tx.Hash
			if e.Mode == sa.AuthModeSession {
				event.RootConfigHash, err = sa.RootConfigHash(&cfg)
				if err != nil {
					t.Fatal(err)
				}
				event.RootNonce = 1
			}
			encoded, err := sa.MarshalAuthorizationEvent(event)
			if err != nil {
				t.Fatal(err)
			}
			receipt.AuthorizationEvents = append(receipt.AuthorizationEvents, encoded)
		}
		receipt.EventsRoot, err = sa.AuthorizationEventsRoot(receipt.AuthorizationEvents)
		if err != nil {
			t.Fatal(err)
		}
		backend := &mockChain{height: height, blocks: map[uint64]*types.Block{height: block}, receipts: map[types.Hash][]*types.Receipt{hash: {receipt}}}
		params := config.DefaultChainParams()
		params.ChainID = ctx.ChainID
		params.GenesisHash = ctx.GenesisHash
		params.SlotsPerEpoch = 64
		params.SlotDuration = 6 * time.Second
		api := NewAPI(backend, func(root types.Hash) StateBackend { return state.NewStateDB(store, chaincrypto.Hash32(root)) }, nil, nil, nil, params, nil)
		h := NewHandler()
		api.RegisterRoutes(h)
		call := func(method string, args ...any) json.RawMessage {
			if args == nil {
				args = []any{}
			}
			b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": args})
			if err != nil {
				t.Fatal(err)
			}
			return h.Handle(b)
		}
		f := sdkReconciliationFixture{Scenario: original.Scenario, Canonical: EncodeHex(tx.Payload), TransactionHash: tx.Hash.Hex(), Identity: call("rsc_getAuthorizationFinalityStatus"), Transaction: call("rsc_getTransactionByHash", tx.Hash.Hex()), Receipt: call("rsc_getTransactionReceipt", tx.Hash.Hex()), Block: call("rsc_getBlockByNumber", EncodeUint64Hex(height), false), Root: call("rsc_getRootAuthority", i.Sender.Hex()), AccountNonce: call("rsc_getTransactionCount", i.Sender.Hex(), "latest")}
		if i.Sponsored() {
			f.SponsorNonce = call("rsc_getTransactionCount", i.Sponsor.Hex(), "latest")
		}
		if e.Mode == sa.AuthModeSession {
			f.Grant = call("rsc_getSessionGrant", i.Sender.Hex(), e.CredentialID.Hex())
		}
		fixtures = append(fixtures, f)
		store.Close()
	}
	output, err := json.MarshalIndent(fixtures, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("RSC_RPC_RECONCILE_OUTPUT")
	if path == "" {
		t.Fatal("RSC_RPC_RECONCILE_OUTPUT required")
	}
	if err = os.WriteFile(path, append(output, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
func mustSDKDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func mustSDKQuantity(t *testing.T, s string) uint64 {
	t.Helper()
	n, err := DecodeUint64Hex(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
