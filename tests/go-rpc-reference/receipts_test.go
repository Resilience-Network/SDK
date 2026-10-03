// Projection-only fixtures: canonical native hashes/events and production RPC
// rendering against owned in-memory state. Not funded execution or finality proof.
package rpc

import (
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

type sdkReceiptFixture struct {
	Scenario        string          `json:"scenario"`
	Canonical       string          `json:"canonical"`
	TransactionHash string          `json:"transactionHash"`
	Identity        json.RawMessage `json:"identity"`
	Transaction     json.RawMessage `json:"transaction"`
	Receipt         json.RawMessage `json:"receipt"`
}

func sdkWriteReceiptFixtures(t *testing.T) {
	t.Helper()
	var vectors map[string]json.RawMessage
	content, err := os.ReadFile("../../reference/sessionauth/vectors/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(content, &vectors); err != nil {
		t.Fatal(err)
	}
	var chain struct {
		ChainID     string `json:"chainId"`
		GenesisHash string `json:"genesisHash"`
	}
	if err = json.Unmarshal(vectors["chain"], &chain); err != nil {
		t.Fatal(err)
	}
	genesis, err := types.HashFromHex(chain.GenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	ctx := sa.ChainContext{ChainID: 1337, GenesisHash: genesis}
	var fixtures []sdkReceiptFixture
	for _, name := range []string{"directTransfer", "createGrant", "sessionTransfer", "p256SessionTransfer", "sponsoredTransfer", "sessionCancel"} {
		for _, success := range []bool{true, false} {
			if name == "sessionCancel" && !success {
				continue
			}
			vectorName := name
			if name == "sessionCancel" {
				vectorName = "sessionTransfer"
			}
			var vector struct {
				Intent   string `json:"intentCanonical"`
				Envelope string `json:"authEnvelopeCanonical"`
			}
			if err = json.Unmarshal(vectors[vectorName], &vector); err != nil {
				t.Fatal(err)
			}
			iBytes, err := hex.DecodeString(vector.Intent[2:])
			if err != nil {
				t.Fatal(err)
			}
			eBytes, err := hex.DecodeString(vector.Envelope[2:])
			if err != nil {
				t.Fatal(err)
			}
			intent, err := sa.UnmarshalTxIntent(iBytes)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := sa.UnmarshalAuthEnvelope(eBytes)
			if err != nil {
				t.Fatal(err)
			}
			if name == "sessionCancel" {
				intent.ActionType = sa.ActionSessionCancel
				intent.Destination = types.ZeroAddress
				intent.Value = sa.Uint256{}
				intent.Data = nil
				envelope.Witness = make([]byte, 65)
			}
			tx, err := sa.NewSignedTransaction(ctx, intent, envelope)
			if err != nil {
				t.Fatal(err)
			}
			gas := uint64(21000)
			price := intent.MaxFeePerGas
			fee, err := price.MulUint64(gas)
			if err != nil {
				t.Fatal(err)
			}
			status := types.ReceiptStatusSuccess
			failure := types.ReceiptFailureNone
			if !success {
				status = types.ReceiptStatusFailed
				failure = types.ReceiptFailureReverted
			}
			delta := &sa.ReceiptCounterDelta{Version: 1, Mode: envelope.Mode, ActionType: intent.ActionType, NonceDelta: 1, FeeDelta: fee, Succeeded: success}
			if intent.Sponsored() {
				delta.NonceDelta = 2
			}
			if envelope.Mode == sa.AuthModeSession {
				delta.AttemptsDelta = 1
				if success && intent.ActionType != sa.ActionSessionCancel {
					delta.SuccessesDelta = 1
					delta.ValueCategory = sa.ValueAccountingExternalSpend
					delta.ValueDelta = intent.Value
				}
			}
			deltaHash, err := sa.ReceiptCounterDeltaHash(delta)
			if err != nil {
				t.Fatal(err)
			}
			receipt := &types.Receipt{TxHash: tx.Hash, BlockHeight: 11, TxIndex: 0, AuthorizationMode: uint8(envelope.Mode), CredentialID: envelope.CredentialID, AuthorizationEpoch: envelope.AuthEpoch, AuthorizationNonce: envelope.Nonce, PolicyHash: envelope.PolicyHash, Sponsor: intent.Sponsor, AuthorizationGasUsed: 1000, ActualFee: types.Amount256(fee), BurnedFee: types.Amount256(sa.Uint256FromUint64(gas * 2)), CounterDeltaHash: deltaHash, ActionStatus: status, FailureCode: failure, GasUsed: gas, CumulativeGasUsed: gas}
			if name == "directTransfer" && success {
				receipt.Logs = []*types.Log{{Address: intent.Destination, Topics: []types.Hash{{31: 9}}, Data: []byte{1, 2, 3}}}
			}

			if envelope.Mode == sa.AuthModeSession {
				event := &sa.AuthorizationEvent{Version: 1, Type: sa.EventSessionAttempted, Owner: intent.Sender, GrantID: envelope.CredentialID, RootConfigHash: types.Hash{31: 1}, PolicyHash: envelope.PolicyHash, AuthEpoch: envelope.AuthEpoch, RootNonce: 5, SessionNonce: envelope.Nonce + 1, BlockHeight: 11, TransactionID: tx.Hash, AmountA: fee, AmountB: delta.ValueDelta, ActionStatus: uint8(status), FailureCode: uint16(failure)}
				native, err := sa.MarshalAuthorizationEvent(event)
				if err != nil {
					t.Fatal(err)
				}
				receipt.AuthorizationEvents = []*types.NativeEvent{native}
				if intent.ActionType == sa.ActionSessionCancel {
					event.Type = sa.EventSessionCancelled
					native, err := sa.MarshalAuthorizationEvent(event)
					if err != nil {
						t.Fatal(err)
					}
					receipt.AuthorizationEvents = append(receipt.AuthorizationEvents, native)
				}
			} else if name == "createGrant" && success {
				d, err := sa.UnmarshalCreateGrantActionData(intent.Data)
				if err != nil {
					t.Fatal(err)
				}
				policy, err := sa.PolicyHash(&d.Grant.Policy)
				if err != nil {
					t.Fatal(err)
				}
				native, err := sa.MarshalAuthorizationEvent(&sa.AuthorizationEvent{Version: 1, Type: sa.EventSessionGrantCreated, Owner: intent.Sender, GrantID: types.Hash{31: 2}, RootConfigHash: envelope.CredentialID, PolicyHash: policy, AuthEpoch: envelope.AuthEpoch, RootNonce: envelope.Nonce + 1, BlockHeight: 11, TransactionID: tx.Hash, AmountA: d.Grant.StorageDeposit, ActionStatus: 1})
				if err != nil {
					t.Fatal(err)
				}
				receipt.AuthorizationEvents = []*types.NativeEvent{native}
			}
			receipt.EventsRoot, err = sa.AuthorizationEventsRoot(receipt.AuthorizationEvents)
			if err != nil {
				t.Fatal(err)
			}
			store := db.NewMemDB()
			stateDB := state.NewStateDB(store, chaincrypto.ZeroHash)
			root, err := stateDB.Commit()
			if err != nil {
				t.Fatal(err)
			}
			block := &types.Block{Header: &types.BlockHeader{Height: 11, Slot: 11, Timestamp: 67, StateRoot: root, GasLimit: 30000000, GasUsed: gas, BaseFee: big.NewInt(2)}, Transactions: []*types.SignedTransaction{tx}}
			hash := blockchain.HashHeader(block.Header)
			receipt.BlockHash = hash
			backend := &mockChain{height: 11, blocks: map[uint64]*types.Block{11: block}, receipts: map[types.Hash][]*types.Receipt{hash: {receipt}}}
			params := config.DefaultChainParams()
			params.ChainID = ctx.ChainID
			params.GenesisHash = ctx.GenesisHash
			params.SlotsPerEpoch = 64
			params.SlotDuration = 6 * time.Second
			api := NewAPI(backend, func(root types.Hash) StateBackend { return state.NewStateDB(store, chaincrypto.Hash32(root)) }, nil, nil, nil, params, nil)
			h := NewHandler()
			api.RegisterRoutes(h)
			call := func(method string, args ...string) json.RawMessage {
				if args == nil {
					args = []string{}
				}
				b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": args})
				if err != nil {
					t.Fatal(err)
				}
				return h.Handle(b)
			}
			scenario := name + "-success"
			if !success {
				scenario = name + "-failure"
			}
			fixtures = append(fixtures, sdkReceiptFixture{scenario, EncodeHex(tx.Payload), tx.Hash.Hex(), call("rsc_getAuthorizationFinalityStatus"), call("rsc_getTransactionByHash", tx.Hash.Hex()), call("rsc_getTransactionReceipt", tx.Hash.Hex())})
			store.Close()
		}
	}
	b, err := json.MarshalIndent(fixtures, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("RSC_RPC_RECEIPT_OUTPUT")
	if path == "" {
		t.Fatal("RSC_RPC_RECEIPT_OUTPUT required")
	}
	if err = os.WriteFile(path, append(b, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
