// Installed exclusively into the pinned sessionauth package for native comparison.
// Decision fixtures test seal commitments, not policy evaluation or live authority.
package sessionauth

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	chaincrypto "github.com/resilience-network/chain/crypto"
	"github.com/resilience-network/chain/pkg/types"
	"os"
	"testing"
)

type sdkCommitmentCase struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Hex  string `json:"hex"`
	Hash string `json:"hash"`
}
type sdkCommitmentRequest struct {
	Kind string `json:"kind"`
	Hex  string `json:"hex"`
}
type sdkCommitmentResult struct {
	Accepted  bool   `json:"accepted"`
	Canonical string `json:"canonical,omitempty"`
	Hash      string `json:"hash,omitempty"`
}

func sdkHex(b []byte) string { return "0x" + hex.EncodeToString(b) }
func sdkDecisionEncoding(v *SessionAuthorizationDecision) []byte {
	e := new(encoder)
	e.address(v.sender)
	e.hash(v.intentHash)
	e.hash(v.grantID)
	e.u64(v.authEpoch)
	e.u64(v.sessionNonce)
	e.hash(v.policyHash)
	e.u8(uint8(v.actionType))
	e.uint256(v.maximumFee)
	e.uint256(v.maximumDebit)
	e.uint256(v.reservedValue)
	e.u8(uint8(v.valueCategory))
	e.bool(v.feeBucketPresent)
	encodeTokenBucketState(e, v.refilledFeeBucket)
	e.bool(v.valueBucketPresent)
	encodeTokenBucketState(e, v.refilledValueBucket)
	e.bool(v.matchedRulePresent)
	e.u16(v.matchedRuleIndex)
	e.u32(v.maxRuntimeCodeLength)
	e.u16(v.constraintCount)
	e.u32(v.inspectedCalldataBytes)
	e.u8(v.merkleProofNodes)
	e.bool(v.targetCodePresent)
	e.address(v.targetCodeAddress)
	e.hash(v.targetCodeDependency)
	e.u64(v.evaluationHeight)
	return e.data
}
func sdkDecisionDecode(b []byte) (*SessionAuthorizationDecision, error) {
	// This test decoder is not a Chain wire API. The production seal is recomputed
	// only to compare structural rules through ValidateSessionAuthorizationDecision.
	d := newDecoder(b)
	v := new(SessionAuthorizationDecision)
	var err error
	if v.sender, err = d.address(); err != nil {
		return nil, err
	}
	if v.intentHash, err = d.hash(); err != nil {
		return nil, err
	}
	if v.grantID, err = d.hash(); err != nil {
		return nil, err
	}
	if v.authEpoch, err = d.u64(); err != nil {
		return nil, err
	}
	if v.sessionNonce, err = d.u64(); err != nil {
		return nil, err
	}
	if v.policyHash, err = d.hash(); err != nil {
		return nil, err
	}
	a, err := d.u8()
	if err != nil {
		return nil, err
	}
	v.actionType = ActionType(a)
	if v.maximumFee, err = d.uint256(); err != nil {
		return nil, err
	}
	if v.maximumDebit, err = d.uint256(); err != nil {
		return nil, err
	}
	if v.reservedValue, err = d.uint256(); err != nil {
		return nil, err
	}
	c, err := d.u8()
	if err != nil {
		return nil, err
	}
	v.valueCategory = ValueAccountingCategory(c)
	if v.feeBucketPresent, err = d.bool(); err != nil {
		return nil, err
	}
	if v.refilledFeeBucket, err = decodeTokenBucketState(d); err != nil {
		return nil, err
	}
	if v.valueBucketPresent, err = d.bool(); err != nil {
		return nil, err
	}
	if v.refilledValueBucket, err = decodeTokenBucketState(d); err != nil {
		return nil, err
	}
	if v.matchedRulePresent, err = d.bool(); err != nil {
		return nil, err
	}
	if v.matchedRuleIndex, err = d.u16(); err != nil {
		return nil, err
	}
	if v.maxRuntimeCodeLength, err = d.u32(); err != nil {
		return nil, err
	}
	if v.constraintCount, err = d.u16(); err != nil {
		return nil, err
	}
	if v.inspectedCalldataBytes, err = d.u32(); err != nil {
		return nil, err
	}
	if v.merkleProofNodes, err = d.u8(); err != nil {
		return nil, err
	}
	if v.targetCodePresent, err = d.bool(); err != nil {
		return nil, err
	}
	if v.targetCodeAddress, err = d.address(); err != nil {
		return nil, err
	}
	if v.targetCodeDependency, err = d.hash(); err != nil {
		return nil, err
	}
	if v.evaluationHeight, err = d.u64(); err != nil {
		return nil, err
	}
	if err = d.done(); err != nil {
		return nil, err
	}
	v.decisionSeal = sessionDecisionSeal(v)
	if err = ValidateSessionAuthorizationDecision(v); err != nil {
		return nil, err
	}
	return v, nil
}
func sdkCommitmentOracle(request sdkCommitmentRequest) sdkCommitmentResult {
	if len(request.Hex) < 2 || request.Hex[:2] != "0x" {
		return sdkCommitmentResult{}
	}
	b, err := hex.DecodeString(request.Hex[2:])
	if err != nil {
		return sdkCommitmentResult{}
	}
	switch request.Kind {
	case "counter":
		v, err := UnmarshalReceiptCounterDelta(b)
		if err != nil {
			return sdkCommitmentResult{}
		}
		out, err := MarshalReceiptCounterDelta(v)
		if err != nil {
			return sdkCommitmentResult{}
		}
		h, err := ReceiptCounterDeltaHash(v)
		if err != nil {
			return sdkCommitmentResult{}
		}
		return sdkCommitmentResult{true, sdkHex(out), h.Hex()}
	case "event":
		if len(b) < 4 {
			return sdkCommitmentResult{}
		}
		native := &types.NativeEvent{Type: uint16(b[2])<<8 | uint16(b[3]), Data: b}
		v, err := UnmarshalAuthorizationEvent(native)
		if err != nil {
			return sdkCommitmentResult{}
		}
		out, err := MarshalAuthorizationEvent(v)
		if err != nil {
			return sdkCommitmentResult{}
		}
		return sdkCommitmentResult{true, sdkHex(out.Data), types.Hash(chaincrypto.Keccak256Hash(out.Data)).Hex()}
	case "decision":
		v, err := sdkDecisionDecode(b)
		if err != nil {
			return sdkCommitmentResult{}
		}
		return sdkCommitmentResult{true, sdkHex(sdkDecisionEncoding(v)), sessionDecisionSeal(v).Hex()}
	}
	return sdkCommitmentResult{}
}
func TestSDKReceiptCommitments(t *testing.T) {
	var output any
	if path := os.Getenv("RSC_RECEIPT_INPUT"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var requests []sdkCommitmentRequest
		if err = json.Unmarshal(b, &requests); err != nil {
			t.Fatal(err)
		}
		results := make([]sdkCommitmentResult, len(requests))
		for i, r := range requests {
			results[i] = sdkCommitmentOracle(r)
		}
		output = results
	} else {
		var fixtures []sdkCommitmentCase
		add := func(kind, name string, b []byte) {
			result := sdkCommitmentOracle(sdkCommitmentRequest{kind, sdkHex(b)})
			if !result.Accepted {
				t.Fatalf("invalid independent fixture %s/%s", kind, name)
			}
			fixtures = append(fixtures, sdkCommitmentCase{kind, name, result.Canonical, result.Hash})
		}
		maximum := Uint256{}
		for i := range maximum {
			maximum[i] = 255
		}
		for _, mode := range []AuthMode{AuthModeDirect, AuthModeRoot, AuthModeSession} {
			for action := ActionTransfer; action <= ActionCancelRecovery; action++ {
				if !action.Valid() {
					continue
				}
				for _, success := range []bool{false, true} {
					d := &ReceiptCounterDelta{Version: 1, Mode: mode, ActionType: action, NonceDelta: 1, FeeDelta: maximum, Succeeded: success}
					if mode == AuthModeSession {
						d.AttemptsDelta = 1
						if success && action != ActionSessionCancel {
							d.SuccessesDelta = 1
							switch action {
							case ActionTransfer, ActionContractCall, ActionContractCreate:
								d.ValueCategory = ValueAccountingExternalSpend
							case ActionStake:
								d.ValueCategory = ValueAccountingStakeLock
							case ActionUnstake:
								d.ValueCategory = ValueAccountingUnlock
							case ActionDelegate:
								d.ValueCategory = ValueAccountingDelegationLock
							case ActionClaimRewards:
								d.ValueCategory = ValueAccountingRewardClaim
								d.ClaimsDelta = 1
							default:
								continue
							}
							d.ValueDelta = maximum
						}
					}
					b, err := MarshalReceiptCounterDelta(d)
					if err != nil {
						t.Fatal(err)
					}
					add("counter", fmt.Sprintf("mode-%d-action-%02x-success-%t", mode, action, success), b)
				}
			}
		}
		sponsored := &ReceiptCounterDelta{Version: 1, Mode: AuthModeDirect, ActionType: ActionTransfer, NonceDelta: 2, FeeDelta: Uint256FromUint64(17), Succeeded: true}
		b, err := MarshalReceiptCounterDelta(sponsored)
		if err != nil {
			t.Fatal(err)
		}
		add("counter", "sponsored", b)
		for typ := EventAuthorizationActivated; typ <= EventRecoveryFinalized; typ++ {
			e := &AuthorizationEvent{Version: 1, Type: typ, Owner: types.Address{19: 1}, GrantID: types.Hash{31: 2}, RootConfigHash: types.Hash{31: 3}, PolicyHash: types.Hash{31: 4}, AuthEpoch: ^uint64(0), RootNonce: ^uint64(0), SessionNonce: ^uint64(0), BlockHeight: ^uint64(0), TransactionID: types.Hash{31: 5}, AmountA: maximum, AmountB: maximum, ActionStatus: 1}
			if typ == EventSessionGrantReplaced {
				e.RelatedID = types.Hash{31: 6}
			}
			if typ == EventSessionGrantCleaned || typ >= EventRecoveryConfigured {
				e.Actor = types.Address{19: 7}
			}
			native, err := MarshalAuthorizationEvent(e)
			if err != nil {
				t.Fatal(err)
			}
			add("event", fmt.Sprintf("event-%04x", typ), native.Data)
		}
		for action := ActionTransfer; action <= ActionSessionCancel; action++ {
			v := &SessionAuthorizationDecision{sender: types.Address{19: 1}, intentHash: types.Hash{31: 2}, grantID: types.Hash{31: 3}, authEpoch: ^uint64(0), sessionNonce: ^uint64(0), policyHash: types.Hash{31: 4}, actionType: action, maximumFee: maximum, maximumDebit: maximum, reservedValue: maximum, evaluationHeight: ^uint64(0)}
			switch action {
			case ActionTransfer, ActionContractCall, ActionContractCreate:
				v.valueCategory = ValueAccountingExternalSpend
			case ActionStake:
				v.valueCategory = ValueAccountingStakeLock
			case ActionUnstake:
				v.valueCategory = ValueAccountingUnlock
			case ActionDelegate:
				v.valueCategory = ValueAccountingDelegationLock
			case ActionClaimRewards:
				v.valueCategory = ValueAccountingRewardClaim
			}
			if action == ActionContractCall || action == ActionContractCreate {
				v.matchedRulePresent = true
				v.matchedRuleIndex = 65535
			}
			if action == ActionContractCall {
				v.constraintCount = 65535
				v.inspectedCalldataBytes = ^uint32(0)
				v.targetCodePresent = true
				v.targetCodeAddress = types.Address{19: 5}
				v.targetCodeDependency = types.Hash{31: 6}
			}
			if action == ActionContractCreate {
				v.maxRuntimeCodeLength = ^uint32(0)
			}
			if action == ActionTransfer || action == ActionDelegate {
				v.merkleProofNodes = 255
			}
			v.feeBucketPresent = true
			v.valueBucketPresent = true
			v.refilledFeeBucket = TokenBucketState{Available: maximum, LastRefillHeight: ^uint64(0)}
			v.refilledValueBucket = v.refilledFeeBucket
			add("decision", fmt.Sprintf("action-%02x", action), sdkDecisionEncoding(v))
		}
		output = fixtures
	}
	b, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("RSC_RECEIPT_OUTPUT")
	if path == "" {
		t.Fatal("RSC_RECEIPT_OUTPUT required")
	}
	if err = os.WriteFile(path, append(b, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
