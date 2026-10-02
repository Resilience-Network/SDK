// Differential oracle: compiled against the immutable external Chain checkout.
// It is a test tool and is never shipped in the SDK package.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"

	sa "github.com/resilience-network/chain/pkg/sessionauth"
	"github.com/resilience-network/chain/pkg/types"
)

type Request struct {
	Kind    string `json:"kind"`
	Hex     string `json:"hex"`
	Genesis string `json:"genesis"`
	ChainID string `json:"chainId"`
	Owner   string `json:"owner"`
}
type Result struct {
	Accepted  bool              `json:"accepted"`
	Canonical string            `json:"canonical,omitempty"`
	Hashes    map[string]string `json:"hashes,omitempty"`
	Error     string            `json:"error,omitempty"`
}

func decode(value string) ([]byte, error) {
	if len(value) < 2 || value[:2] != "0x" {
		return nil, fmt.Errorf("hex prefix")
	}
	return hex.DecodeString(value[2:])
}
func hx(value []byte) string { return "0x" + hex.EncodeToString(value) }
func do(request Request) Result {
	input, err := decode(request.Hex)
	if err != nil {
		return Result{Error: err.Error()}
	}
	var canonical []byte
	hashes := map[string]string{}
	chainID, err := strconv.ParseUint(request.ChainID, 10, 64)
	if err != nil {
		return Result{Error: err.Error()}
	}
	genesis, err := types.HashFromHex(request.Genesis)
	if err != nil {
		return Result{Error: err.Error()}
	}
	ctx := sa.ChainContext{ChainID: chainID, GenesisHash: genesis}
	put := func(name string, hash types.Hash, e error) {
		if e != nil {
			hashes[name+"Error"] = e.Error()
			return
		}
		hashes[name] = hash.Hex()
	}
	switch request.Kind {
	case "hashes":
		canonical = input
		id, e := types.HashFromHex(request.Hex)
		if e != nil {
			err = e
			break
		}
		owner, e := types.AddressFromHex(request.Owner)
		if e != nil {
			err = e
			break
		}
		hashes["meta"] = sa.AuthorizationMetaKey().Hex()
		hashes["recovery"] = sa.AuthorizationRecoveryKey().Hex()
		h, e := sa.AuthorizationGrantKey(id)
		put("grantKey", h, e)
		h, e = sa.AuthorizationActiveKey(1, id)
		put("activeKey", h, e)
		h, e = sa.RecipientLeafHash(ctx, sa.ActionTransfer, owner)
		put("leaf", h, e)
		h, e = sa.RecipientEmptyLeafHash(ctx, sa.ActionTransfer, ^uint32(0))
		put("empty", h, e)
		h, e = sa.RecipientNodeHash(ctx, sa.ActionTransfer, id, id)
		put("node", h, e)
		h, e = sa.ValidatorConsensusKeyHash(input)
		put("validator", h, e)
	case "intent":
		var v *sa.TxIntent
		v, err = sa.UnmarshalTxIntent(input)
		if err == nil {
			canonical, err = sa.MarshalTxIntent(v)
			h, e := sa.IntentHash(ctx, v)
			put("intentHash", h, e)
		}
	case "envelope":
		var v *sa.AuthEnvelope
		v, err = sa.UnmarshalAuthEnvelope(input)
		if err == nil {
			canonical, err = sa.MarshalAuthEnvelope(v)
		}
	case "transaction":
		var i *sa.TxIntent
		var e *sa.AuthEnvelope
		i, e, err = sa.UnmarshalTransaction(input)
		if err == nil {
			canonical, err = sa.MarshalTransaction(i, e)
			h, x := sa.TransactionID(ctx, i, e)
			put("transactionId", h, x)
			switch e.Mode {
			case sa.AuthModeDirect:
				h, x = sa.DirectDigest(ctx, i, e.Nonce)
				put("digest", h, x)
			case sa.AuthModeRoot:
				h, x = sa.RootDigest(ctx, i, e.CredentialID, e.AuthEpoch, e.Nonce)
				put("digest", h, x)
			case sa.AuthModeSession:
				h, x = sa.SessionDigest(ctx, i, sa.SessionCredential{GrantID: e.CredentialID, AuthEpoch: e.AuthEpoch, PolicyHash: e.PolicyHash, Nonce: e.Nonce})
				put("digest", h, x)
			}
			if i.Sponsored() {
				h, x = sa.SponsorDigest(ctx, i, i.Sponsor, e.SponsorNonce)
				put("sponsorDigest", h, x)
			}
		}
	case "policy":
		var v *sa.Policy
		v, err = sa.UnmarshalPolicy(input)
		if err == nil {
			canonical, err = sa.MarshalPolicy(v)
			h, e := sa.PolicyHash(v)
			put("policyHash", h, e)
		}
	case "root":
		var v *sa.RootConfig
		v, err = sa.UnmarshalRootConfig(input)
		if err == nil {
			canonical, err = sa.MarshalRootConfig(v)
			h, e := sa.RootConfigHash(v)
			put("rootConfigHash", h, e)
			for index, key := range v.Keys {
				hashes[fmt.Sprint("rootKeyId", index)] = sa.RootKeyID(key).Hex()
			}
		}
	case "create":
		var v *sa.CreateGrantActionData
		v, err = sa.UnmarshalCreateGrantActionData(input)
		if err == nil {
			canonical, err = sa.MarshalCreateGrantActionData(v)
			h, e := sa.SessionKeyFingerprint(v.Grant.KeyScheme, v.Grant.PublicKey)
			put("fingerprint", h, e)
			owner, e := types.AddressFromHex(request.Owner)
			if e != nil {
				err = e
			} else {
				h, e = sa.GrantID(ctx, owner, 1, 0, v.Grant.KeyScheme, v.Grant.PublicKey)
				put("grantId", h, e)
			}
		}
	case "activate":
		var v *sa.ActivateAuthorizationActionData
		v, err = sa.UnmarshalActivateAuthorizationActionData(input)
		if err == nil {
			canonical, err = sa.MarshalActivateAuthorizationActionData(v)
		}
	case "revoke":
		var v *sa.RevokeGrantActionData
		v, err = sa.UnmarshalRevokeGrantActionData(input)
		if err == nil {
			canonical, err = sa.MarshalRevokeGrantActionData(v)
		}
	case "replace":
		var v *sa.ReplaceGrantActionData
		v, err = sa.UnmarshalReplaceGrantActionData(input)
		if err == nil {
			canonical, err = sa.MarshalReplaceGrantActionData(v)
		}
	case "rotate":
		var v *sa.RotateRootActionData
		v, err = sa.UnmarshalRotateRootActionData(input)
		if err == nil {
			canonical, err = sa.MarshalRotateRootActionData(v)
		}
	case "reserve":
		var v *sa.SetSecurityReserveActionData
		v, err = sa.UnmarshalSetSecurityReserveActionData(input)
		if err == nil {
			canonical, err = sa.MarshalSetSecurityReserveActionData(v)
		}
	case "cleanup":
		var v *sa.CleanupGrantActionData
		v, err = sa.UnmarshalCleanupGrantActionData(input)
		if err == nil {
			canonical, err = sa.MarshalCleanupGrantActionData(v)
		}
	case "proof":
		var v *sa.RecipientProof
		v, err = sa.UnmarshalRecipientProof(input)
		if err == nil {
			canonical, err = sa.MarshalRecipientProof(v)
		}
	case "sessionWitness":
		var v *sa.SessionWitness
		v, err = sa.UnmarshalSessionWitness(input)
		if err == nil {
			canonical, err = sa.MarshalSessionWitness(v)
		}
	default:
		err = fmt.Errorf("unknown test kind")
	}
	if err != nil {
		return Result{Error: err.Error()}
	}
	return Result{Accepted: true, Canonical: hx(canonical), Hashes: hashes}
}

func fixtures() {
	// Read the independent source fixture for identities; encode missing scenarios
	// directly with Go structs so the SDK cannot define its own expected layout.
	var vectors struct {
		Root struct {
			Threshold       uint16
			SortedKeys      []struct{ PublicKey string }
			SecurityReserve string
		}
		Policy      struct{ Canonical string }
		Keys        struct{ Owner string }
		CreateGrant struct {
			ActionData     string
			DerivedGrantID string
		}
	}
	f, err := os.Open("reference/sessionauth/vectors/v1.json")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err = json.NewDecoder(f).Decode(&vectors); err != nil {
		panic(err)
	}
	config := sa.RootConfig{Version: 1, Threshold: vectors.Root.Threshold}
	for _, key := range vectors.Root.SortedKeys {
		b, e := decode(key.PublicKey)
		if e != nil {
			panic(e)
		}
		var k sa.RootKey
		k.KeyScheme = sa.KeySchemeEd25519
		copy(k.PublicKey[:], b)
		config.Keys = append(config.Keys, k)
	}
	reserveBig, ok := new(big.Int).SetString(vectors.Root.SecurityReserve, 10)
	if !ok {
		panic("invalid reserve fixture")
	}
	reserve, err := sa.Uint256FromBig(reserveBig)
	if err != nil {
		panic(err)
	}
	grantBytes, err := decode(vectors.CreateGrant.ActionData)
	if err != nil {
		panic(err)
	}
	create, err := sa.UnmarshalCreateGrantActionData(grantBytes)
	if err != nil {
		panic(err)
	}
	id, err := types.HashFromHex(vectors.CreateGrant.DerivedGrantID)
	if err != nil {
		panic(err)
	}
	owner, err := types.AddressFromHex(vectors.Keys.Owner)
	if err != nil {
		panic(err)
	}
	output := map[string]string{}
	put := func(name string, b []byte, e error) {
		if e != nil {
			panic(e)
		}
		output[name] = hx(b)
	}
	b, e := sa.MarshalActivateAuthorizationActionData(&sa.ActivateAuthorizationActionData{Version: 1, Config: config, SecurityReserve: reserve})
	put("activate", b, e)
	b, e = sa.MarshalRevokeGrantActionData(&sa.RevokeGrantActionData{Version: 1, GrantID: id})
	put("revoke", b, e)
	b, e = sa.MarshalReplaceGrantActionData(&sa.ReplaceGrantActionData{Version: 1, OldGrantID: id, NewGrant: create.Grant})
	put("replace", b, e)
	b, e = sa.MarshalRotateRootActionData(&sa.RotateRootActionData{Version: 1, Config: config, ReserveMode: sa.ReservePreserve})
	put("rotate0", b, e)
	hundred := sa.Uint256FromUint64(100)
	b, e = sa.MarshalRotateRootActionData(&sa.RotateRootActionData{Version: 1, Config: config, ReserveMode: sa.ReserveReplace, ReplacementReserve: hundred})
	put("rotate1", b, e)
	b, e = sa.MarshalSetSecurityReserveActionData(&sa.SetSecurityReserveActionData{Version: 1})
	put("reserve", b, e)
	b, e = sa.MarshalCleanupGrantActionData(&sa.CleanupGrantActionData{Version: 1, Owner: owner, GrantID: id})
	put("cleanup", b, e)
	if err = json.NewEncoder(os.Stdout).Encode(output); err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "fixtures" {
		fixtures()
		return
	}
	var requests []Request
	if err := json.NewDecoder(os.Stdin).Decode(&requests); err != nil {
		panic(err)
	}
	results := make([]Result, len(requests))
	for i, r := range requests {
		results[i] = do(r)
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		panic(err)
	}
}
