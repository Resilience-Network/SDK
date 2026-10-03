// Test-only oracle. Fixed keys are public test fixtures, never wallet keys.
// Built against production verification at protocol-source.json's immutable pin.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"

	sa "github.com/resilience-network/chain/pkg/sessionauth"
	"github.com/resilience-network/chain/pkg/types"
)

type request struct {
	Operation   string `json:"operation"`
	Scheme      uint8  `json:"scheme"`
	Seed        uint8  `json:"seed"`
	Digest      string `json:"digest"`
	Transaction string `json:"transaction"`
	Root        string `json:"root"`
	Genesis     string `json:"genesis"`
	ChainID     string `json:"chainId"`
	Nonce       string `json:"nonce"`
	Epoch       string `json:"epoch"`
	GrantID     string `json:"grantId"`
	PolicyHash  string `json:"policyHash"`
	PublicKey   string `json:"publicKey"`
}
type result struct {
	Accepted  bool   `json:"accepted"`
	PublicKey string `json:"publicKey,omitempty"`
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

func decode(value string) ([]byte, error) {
	if len(value) < 2 || value[:2] != "0x" {
		return nil, fmt.Errorf("missing hex prefix")
	}
	return hex.DecodeString(value[2:])
}
func hx(value []byte) string { return "0x" + hex.EncodeToString(value) }
func sign(r request) (result, error) {
	digest, err := decode(r.Digest)
	if err != nil || len(digest) != 32 {
		return result{}, fmt.Errorf("digest must be 32 bytes")
	}
	if r.Scheme == 1 {
		seed := make([]byte, 32)
		for i := range seed {
			seed[i] = r.Seed
		}
		key := ed25519.NewKeyFromSeed(seed)
		return result{Accepted: true, PublicKey: hx(key.Public().(ed25519.PublicKey)), Signature: hx(ed25519.Sign(key, digest))}, nil
	}
	if r.Scheme != 2 {
		return result{}, fmt.Errorf("unsupported signing scheme")
	}
	d := big.NewInt(7)
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	rScalar, sScalar, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return result{}, err
	}
	publicKey, signature := make([]byte, 64), make([]byte, 64)
	x.FillBytes(publicKey[:32])
	y.FillBytes(publicKey[32:])
	rScalar.FillBytes(signature[:32])
	sScalar.FillBytes(signature[32:])
	return result{Accepted: true, PublicKey: hx(publicKey), Signature: hx(signature)}, nil
}
func verify(r request) error {
	wire, err := decode(r.Transaction)
	if err != nil {
		return err
	}
	intent, envelope, err := sa.UnmarshalTransaction(wire)
	if err != nil {
		return err
	}
	chainID, err := strconv.ParseUint(r.ChainID, 10, 64)
	if err != nil {
		return err
	}
	genesis, err := types.HashFromHex(r.Genesis)
	if err != nil {
		return err
	}
	nonce, err := strconv.ParseUint(r.Nonce, 10, 64)
	if err != nil {
		return err
	}
	context := sa.ChainContext{ChainID: chainID, GenesisHash: genesis}
	switch envelope.Mode {
	case sa.AuthModeDirect:
		return sa.VerifyDirectAuthorization(context, intent, envelope, nonce)
	case sa.AuthModeRoot:
		root, err := decode(r.Root)
		if err != nil {
			return err
		}
		config, err := sa.UnmarshalRootConfig(root)
		if err != nil {
			return err
		}
		epoch, err := strconv.ParseUint(r.Epoch, 10, 64)
		if err != nil {
			return err
		}
		return sa.VerifyRootAuthorization(context, intent, envelope, config, epoch, nonce)
	case sa.AuthModeSession:
		epoch, err := strconv.ParseUint(r.Epoch, 10, 64)
		if err != nil {
			return err
		}
		grant, err := types.HashFromHex(r.GrantID)
		if err != nil {
			return err
		}
		policy, err := types.HashFromHex(r.PolicyHash)
		if err != nil {
			return err
		}
		key, err := decode(r.PublicKey)
		if err != nil {
			return err
		}
		if (r.Scheme == 1 && len(key) != 32) || (r.Scheme == 2 && len(key) != 64) {
			return fmt.Errorf("public key width")
		}
		credential := sa.SessionCredential{GrantID: grant, AuthEpoch: epoch, PolicyHash: policy, Nonce: nonce, KeyScheme: sa.KeyScheme(r.Scheme)}
		copy(credential.PublicKey[:], key)
		if err := sa.ValidateSessionPublicKey(credential.KeyScheme, credential.PublicKey); err != nil {
			return err
		}
		return sa.VerifySessionAuthorization(context, intent, envelope, credential)
	default:
		return fmt.Errorf("unsupported mode")
	}
}
func main() {
	var requests []request
	if err := json.NewDecoder(os.Stdin).Decode(&requests); err != nil {
		panic(err)
	}
	results := make([]result, len(requests))
	for i, r := range requests {
		if r.Operation == "sign" {
			value, err := sign(r)
			if err != nil {
				results[i] = result{Error: err.Error()}
			} else {
				results[i] = value
			}
		} else if r.Operation == "verify" {
			if err := verify(r); err != nil {
				results[i] = result{Error: err.Error()}
			} else {
				results[i] = result{Accepted: true}
			}
		} else {
			results[i] = result{Error: "unknown operation"}
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		panic(err)
	}
}
