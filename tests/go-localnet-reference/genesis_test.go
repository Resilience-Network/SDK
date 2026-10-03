package blockchain

import (
	"encoding/json"
	"github.com/resilience-network/chain/crypto"
	"github.com/resilience-network/chain/internal/db"
	"github.com/resilience-network/chain/internal/state"
	"math/big"
	"os"
	"testing"
)

// Independent native bootstrap oracle; uses the same canonical production
// genesis initialization contract, not an SDK JSON/header implementation.
func TestSDKOwnedGenesisIdentity(t *testing.T) {
	input, output := os.Getenv("RSC_SDK_GENESIS_INPUT"), os.Getenv("RSC_SDK_GENESIS_OUTPUT")
	if input == "" || output == "" {
		t.Fatal("owned input/output paths required")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	config, err := LoadGenesisConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	database := db.NewMemDB()
	defer database.Close()
	statedb := state.NewStateDB(database, crypto.ZeroHash)
	if err = ApplyGenesisState(statedb, config); err != nil {
		t.Fatal(err)
	}
	root, err := statedb.Commit()
	if err != nil {
		t.Fatal(err)
	}
	block, err := AssembleGenesisBlock(config, root, big.NewInt(1000000000))
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]any{"chainId": config.ChainID, "genesisHash": HashHeader(block.Header).Hex(), "stateRoot": root.Hex(), "protocolCommitment": config.ProtocolCommitment.Hex(), "minGasPrice": "1000000000"}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(output, encoded, 0600); err != nil {
		t.Fatal(err)
	}
}
