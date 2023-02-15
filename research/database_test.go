package research

import (
	"log"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/research/contract"
)

var (
	chainId = big.NewInt(1337)
)

func TestDatabase(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	auth := bind.NewKeyedTransactor(privateKey)

	balance := new(big.Int)
	balance.SetString("10000000000000000000", 10) // 10 eth in wei

	address := auth.From
	genesisAlloc := map[common.Address]core.GenesisAccount{
		address: {
			Balance: balance,
		},
	}

	blockGasLimit := uint64(4712388)
	client := backends.NewSimulatedBackend(genesisAlloc, blockGasLimit)
	opts, _ := bind.NewKeyedTransactorWithChainID(privateKey, chainId)

	testAddress, _, testContract, err := contract.DeployTest(opts, client)
	if err != nil {
		t.Fatal(err)
	}
	log.Println(testAddress)
	client.Commit()

	out, err := testContract.A(&bind.CallOpts{})
	if err != nil {
		t.Fatal(err)
	}
	log.Println(out)
}
