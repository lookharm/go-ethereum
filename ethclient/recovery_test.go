package ethclient

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

func Test_GetAddress(t *testing.T) {
	client, err := Dial("https://speedy-nodes-nyc.moralis.io/01e82deb83b506fe65db24e6/eth/ropsten")
	if err != nil {
		log.Fatal(err)
	}

	txHash := common.HexToHash("0x39e1e6cc82d09edc4c57117e3edec46e92f25acd00f2015f07e55dc0e0678154")

	tx, _, err := client.TransactionByHash(context.Background(), txHash)
	if err != nil {
		log.Fatal(err)
	}
	// address, err := client.TransactionSender(context.TODO(), tx, common.HexToHash("0x487183cd9eed0970dab843c9ebd577e6af3e1eb7c9809d240c8735eab7cb43de"), 7)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println(address)
	// fmt.Println("isPending:", isPending)
	// fmt.Println("hash:", tx.Hash())
	// fmt.Println("to:", tx.To().Hash())
	// fmt.Println("chainID:", tx.ChainId())

	var sigingData bytes.Buffer
	txData := []interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
		tx.ChainId(), uint(0), uint(0),
	}
	err = rlp.Encode(&sigingData, txData)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("sigingData: %x\n", sigingData.Bytes())
	sighash := crypto.Keccak256(sigingData.Bytes())

	fmt.Printf("sighash: %x\n", sighash)

	Vb, R, S := tx.RawSignatureValues()
	V := byte(Vb.Int64())

	fmt.Println("valid: ", crypto.ValidateSignatureValues(V, R, S, false))

	// encode the signature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	sig := make([]byte, crypto.SignatureLength)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V
	// recover the public key from the signature
	pubBytes, err := crypto.Ecrecover(sighash[:], sig)

	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(pubBytes)

	fmt.Printf("%x\n", pubBytes[:1])
	fmt.Printf("%x\n", pubBytes[1:33])
	fmt.Printf("%x\n", pubBytes[33:])

	fmt.Println(crypto.Keccak256Hash(pubBytes))

	pub, err := crypto.SigToPub(sighash, sig)
	fmt.Println(pub.X.Bytes())
	ok := crypto.VerifySignature(pubBytes, sighash, sig)
	fmt.Println(ok)
}
