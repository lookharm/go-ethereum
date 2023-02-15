// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package crypto

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/holiman/uint256"
)

var testAddrHex = "970e8128ab834e8eac17ab8e3812f010678cf791"
var testPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"

// These tests are sanity checks.
// They should ensure that we don't e.g. use Sha3-224 instead of Sha3-256
// and that the sha3 library uses keccak-f permutation.
func TestKeccak256Hash(t *testing.T) {
	msg := []byte("abc")
	exp, _ := hex.DecodeString("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
	checkhash(t, "Sha3-256-array", func(in []byte) []byte { h := Keccak256Hash(in); return h[:] }, msg, exp)
}

func TestKeccak256Hasher(t *testing.T) {
	msg := []byte("abc")
	exp, _ := hex.DecodeString("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
	hasher := NewKeccakState()
	checkhash(t, "Sha3-256-array", func(in []byte) []byte { h := HashData(hasher, in); return h[:] }, msg, exp)
}

func TestToECDSAErrors(t *testing.T) {
	if _, err := HexToECDSA("0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("HexToECDSA should've returned error")
	}
	if _, err := HexToECDSA("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); err == nil {
		t.Fatal("HexToECDSA should've returned error")
	}
}

func BenchmarkSha3(b *testing.B) {
	a := []byte("hello world")
	for i := 0; i < b.N; i++ {
		Keccak256(a)
	}
}

func TestUnmarshalPubkey(t *testing.T) {
	key, err := UnmarshalPubkey(nil)
	if err != errInvalidPubkey || key != nil {
		t.Fatalf("expected error, got %v, %v", err, key)
	}
	key, err = UnmarshalPubkey([]byte{1, 2, 3})
	if err != errInvalidPubkey || key != nil {
		t.Fatalf("expected error, got %v, %v", err, key)
	}

	var (
		enc, _ = hex.DecodeString("04760c4460e5336ac9bbd87952a3c7ec4363fc0a97bd31c86430806e287b437fd1b01abc6e1db640cf3106b520344af1d58b00b57823db3e1407cbc433e1b6d04d")
		dec    = &ecdsa.PublicKey{
			Curve: S256(),
			X:     hexutil.MustDecodeBig("0x760c4460e5336ac9bbd87952a3c7ec4363fc0a97bd31c86430806e287b437fd1"),
			Y:     hexutil.MustDecodeBig("0xb01abc6e1db640cf3106b520344af1d58b00b57823db3e1407cbc433e1b6d04d"),
		}
	)
	key, err = UnmarshalPubkey(enc)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !reflect.DeepEqual(key, dec) {
		t.Fatal("wrong result")
	}
}

func TestSign(t *testing.T) {
	key, _ := HexToECDSA(testPrivHex)
	addr := common.HexToAddress(testAddrHex)

	msg := Keccak256([]byte("foo"))
	sig, err := Sign(msg, key)
	if err != nil {
		t.Errorf("Sign error: %s", err)
	}
	recoveredPub, err := Ecrecover(msg, sig)
	if err != nil {
		t.Errorf("ECRecover error: %s", err)
	}
	pubKey, _ := UnmarshalPubkey(recoveredPub)
	recoveredAddr := PubkeyToAddress(*pubKey)
	if addr != recoveredAddr {
		t.Errorf("Address mismatch: want: %x have: %x", addr, recoveredAddr)
	}

	// should be equal to SigToPub
	recoveredPub2, err := SigToPub(msg, sig)
	if err != nil {
		t.Errorf("ECRecover error: %s", err)
	}
	recoveredAddr2 := PubkeyToAddress(*recoveredPub2)
	if addr != recoveredAddr2 {
		t.Errorf("Address mismatch: want: %x have: %x", addr, recoveredAddr2)
	}
}

func TestInvalidSign(t *testing.T) {
	if _, err := Sign(make([]byte, 1), nil); err == nil {
		t.Errorf("expected sign with hash 1 byte to error")
	}
	if _, err := Sign(make([]byte, 33), nil); err == nil {
		t.Errorf("expected sign with hash 33 byte to error")
	}
}

func TestNewContractAddress(t *testing.T) {
	key, _ := HexToECDSA(testPrivHex)
	addr := common.HexToAddress(testAddrHex)
	genAddr := PubkeyToAddress(key.PublicKey)
	// sanity check before using addr to create contract address
	checkAddr(t, genAddr, addr)

	caddr0 := CreateAddress(addr, 0)
	caddr1 := CreateAddress(addr, 1)
	caddr2 := CreateAddress(addr, 2)
	checkAddr(t, common.HexToAddress("333c3310824b7c685133f2bedb2ca4b8b4df633d"), caddr0)
	checkAddr(t, common.HexToAddress("8bda78331c916a08481428e4b07c96d3e916d165"), caddr1)
	checkAddr(t, common.HexToAddress("c9ddedf451bc62ce88bf9292afb13df35b670699"), caddr2)
}

func Test_CraeteAddress(t *testing.T) {
	addr1 := CreateAddress(common.HexToAddress("94a1eeea2a7bbc995f884540963e2e59d068cbfb"), 1)
	fmt.Println(addr1.Hex())
	addr2 := CreateAddress(common.HexToAddress("94a1eeea2a7bbc995f884540963e2e59d068cbfb"), 2)
	fmt.Println(addr2.Hex())
	addr3 := CreateAddress(common.HexToAddress("94a1eeea2a7bbc995f884540963e2e59d068cbfb"), 3)
	fmt.Println(addr3.Hex())
}

func Test_BruteAddr(t *testing.T) {
	var wg sync.WaitGroup

	done := make(chan struct{})
	count := 0
	var mu sync.Mutex
	for i := 0; i < 100; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			for {
				privateKey, err := GenerateKey()
				if err != nil {
					log.Println("err: ", err)
				}
				address := PubkeyToAddress(privateKey.PublicKey)
				// fmt.Println(address)
				contractAddress := CreateAddress(address, 0)
				if strings.ToLower(contractAddress.Hex())[33:] == "badc0de" {
					fmt.Println("found!!! ", "address: ", address, hexutil.Encode(FromECDSA(privateKey)), contractAddress, "nonce: ", 0)
					done <- struct{}{}
					break
				}

				mu.Lock()
				count++
				if count%100000 == 0 {
					fmt.Println("count: ", count)
				}
				mu.Unlock()

				select {
				case <-done:
					break
				default:
				}
			}
		}()
	}
	wg.Wait()
}

func TestPrint(t *testing.T) {
	// privateKey, err := GenerateKey()
	// if err != nil {
	// 	log.Println("err: ", err)
	// }
	// address := PubkeyToAddress(privateKey.PublicKey)

	// fmt.Println("found!!! ", "address: ", address, hexutil.Encode(FromECDSA(privateKey)))
	// if "000000000000000000000000000000000badc0de"[33:] == "badc0de" {
	// 	fmt.Println("ok")
	// }

	factoryAddress := common.HexToAddress("0xffca4dfd86a86c48c5d9c228bedbeb7f218a29c94b")
	initHash := common.Hex2Bytes("4670da3f633e838c2746ca61c370ba3dbd257b86b28b78449f4185480e2aba51")

	salt, _ := uint256.FromBig(big.NewInt(5975038))
	contractAddress := CreateAddress2(factoryAddress, salt.Bytes32(), initHash)
	if strings.ToLower(contractAddress.Hex())[35:] == "badc0de" {
		fmt.Println(contractAddress)
	}
}

func TestCreateAddress2(t *testing.T) {
	startTime := time.Now()
	var (
		start        int64 = 0
		limit        int64 = math.MaxInt64
		interval     int64 = 1000000
		maxGoroutint int   = 20
	)

	var wg sync.WaitGroup
	factoryAddress := common.HexToAddress("ac801268f41189a9c1e352347C53A4966687Ef2c")
	codeBytes := common.Hex2Bytes("608060405234801561001057600080fd5b50610243806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c806306fdde031461003b578063d018db3e14610059575b600080fd5b61004361009d565b6040518082815260200191505060405180910390f35b61009b6004803603602081101561006f57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506100c5565b005b60007f736d617278000000000000000000000000000000000000000000000000000000905090565b60008173ffffffffffffffffffffffffffffffffffffffff166040516024016040516020818303038152906040527f380c7a67000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050506040518082805190602001908083835b602083106101945780518252602082019150602081019050602083039250610171565b6001836020036101000a0380198251168184511680821785525050505050509050019150506000604051808303816000865af19150503d80600081146101f6576040519150601f19603f3d011682016040523d82523d6000602084013e6101fb565b606091505b505090508061020957600080fd5b505056fea2646970667358221220867041414c1dae36666057fa3a823c3ff1fd2f922d5b1548ad0ed009ea9f783064736f6c634300060c0033")
	initHash := Keccak256Hash(codeBytes).Bytes()

	// salt, _ := uint256.FromBig(big.NewInt(140083175))
	// contractAddress := CreateAddress2(factoryAddress, salt.Bytes32(), initHash)
	// fmt.Println(contractAddress)

	f := bufio.NewWriter(os.Stdout)
	found := false
	for i, j := start, 1; i <= limit && !found; i, j = i+interval, j+1 {
		if j%maxGoroutint == 0 {
			wg.Wait()
			j = 1
		}
		wg.Add(1)
		go func(start, limit int64) {
			defer wg.Done()
			var i int64 = start
			for i <= limit && !found {
				salt, _ := uint256.FromBig(big.NewInt(i))
				contractAddress := CreateAddress2(factoryAddress, salt.Bytes32(), initHash)

				if strings.ToLower(contractAddress.Hex())[35:] == "badc0de" {
					fmt.Println("found!!! ", "contractAddress: ", contractAddress, "salt: ", salt, time.Since(startTime))
					found = true
				}
				i++
			}

			fmt.Fprintf(f, "%v - %v: %v\n", start, limit, time.Since(startTime))
			f.Flush()
		}(i, i+interval)
	}

	wg.Wait()
}

func Test_BrutePublicKey(t *testing.T) {
	startTime := time.Now()
	var (
		start        int64 = 0
		limit        int64 = math.MaxInt64
		interval     int64 = 1000000
		maxGoroutint int   = 20
	)

	var wg sync.WaitGroup
	address := common.HexToAddress("92b28647ae1f3264661f72fb2eb9625a89d88a31")

	found := false
	for i, j := start, 1; i <= limit && !found; i, j = i+interval, j+1 {
		if j%maxGoroutint == 0 {
			wg.Wait()
			j = 1
		}
		wg.Add(1)
		go func(start, limit int64) {
			defer wg.Done()
			var i int64 = start
			for i <= limit && !found {
				salt, _ := uint256.FromBig(big.NewInt(i))
				_address := common.BytesToAddress(Keccak256(salt.Bytes()))

				if address == _address {
					println("found!!! ", "salt: ", salt, time.Since(startTime))
					found = true
				}
				i++
			}

			println(start, "-", limit, time.Since(startTime))
		}(i, i+interval)
	}

	wg.Wait()
}

func TestLoadECDSA(t *testing.T) {
	tests := []struct {
		input string
		err   string
	}{
		// good
		{input: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{input: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"},
		{input: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\r"},
		{input: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"},
		{input: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\n"},
		{input: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\r"},
		// bad
		{
			input: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			err:   "key file too short, want 64 hex characters",
		},
		{
			input: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde\n",
			err:   "key file too short, want 64 hex characters",
		},
		{
			input: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeX",
			err:   "invalid hex character 'X' in private key",
		},
		{
			input: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefX",
			err:   "invalid character 'X' at end of key file",
		},
		{
			input: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\n\n",
			err:   "key file too long, want 64 hex characters",
		},
	}

	for _, test := range tests {
		f, err := ioutil.TempFile("", "loadecdsa_test.*.txt")
		if err != nil {
			t.Fatal(err)
		}
		filename := f.Name()
		f.WriteString(test.input)
		f.Close()

		_, err = LoadECDSA(filename)
		switch {
		case err != nil && test.err == "":
			t.Fatalf("unexpected error for input %q:\n  %v", test.input, err)
		case err != nil && err.Error() != test.err:
			t.Fatalf("wrong error for input %q:\n  %v", test.input, err)
		case err == nil && test.err != "":
			t.Fatalf("LoadECDSA did not return error for input %q", test.input)
		}
	}
}

func TestSaveECDSA(t *testing.T) {
	f, err := ioutil.TempFile("", "saveecdsa_test.*.txt")
	if err != nil {
		t.Fatal(err)
	}
	file := f.Name()
	f.Close()
	defer os.Remove(file)

	key, _ := HexToECDSA(testPrivHex)
	if err := SaveECDSA(file, key); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadECDSA(file)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(key, loaded) {
		t.Fatal("loaded key not equal to saved key")
	}
}

func TestValidateSignatureValues(t *testing.T) {
	check := func(expected bool, v byte, r, s *big.Int) {
		if ValidateSignatureValues(v, r, s, false) != expected {
			t.Errorf("mismatch for v: %d r: %d s: %d want: %v", v, r, s, expected)
		}
	}
	minusOne := big.NewInt(-1)
	one := common.Big1
	zero := common.Big0
	secp256k1nMinus1 := new(big.Int).Sub(secp256k1N, common.Big1)

	// correct v,r,s
	check(true, 0, one, one)
	check(true, 1, one, one)
	// incorrect v, correct r,s,
	check(false, 2, one, one)
	check(false, 3, one, one)

	// incorrect v, combinations of incorrect/correct r,s at lower limit
	check(false, 2, zero, zero)
	check(false, 2, zero, one)
	check(false, 2, one, zero)
	check(false, 2, one, one)

	// correct v for any combination of incorrect r,s
	check(false, 0, zero, zero)
	check(false, 0, zero, one)
	check(false, 0, one, zero)

	check(false, 1, zero, zero)
	check(false, 1, zero, one)
	check(false, 1, one, zero)

	// correct sig with max r,s
	check(true, 0, secp256k1nMinus1, secp256k1nMinus1)
	// correct v, combinations of incorrect r,s at upper limit
	check(false, 0, secp256k1N, secp256k1nMinus1)
	check(false, 0, secp256k1nMinus1, secp256k1N)
	check(false, 0, secp256k1N, secp256k1N)

	// current callers ensures r,s cannot be negative, but let's test for that too
	// as crypto package could be used stand-alone
	check(false, 0, minusOne, one)
	check(false, 0, one, minusOne)
}

func checkhash(t *testing.T, name string, f func([]byte) []byte, msg, exp []byte) {
	sum := f(msg)
	if !bytes.Equal(exp, sum) {
		t.Fatalf("hash %s mismatch: want: %x have: %x", name, exp, sum)
	}
}

func checkAddr(t *testing.T, addr0, addr1 common.Address) {
	if addr0 != addr1 {
		t.Fatalf("address mismatch: want: %x have: %x", addr0, addr1)
	}
}

// test to help Python team with integration of libsecp256k1
// skip but keep it after they are done
func TestPythonIntegration(t *testing.T) {
	kh := "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"
	k0, _ := HexToECDSA(kh)

	msg0 := Keccak256([]byte("foo"))
	sig0, _ := Sign(msg0, k0)

	msg1 := common.FromHex("00000000000000000000000000000000")
	sig1, _ := Sign(msg0, k0)

	t.Logf("msg: %x, privkey: %s sig: %x\n", msg0, kh, sig0)
	t.Logf("msg: %x, privkey: %s sig: %x\n", msg1, kh, sig1)
}
