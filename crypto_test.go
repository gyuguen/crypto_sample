package crypto_sample

import (
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/go-bip39"
	ecies "github.com/ecies/go"
	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	"log"
	"testing"
)

const (
	mnemonicEntropySize = 256
)

var msg = "My Test Data"

func TestCrypto(t *testing.T) {
	privKey := makePrivKeyWithSecp256K1()

	checkSecp256k1(t, privKey)

	checkEcies(t, privKey)
}

func makePrivKeyWithSecp256K1() []byte {
	entropySeed, err := bip39.NewEntropy(mnemonicEntropySize)
	if err != nil {
		panic(err)
	}
	mnemonic, err := bip39.NewMnemonic(entropySeed[:])
	if err != nil {
		panic(err)
	}
	log.Printf("Generated Mnemonic: %v\n", mnemonic)
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		panic(err)
	}
	hdPath := hd.NewFundraiserParams(0, 371, 0).String()
	masterPriv, chainCode := hd.ComputeMastersFromSeed(seed)
	privKey, err := hd.DerivePrivateKeyForPath(masterPriv, chainCode, hdPath)
	if err != nil {
		panic(err)
	}
	return privKey
}

func checkSecp256k1(t *testing.T, privKey []byte) {
	secp256PrivKey := secp256k1.GenPrivKeySecp256k1(privKey)
	pubKey := secp256PrivKey.PubKey()

	log.Printf("Secp256k1 test msg: %v\n", msg)
	signature, err := secp256PrivKey.Sign([]byte(msg))
	if err != nil {
		panic(err)
	}
	isValid := pubKey.VerifySignature([]byte(msg), signature)
	assert.True(t, isValid)
	log.Println("Secp256k1 test success.")
}

func checkEcies(t *testing.T, privKey []byte) {
	log.Printf("Ecies test msg: %v\n", msg)
	eciesPriv := ecies.NewPrivateKeyFromBytes(privKey)
	ciphertext, err := ecies.Encrypt(eciesPriv.PublicKey, []byte(msg))
	if err != nil {
		panic(err)
	}
	log.Printf("Ecies msg encrypted: %v\n", ciphertext)
	plaintext, err := ecies.Decrypt(eciesPriv, ciphertext)
	if err != nil {
		panic(err)
	}

	log.Printf("Ecies msg decrypted: %v\n", string(plaintext))

	assert.Equal(t, msg, string(plaintext))
	log.Println("Ecies test success.")
}
