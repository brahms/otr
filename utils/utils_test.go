package utils

import (
	//"fmt"
	"crypto/rsa"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestGenerateDHP(t *testing.T) {
	assert.NotNil(t, diffie_p, "DHP should not be nil")
}

func TestGenerateBigInt(t *testing.T) {
	b := GenerateRandomBigInt(320)
	assert.Equal(t, 1, b.Cmp(big.NewInt(0)))
}

func TestDiffieExp(t *testing.T) {
	b := GenerateRandomBigInt(320)
	secret := DiffieExp(b)
	assert.Equal(t, 1, secret.Cmp(big.NewInt(0)))
}

func TestAes(t *testing.T) {
	key := GenerateRandomBytes(32)
	msg := "hello world"
	cipherText := AesEncrypt(key, []byte(msg))
	plainText := AesDecrypt(key, cipherText)
	assert.Equal(t, msg, string(plainText))
}

func TestHmac(t *testing.T) {
	key := GenerateRandomBytes(32)
	msg := GenerateRandomBytes(32)
	hmac := CreateHmac(msg, key)
	assert.True(t, VerifyHmac(msg, hmac, key))
}

var rsaKey *rsa.PrivateKey = GenerateRsaPrivateKey()

func TestCreateRsaPrivateKey(t *testing.T) {
	assert.NotNil(t, rsaKey)
}

func TestSignature(t *testing.T) {
	hmacKey := GenerateRandomBytes(32)
	msg := GenerateRandomBytes(32)
	sig := CreateSignature(msg, rsaKey, hmacKey)
	assert.True(t, VerifySignature(sig, msg, &rsaKey.PublicKey, hmacKey))
}

func TestHash(t *testing.T) {
	msg := GenerateRandomBytes(32)
	hash := CreateHash(msg)
	assert.True(t, VerifyHash(msg, hash))
}

func TestHash2(t *testing.T) {
	msg, err := hex.DecodeString("b89adeaaca026b55ff2558af380401cb1829cadfdad254452177e2ca1f12f3d40b40bf722a4d8b5ebdf25140fd221a779486862ac9dfe46e0e87e292b89f42c7098c3ab03ddb7ecd9dd46ee2fa18cdefe3e7fbcb0afb6bbd2b23f6c156e84a9eb804d36d92a45f7d17f0d47ea14fbfe34569ca61e69288ec8a85ba24a612c40b701a59cf8a19c379bae773148db47200b8101a34c5a983c64d8c04db88229658968743b533795380da569fb21773766160552f4b644f7372205e2607a034f9b40a3240ff998d690ce7a7040d802585fcd04451d0f8988a3f1745532749092036")
	assert.NoError(t, err)

	bytes, err := hex.DecodeString("34e720c270ad7c4b067f59bae94f43121024d56b517496f39ad1108a9d45c95e")
	assert.NoError(t, err)
	hexstr := CreateHash(msg)
	println(hex.EncodeToString(hexstr))
	assert.True(t, VerifyHash(msg, bytes))
}

func TestMarshalRsaPublicKey(t *testing.T) {
	key := rsaKey
	marshaled := MarshalRsaPublicKey(&key.PublicKey)
	assert.NotEmpty(t, marshaled)
	unmarshaled := UnmarshalRsaPublicKey(marshaled)
	assert.NotNil(t, unmarshaled)
	assert.Equal(t, &key.PublicKey, unmarshaled)
}
