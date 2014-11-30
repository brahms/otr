package utils

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"github.com/op/go-logging"
	"math/big"
	"strings"
	"encoding/base64"

	"github.com/golang/protobuf/proto"
)

const (
	diffe_p_string = `FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF`
)

func generateDiffieP() *big.Int {
	temp := strings.Replace(diffe_p_string, "\n", "", -1)
	temp = strings.Replace(temp, " ", "", -1)
	bytes, err := hex.DecodeString(temp)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	diffie_p := new(big.Int).SetBytes(bytes)

	return diffie_p
}

var (
	log               = logging.MustGetLogger("brahms.otr.utils")
	diffie_p *big.Int = generateDiffieP()
	diffie_g *big.Int = big.NewInt(2)
)

func BitsToBytes(b int) int {
	assertValidBits(b)
	return b / 8
}

// GenerateRandomBytes returns securely generated random bytes.
func GenerateRandomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		log.Fatal("Unable to create secure random bytes")
	}

	return b
}

func assertValidBits(bits int) {
	if bits%8 != 0 {
		log.Panicf("BIt amount not dividable by 8: %v", bits)
	}
}

// Returns a big int
func GenerateRandomBigInt(bits int) *big.Int {
	assertValidBits(bits)
	return BytesToBigInt(GenerateRandomBytes(BitsToBytes(bits)))
}

func BytesToBigInt(bytes []byte) *big.Int {
	bigInt := new(big.Int).SetBytes(bytes)
	bigInt = bigInt.Abs(bigInt)
	return bigInt
}
func CreateHash(value []byte) []byte {
	hasher := sha256.New()
	hasher.Write(value)
	return hasher.Sum(nil)
}
func VerifyHash(value []byte, hashed []byte) bool {
	hasher := sha256.New()
	hasher.Write(value)
	return hmac.Equal(hasher.Sum(nil), hashed)
}
func DiffieExp(secret *big.Int) *big.Int {
	exp := new(big.Int).Exp(diffie_g, secret, diffie_p)
	return exp
}
func DiffieSecret(secret *big.Int, someG *big.Int) *big.Int {
	exp := new(big.Int).Exp(someG, secret, diffie_p)
	return exp
}

func Pad(in []byte) []byte {
	padding := 16 - (len(in) % 16)
	if padding == 0 {
		padding = 16
	}
	for i := 0; i < padding; i++ {
		in = append(in, byte(padding))
	}
	return in
}

// Unpad strips the PKCS #7 padding on a buffer. If the padding is
// invalid, nil is returned.
func Unpad(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}

	padding := in[len(in)-1]
	if int(padding) > len(in) || padding > aes.BlockSize {
		return nil
	} else if padding == 0 {
		return nil
	}

	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
			return nil
		}
	}
	return in[:len(in)-int(padding)]
}
func AesEncrypt(key []byte, plainText []byte) []byte {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	plainText = Pad(plainText)
	iv := GenerateRandomBytes(16)

	encrypter := cipher.NewCBCEncrypter(block, iv)

	cipherText := make([]byte, len(plainText))

	encrypter.CryptBlocks(cipherText, plainText)
	cipherText = append(iv, cipherText...)
	return cipherText
}

func AesDecrypt(key []byte, cipherText []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	decrypter := cipher.NewCBCDecrypter(block, cipherText[:aes.BlockSize])
	plainText := make([]byte, len(cipherText)-aes.BlockSize)
	decrypter.CryptBlocks(plainText, cipherText[aes.BlockSize:])
	plainText = Unpad(plainText)
	return plainText
}

func CreateHmac(value []byte, hmacKey []byte) []byte {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(value)
	return mac.Sum(nil)
}

func VerifyHmac(value []byte, actualMac []byte, hmacKey []byte) bool {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(value)
	expectedMac := mac.Sum(nil)

	return hmac.Equal(actualMac, expectedMac)
}

func CreateSignature(what []byte, privateKey *rsa.PrivateKey, hmacKey []byte) []byte {
	hasher := hmac.New(sha256.New, hmacKey)
	hasher.Write(what)

	if signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hasher.Sum(nil)); err == nil {
		return signature
	} else {
		panic(err)
	}
}

func VerifySignature(signature []byte, what []byte, publicKey *rsa.PublicKey, hmacKey []byte) bool {
	hasher := hmac.New(sha256.New, hmacKey)
	hasher.Write(what)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hasher.Sum(nil), signature); err == nil {
		return true
	} else {
		log.Warning("Failed to validate signature: %v", err)
		return false
	}
}

func GenerateRsaPrivateKey() *rsa.PrivateKey {

	if privatekey, err := rsa.GenerateKey(rand.Reader, 1024); err == nil {
		return privatekey
	} else {
		panic(err)
	}
}

func MarshalRsaPublicKey(key *rsa.PublicKey) []byte {
	if serialized, err := x509.MarshalPKIXPublicKey(key); err == nil {
		return serialized
	} else {
		panic(err)
	}
}

func UnmarshalRsaPublicKey(bytes []byte) *rsa.PublicKey {
	if deserialized, err := x509.ParsePKIXPublicKey(bytes); err == nil {
		if key, ok := deserialized.(*rsa.PublicKey); ok {
			return key
		} else {
			panic("Not a rsa key")
		}
	} else {
		panic(err)
	}
}

func MarshalProto(pb proto.Message) string {
	if bytes, err := proto.Marshal(pb); err != nil {
		panic(err)
	} else {
		return base64.StdEncoding.EncodeToString(bytes)
	}
}

func UnmarshalProto(encoded string,  pb proto.Message) {
	bytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic(err)
	}
	if err = proto.Unmarshal(bytes, pb); err != nil {
		panic(err)
	} 
}
