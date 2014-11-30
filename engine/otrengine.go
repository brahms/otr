package engine

import (
	"brahms/otr/serialization"
	"brahms/otr/utils"
	// "bytes"
	// "crypto/rsa"
	// "encoding/base64"
	"encoding/binary"
	// "encoding/hex"
	// "github.com/golang/protobuf/proto"
	"github.com/op/go-logging"
	"math/big"
	// "strconv"
)

func init() {
	logging.SetLevel(logging.INFO, "brahms.otr.otrengine")
}

const (
	START           = "START"
	DIFFIE_FINISHED = "DIFFIE_FINISHED"
)

var (
	log    = logging.MustGetLogger("brahms.otr.otrengine")
	ENDIAN = binary.BigEndian
)

type Adapter struct {
	otr1          *OtrEngine
	otr2          *OtrEngine
	TotalMessages int
	Otr1Messages  []string
	Otr2Messages  []string
	LastMessage   string
}

func MakeAdapter(otr1 *OtrEngine, otr2 *OtrEngine) *Adapter {
	return &Adapter{otr1, otr2, 0, make([]string, 1), make([]string, 1), ""}
}
func (this *Adapter) Run() {
	for {
		select {
		case msg := <-this.otr1.writer:
			log.Info("Eve sees: %v -> %v: %v", this.otr1.Name, this.otr2.Name, msg)
			this.otr2.reader <- msg
			this.Otr1Messages = append(this.Otr1Messages, msg)
			this.TotalMessages = this.TotalMessages + 1
			this.LastMessage = msg
		case msg := <-this.otr2.writer:
			log.Info("Eve sees: %v -> %v: %v", this.otr2.Name, this.otr1.Name, msg)
			this.otr1.reader <- msg
			this.Otr2Messages = append(this.Otr2Messages, msg)
			this.TotalMessages = this.TotalMessages + 1
			this.LastMessage = msg
		}
	}
}

type OtrEngine struct {
	Name           string
	reader         chan string
	writer         chan string
	SendChannel    chan string
	ReceiveChannel chan string
	phase          string
}

func MakeOtrEngine(name string) *OtrEngine {
	return &OtrEngine{Name: name,
		reader:         make(chan string),
		writer:         make(chan string),
		SendChannel:    make(chan string, 1),
		ReceiveChannel: make(chan string, 1),
		phase:          START}
}
func (this *OtrEngine) String() string {
	return this.Name
}

func (this *OtrEngine) Run() {
	var mySecret *big.Int
	var myPublic *big.Int
	var theirPublic *big.Int
	var ourSecret *big.Int
	var sessionKey []byte

	for {
		select {
		case msg := <-this.reader:
			switch this.phase {
			// case where i'm the receiver
			case START:
				mySecret = utils.GenerateRandomBigInt(utils.BitsToBytes(320))
				myPublic = utils.DiffieExp(mySecret)

				diffieExchange := &serialization.DiffieExchange{Diffie: myPublic.Bytes()}

				this.writer <- utils.MarshalProto(diffieExchange)

				utils.UnmarshalProto(msg, diffieExchange)
				theirPublic = new(big.Int).SetBytes(diffieExchange.Diffie)

				this.phase = DIFFIE_FINISHED
			case DIFFIE_FINISHED:
				ourSecret = utils.DiffieSecret(mySecret, theirPublic)
				sessionKey = generateSessionKey(ourSecret)

				textMessage := &serialization.TextMessage{}
				utils.UnmarshalProto(msg, textMessage)
				unencrypted := string(utils.AesDecrypt(sessionKey, textMessage.Encrypted))
				theMsg := string(unencrypted)

				log.Info("%v received %v", this.Name, theMsg)
				this.ReceiveChannel <- theMsg
				theirPublic = new(big.Int).SetBytes(textMessage.Diffie)

				// now we regenerate our session key by using our new diffie public and secret
				ourSecret = utils.DiffieSecret(mySecret, theirPublic)
				sessionKey = generateSessionKey(ourSecret)
			}

		case msg := <-this.SendChannel:
			log.Info("%v is going to send the message '%v'", this.Name, msg)
			switch this.phase {
			// case where I'm the initiator
			case START:
				mySecret = utils.GenerateRandomBigInt(utils.BitsToBytes(320))
				myPublic = utils.DiffieExp(mySecret)

				diffieExchange := &serialization.DiffieExchange{Diffie: myPublic.Bytes()}

				this.writer <- utils.MarshalProto(diffieExchange)

				utils.UnmarshalProto(<-this.reader, diffieExchange)
				theirPublic = new(big.Int).SetBytes(diffieExchange.Diffie)
				ourSecret = utils.DiffieSecret(mySecret, theirPublic)
				sessionKey = generateSessionKey(ourSecret)

				mySecret = utils.GenerateRandomBigInt(utils.BitsToBytes(320))
				myPublic = utils.DiffieExp(mySecret)

				encrypted := utils.AesEncrypt(sessionKey, []byte(msg))

				textMessage := &serialization.TextMessage{Encrypted: encrypted, Diffie: myPublic.Bytes()}
				this.writer <- utils.MarshalProto(textMessage)

				// now we regenerate our session key by using our new diffie public and secret
				ourSecret = utils.DiffieSecret(mySecret, theirPublic)
				sessionKey = generateSessionKey(ourSecret)

				this.phase = DIFFIE_FINISHED
			case DIFFIE_FINISHED:

				mySecret = utils.GenerateRandomBigInt(utils.BitsToBytes(320))
				myPublic = utils.DiffieExp(mySecret)

				encrypted := utils.AesEncrypt(sessionKey, []byte(msg))

				textMessage := &serialization.TextMessage{Encrypted: encrypted, Diffie: myPublic.Bytes()}
				this.writer <- utils.MarshalProto(textMessage)

				// now we regenerate our session key by using our new diffie public and secret
				ourSecret = utils.DiffieSecret(mySecret, theirPublic)
				sessionKey = generateSessionKey(ourSecret)

			}

		}
	}
}
func generateSessionKey(secret *big.Int) []byte {
	bytes := utils.CreateHash(secret.Bytes())
	bytes = bytes[:utils.BitsToBytes(128)]

	return bytes
}
