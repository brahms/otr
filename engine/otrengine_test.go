package engine

import (
	// "brahms/otr/utils"
	//"fmt"
	// "crypto/rand"
	// "crypto/rsa"
	"github.com/stretchr/testify/assert"
	// "math/big"
	"testing"
	// "time"
)

func TestMake(t *testing.T) {
	otr := MakeOtrEngine("Alice")
	assert.Equal(t, "Alice", otr.Name)
}

func TestPipe(t *testing.T) {
	otr := MakeOtrEngine("Alice")
	otr2 := MakeOtrEngine("Bob")
	adapter := MakeAdapter(otr, otr2)
	go otr.Run()
	go otr2.Run()
	go adapter.Run()
	otr.SendChannel <- "hi"
	assert.Equal(t, "hi", <-otr2.ReceiveChannel)
}

func TestEncryptedPipe(t *testing.T) {
	otr := MakeOtrEngine("Alice")
	otr2 := MakeOtrEngine("Bob")
	adapter := MakeAdapter(otr, otr2)
	go otr.Run()
	go otr2.Run()
	go adapter.Run()
	otr.SendChannel <- "hi"
	assert.Equal(t, "hi", <-otr2.ReceiveChannel)
	assert.NotEqual(t, 1, adapter.TotalMessages)
	assert.NotEqual(t, "hi", adapter.LastMessage)
	otr.SendChannel <- "hi2"
	assert.Equal(t, "hi2", <-otr2.ReceiveChannel)
	otr.SendChannel <- "hi3"
	assert.Equal(t, "hi3", <-otr2.ReceiveChannel)
	otr2.SendChannel <- "hi4"
	assert.Equal(t, "hi4", <-otr.ReceiveChannel)
}
