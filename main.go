package main

import (
	"brahms/otr/engine"
	"github.com/op/go-logging"
	"os"
)

var (
	log    = logging.MustGetLogger("brahms.otr.main")
	format = "[%{level:.1s}] [%{time:15:04:05.000000}] --- %{message} |==> %{shortfile}\n"
)

func main() {

	aliceMessages := []string{
		"Lights on",
		"Forward drift?",
		"413 is in",
		"The Eagle has landed"}

	bobMessages := []string{
		"30 seconds",
		"Yes",
		"Houston, Tranquility base here",
		"A small step for a student, a giant leap for the group"}
	// Setup logging to write to stderr
	logBackend := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(logBackend)
	logging.SetFormatter(logging.MustStringFormatter(format))
	logging.SetLevel(logging.INFO, "brahms.otr")

	alice := engine.MakeOtrEngine("Alice")
	bob := engine.MakeOtrEngine("Bob")
	eve := engine.MakeAdapter(alice, bob)
	go alice.Run()
	go bob.Run()
	go eve.Run()
	for i := 0; i < 4; i++ {
		aliceMsg := aliceMessages[i]
		bobMsg := bobMessages[i]

		alice.SendChannel <- aliceMsg
		if aliceMsg != <-bob.ReceiveChannel {
			panic("Bad alice")
		}
		bob.SendChannel <- bobMsg
		if bobMsg != <-alice.ReceiveChannel {
			panic("Bad bob")
		}
	}
}
