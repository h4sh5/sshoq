package main

import (
	"github.com/h4sh5/sshoq/cmd"
	"os"

	// authentication plugins
	_ "github.com/h4sh5/sshoq/auth/plugins/pubkey_authentication/server"
)

func main() {
	os.Exit(cmd.ServerMain())
}
