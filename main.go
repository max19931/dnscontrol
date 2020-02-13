package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/StackExchange/dnscontrol/v2/commands"
	_ "github.com/StackExchange/dnscontrol/v2/providers/_all"
)
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	os.Exit(commands.Run(versionString()))
}
var (
	SHA       = ""
	Version   = "2.10.0"
	BuildTime = ""
)
func versionString() string {
	var version string
	if SHA != "" {
		version = fmt.Sprintf("%s (%s)", Version, SHA)
	} else {
		version = fmt.Sprintf("%s-dev", Version)
	}
	if BuildTime != "" {
		i, err := strconv.ParseInt(BuildTime, 10, 64)
		if err == nil {
			tm := time.Unix(i, 0)
			version += fmt.Sprintf(" built %s", tm.Format(time.RFC822))
		}
	}
	return fmt.Sprintf("dnscontrol %s", version)
}
