package main

import (
	"flag"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec-cloudflare-worker-bouncer/cmd"
)

func main() {
	configTokens := flag.String("g", "", "comma separated tokens to generate config for")
	configOutputPath := flag.String("o", "", "path to store generated config to")
	configPath := flag.String("c", "", "path to config file")
	ver := flag.Bool("version", false, "Display version information and exit")
	testConfig := flag.Bool("t", false, "test config and exit")
	showConfig := flag.Bool("T", false, "show full config (.yaml + .yaml.local) and exit")
	deleteOnly := flag.Bool("d", false, "delete all the created infra and exit")
	setupOnly := flag.Bool("s", false, "setup the infra and exit")
	setupAutonomous := flag.Bool("S", false, "setup the infra in autonomous mode (with decisions-sync-worker) and exit")
	flag.Parse()
	err := cmd.Execute(cmd.ExecuteOptions{
		ConfigTokens:     configTokens,
		ConfigOutputPath: configOutputPath,
		ConfigPath:       configPath,
		Ver:              ver,
		TestConfig:       testConfig,
		ShowConfig:       showConfig,
		DeleteOnly:       deleteOnly,
		SetupOnly:        setupOnly,
		SetupAutonomous:  setupAutonomous,
	})
	if err != nil {
		log.Fatal(err)
	}
}
