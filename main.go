package main

import (
	"flag"
	"log"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/ulfox/iptlb/iptables"
	"github.com/ulfox/iptlb/utils"
)

func main() {
	srcAddr := flag.String("src-addr", "", "The source socket address (ipv4:port) we want to route")
	destAddr := flag.String("dest-addr", "", "Comma-separated list of destination socket addresses (ipv4:port) for the target routes")
	rulesBackend := flag.String("rules-backend", "client", "[client/proxy/server] (Client) If ip tables are applied on the client host. If they are not, set this to (proxy) to apply rules in PREROUTING or (server) to apply rules in INPUT")
	setProfile := flag.String("profile", "default", "The profile name for the rules. Each profile can use a different set or combination of src/dest options")
	resetProfile := flag.Bool("reset", false, "Reset the given profile. Warning: This option removes the IPTable rules also")
	deleteProfile := flag.Bool("delete", false, "Delete the given profile. Warning: This option removes the IPTable rules also")
	statePath := flag.String("state-file", "local/state.db", "The path to the state file that iptlb will use to keep track of rules")
	logChains := flag.Bool("log-custom-chain", false, "Enable verbose logging on IPTLB Custom chains. The loggin will be appended to kernel log by default")
	logLevel := flag.String("log-level", "4", "The log level when log-custom-chain is enabled.")
	protocol := flag.String("protocol", "tcp", "The protocol that will be used for the rules. Default tcp")
	run := flag.Bool("run", false, "By default IPTLB will write the rules to a local storage but will not create them. Pass this flag to also enable the rules")
	useState := flag.Bool("use-state", false, "Requires also -run. Incompatible with -src-addr && -dest-addr. When enabled along with -run, IPTLB will use the state file to read all profiles and apply them")

	flag.Parse()

	operatorOpts := &iptables.OperatorOpts{
		Src:          *srcAddr,
		Profile:      *setProfile,
		RulesType:    *rulesBackend,
		Reset:        *resetProfile,
		Delete:       *deleteProfile,
		Path:         *statePath,
		CheckInput:   utils.CheckInputs,
		ChainLogging: *logChains,
		Protocol:     *protocol,
		LogLevel:     *logLevel,
		CreateRules:  *run,
		UseState:     *useState,
	}

	if *destAddr != "" {
		operatorOpts.Dest = strings.Split(*destAddr, ",")
	}

	if (operatorOpts.Src != "" || len(operatorOpts.Dest) != 0) && *useState {
		log.Fatal("-use-state is incompatible with -src-addr && -dest-addr")
	}

	logger := logrus.New()
	log := logger.WithFields(logrus.Fields{
		"Prog":      "iptlb",
		"Component": "main",
	})
	log.Info("Initiating")
	iptlbEnv := utils.GetIPTLBEnv(utils.IPTLBPrefix)
	log.Info(iptlbEnv)

	operator, err := iptables.NewOperatorFactory(operatorOpts, logger)
	if err != nil {
		log.Fatal(err)
	}
	log.Info("db operator initiated")

	if operator.Opts.Src == "" && len(operator.Opts.Dest) == 0 && *useState {
		data := operator.Storage.GetData()
		for k := range data.(map[interface{}]interface{}) {
			key, ok := k.(string)
			if !ok {
				log.Fatalf("possibly corrupted key in db [%s]", k)
			}
			operatorOpts.Profile = key

			// We now get the src & dest addresses from each profile
			err = operator.GetStateSrc()
			if err != nil {
				log.Fatal(err)
			}
			err = operator.GetStateDest()
			if err != nil {
				log.Fatal(err)
			}
			err = operator.GetStateProtocol()
			if err != nil {
				log.Fatal(err)
			}
			err = operator.GetStateLogLevel()
			if err != nil {
				log.Fatal(err)
			}
			err = operator.GetStateRulesBackend()
			if err != nil {
				log.Fatal(err)
			}

			err = operator.Configure()
			if err != nil {
				log.Fatal(err)
			}
		}
		return
	}
	err = operator.Configure()
	if err != nil {
		log.Fatal(err)
	}
}
