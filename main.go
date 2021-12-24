package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/sirupsen/logrus"
)

var (
	ipt            *iptables.IPTables
	logger         *logrus.Logger
	dest           []string
	src, rulesType string
	err            error
)

func checkInputs() error {
	// Check if src addr is an ip/port pair
	srcAddrSlice := strings.Split(src, ":")
	if len(srcAddrSlice) != 2 {
		return fmt.Errorf("Source address %s is not valid. Expected ip:port", src)
	}

	for _, j := range dest {
		if len(strings.Split(j, ":")) != 2 {
			return fmt.Errorf("Destination address %s is not valid. Expected ip:port", src)
		}
	}

	return nil
}

func createTable(table, chain string, logging bool) {
	log := logger.WithFields(logrus.Fields{
		"Prog":      "iptlb",
		"Component": "createTable",
	})

	err = ipt.ClearChain(table, chain)
	if err != nil {
		log.Fatal(err)
	}

	listChain, err := ipt.ListChains(table)
	if err != nil {
		log.Fatal(err)
	}
	chainExists := false
	for _, v := range listChain {
		if v == chain {
			chainExists = true
			log.Infof("Chain %s found", chain)
			break
		}
	}
	if !chainExists {
		log.Fatalf("Chain %s does not exist", chain)
	}

	if !logging {
		return
	}

	// Add verbose logging to chain
	ruleArgs := []string{
		"-j",
		"LOG",
		"--log-prefix",
		"IPTLB:ACCEPT:",
		"--log-level",
		"6",
	}
	err = ipt.Append(table, chain, ruleArgs...)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("Enabled logging to chain %s", chain)
}

func addRulesToNATTable(table, chain string) {
	log := logger.WithFields(logrus.Fields{
		"Prog":      "iptlb",
		"Component": "addRulesToTable",
	})

	srcAddrSlice := strings.Split(src, ":")

	for i, j := range dest {
		ruleArgs := []string{
			"-p",
			"tcp",
			"-d",
			srcAddrSlice[0],
			"--dport",
			srcAddrSlice[1],
			"-m",
			"statistic",
			"--mode",
			"random",
			"--probability",
			fmt.Sprintf("%0.5f", 1.0/float64(len(dest)-i)),
			"-j",
			"DNAT",
			"--to-destination",
			j,
		}
		err = ipt.Append(table, chain, ruleArgs...)
		if err != nil {
			log.Fatal(err)
		}
	}

	err = ipt.Append(table, chain, "-j", "RETURN")
	if err != nil {
		log.Fatal(err)
	}
}

func jumpToCustomNAT(table, chain, target string) {
	log := logger.WithFields(logrus.Fields{
		"Prog":      "iptlb",
		"Component": "jumpToCustomNAT",
	})

	srcAddrSlice := strings.Split(src, ":")
	ruleArgs := []string{
		"-p",
		"tcp",
		"-d",
		srcAddrSlice[0],
		"--dport",
		srcAddrSlice[1],
		"-j",
		target,
	}

	if isExists, err := ipt.Exists(table, chain, ruleArgs...); !isExists {
		log.Infof("Rule: %s does not exist", strings.Join(ruleArgs, " "))
		err = ipt.Insert(table, chain, 1, ruleArgs...)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Infof("Rule: %s exists", strings.Join(ruleArgs, " "))
	}
}

func jumpToCustomFilter(table, chain, target string) {
	log := logger.WithFields(logrus.Fields{
		"Prog":      "iptlb",
		"Component": "jumpToCustomFilter",
	})

	for _, j := range dest {
		srcAddrSlice := strings.Split(j, ":")
		ruleArgs := []string{
			"-p",
			"tcp",
			"-d",
			srcAddrSlice[0],
			"--dport",
			srcAddrSlice[1],
			"-j",
			target,
		}

		if isExists, err := ipt.Exists(table, chain, ruleArgs...); !isExists {
			log.Infof("Rule: %s does not exist", strings.Join(ruleArgs, " "))
			err = ipt.Insert(table, chain, 1, ruleArgs...)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			log.Infof("Rule: %s exists", strings.Join(ruleArgs, " "))
		}
	}

	err = ipt.Append(table, chain, "-j", "RETURN")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	srcAddr := flag.String("src-addr", "", "The source socket address (ipv4:port) we want to route")
	destAddr := flag.String("dest-addr", "", "Comma-separated list of destination socket addresses (ipv4:port) for the target routes")
	rulesBackend := flag.String("rules-backend", "client", "[client/proxy/server] (Client) If ip tables are applied on the client host. If they are not, set this to (proxy) to apply rules in PREROUTING or (server) to apply rules in INPUT")

	flag.Parse()

	src = *srcAddr
	dest = strings.Split(*destAddr, ",")
	rulesType = *rulesBackend

	logger = logrus.New()
	log := logger.WithFields(logrus.Fields{
		"Prog":      "iptlb",
		"Component": "main",
	})
	log.Info("Initiating")

	// Check if inputs are valid socket addresses
	checkInputs()

	ipt, err = iptables.New()
	if err != nil {
		log.Fatal(err)
	}

	// Create IPTLB Chain under nat table
	// This also clears the chain if it already exists
	chain := "IPT_NAT_LB"
	table := "nat"
	createTable(table, chain, true)

	// Add rules to the custom nat table we created
	addRulesToNATTable(table, chain)

	// Add a jump to custom nat target
	target := chain
	chain = "OUTPUT"
	if rulesType == "client" {
		chain = "OUTPUT"
	} else if rulesType == "proxy" {
		chain = "PREROUTING"
	} else if rulesType == "server" {
		chain = "INPUT"
	}
	jumpToCustomNAT(table, chain, target)

	// Create a custom filter table for logging and future rules and
	// jump inbout packets from the nat rule to the new target
	table = "filter"
	createTable(table, "IPT_FILTER_LB", true)
	jumpToCustomFilter(table, "INPUT", "IPT_FILTER_LB")
}
