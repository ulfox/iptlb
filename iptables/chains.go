package iptables

import (
	"fmt"

	"github.com/sirupsen/logrus"
	ipte "github.com/ulfox/iptlb/utils/logs"
)

// CreateChain for checking if a chain for a given table exists. In case it does not
// it will create the chain. If operator.Opts.ChainLogging has been enabled, it will also
// insert on entry 1 a logging rule
// Method uses operator.Opts.Table & operator.Opts.Chain to set the table and chain parameters
func (o *Operator) CreateChain() error {
	log := o.Logger.WithFields(logrus.Fields{
		"Stage": "createChain",
	})

	chainExists, err := o.IPT.ChainExists(o.Opts.Table, o.Opts.Chain)
	if err != nil {
		return err
	}

	if !chainExists {
		log.Infof(
			ipte.InfoChainDoesNotExist,
			o.Opts.Chain,
			o.Opts.Table,
		)
		err := o.IPT.NewChain(o.Opts.Table, o.Opts.Chain)
		if err != nil {
			return err
		}
	} else {
		log.Infof(ipte.InfoChainFound, o.Opts.Chain, o.Opts.Table)
	}

	chainExists, err = o.IPT.ChainExists(o.Opts.Table, o.Opts.Chain)
	if err != nil {
		return err
	}
	if !chainExists {
		return fmt.Errorf(ipte.ErrChainNotFound, o.Opts.Table, o.Opts.Chain)
	}

	if !o.Opts.ChainLogging {
		return nil
	}

	// Add verbose logging to chain
	ruleArgs := []string{
		"-j",
		"LOG",
		"--log-prefix",
		fmt.Sprintf("%s:ACCEPT:", o.Opts.Chain),
		"--log-level",
		o.Opts.LogLevel,
	}
	err = o.AddRule(ruleArgs)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof(ipte.InfoChainLoggingEnabled, o.Opts.Chain)
	return nil
}

// FlushChain for removing all rules from a chain. Used before we delete the chain
// Method uses operator.Opts.Table & operator.Opts.Chain to set the table and chain parameters
func (o *Operator) FlushChain() error {
	return o.IPT.ClearChain(o.Opts.Table, o.Opts.Chain)
}

// DeleteChain for deleting a chain. If we have any jump rules with that chain as target
// the operation will fail.
// Method uses operator.Opts.Table & operator.Opts.Chain to set the table and chain parameters
func (o *Operator) DeleteChain() error {
	return o.IPT.ClearAndDeleteChain(o.Opts.Table, o.Opts.Chain)
}
