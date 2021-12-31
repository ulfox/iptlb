package iptables

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	ipte "github.com/ulfox/iptlb/utils/logs"
)

func GetLogRule(s, p, c, lv string) []string {
	rule := []string{
		"-d",
		strings.Split(s, ":")[0],
		"-p",
		p,
		"-j",
		"LOG",
		"--log-prefix",
		fmt.Sprintf("IPTLB:%s:ACCEPT:", c),
		"--log-level",
		lv,
	}

	return rule
}

func GetLBRule(s, p, j string, d, i int) []string {
	rule := []string{
		"-p",
		"tcp",
		"-d",
		s,
		"--dport",
		p,
		"-m",
		"statistic",
		"--mode",
		"random",
		"--probability",
		fmt.Sprintf("%0.5f", 1.0/float64(d-i)),
		"-j",
		"DNAT",
		"--to-destination",
		j,
	}
	return rule
}

// RuleExists checks if a rule exists under a chain for a given table.
// Method uses operator.Opts.Table & operator.Opts.Chain to set the table and chain parameters
func (o *Operator) RuleExists(r []string) (bool, error) {
	if isExists, err := o.IPT.Exists(o.Opts.Table, o.Opts.Chain, r...); !isExists {
		if err != nil {
			return false, err
		}
		return false, nil
	}

	return true, nil
}

// InsertRule for adding a new rule to a specific index p on a given chain.
// Method uses operator.Opts.Table & operator.Opts.Chain to set the table and chain parameters
func (o *Operator) InsertRule(p int, r []string) error {
	log := o.Logger.WithFields(logrus.Fields{
		"Stage": "InsertRule",
	})

	ruleExists, err := o.RuleExists(r)
	if err != nil {
		return err
	}

	if ruleExists {
		log.Infof(
			ipte.InfoInsertRuleAlreadyExists,
			strings.Join(r, " "),
			p,
			o.Opts.Table,
			o.Opts.Chain,
		)
		return nil
	}

	log.Infof(
		ipte.InfoInsertRule,
		strings.Join(r, " "),
		p,
		o.Opts.Table,
		o.Opts.Chain,
	)

	err = o.IPT.Insert(o.Opts.Table, o.Opts.Chain, p, r...)
	if err != nil {
		return err
	}

	return nil
}

// AddRule for adding a new rule
// Method uses operator.Opts.Table & operator.Opts.Chain to set the table and chain parameters
func (o *Operator) AddRule(r []string) error {
	log := o.Logger.WithFields(logrus.Fields{
		"Stage": "AddRule",
	})

	ruleExists, err := o.RuleExists(r)
	if err != nil {
		return err
	}

	if ruleExists {
		log.Infof(
			ipte.InfoAppendRuleAlreadyExists,
			strings.Join(r, " "),
			o.Opts.Table,
			o.Opts.Chain,
		)
		return nil
	}

	log.Infof(
		ipte.InfoAppendRule,
		strings.Join(r, " "),
		o.Opts.Table,
		o.Opts.Chain,
	)

	err = o.IPT.Append(o.Opts.Table, o.Opts.Chain, r...)
	if err != nil {
		return err
	}

	return nil
}

// RemoveRule for removing a given rule
// Method uses operator.Opts.Table & operator.Opts.Chain to set the table and chain parameters
func (o *Operator) RemoveRule(r []string) error {
	log := o.Logger.WithFields(logrus.Fields{
		"Stage": "RemoveRule",
	})

	ruleExists, err := o.RuleExists(r)
	if err != nil {
		return err
	}

	if !ruleExists {
		return nil
	}
	err = o.IPT.Delete(o.Opts.Table, o.Opts.Chain, r...)
	if err != nil {
		return err
	}

	log.Infof(
		ipte.InfoDeleteRule,
		strings.Join(r, " "),
		o.Opts.Table,
		o.Opts.Chain,
	)

	return nil
}

// NATLBRules for creating rules that share the same probability for a given chain
// Method uses operator.Opts.Table & operator.Opts.Chain to set the table and chain parameters.
// Method also uses operator.Opts.Profile, operator.Opts.Src, operator.Opts.Dest and o.Opts.Protocol.
// Src is used to capture the inbound packets and Dest to apply DNAT to a different socket address
func (o *Operator) NATLBRules(t bool) error {
	log := o.Logger.WithFields(logrus.Fields{
		"Stage": "NATLBRules",
	})

	srcAddrSlice := strings.Split(o.Opts.Src, ":")

	for i, j := range o.Opts.Dest {
		ruleArgs := GetLBRule(srcAddrSlice[0], srcAddrSlice[1], j, len(o.Opts.Dest), i)
		if t {
			err := o.AddRule(ruleArgs)
			if err != nil {
				return err
			}
		} else {
			err := o.RemoveRule(ruleArgs)
			if err != nil {
				return err
			}
		}
	}

	ruleArgs := []string{
		"-j",
		"RETURN",
	}
	if t {
		err := o.AddRule(ruleArgs)
		if err != nil {
			return err
		}
	} else {
		err := o.RemoveRule(ruleArgs)
		if err != nil {
			return err
		}
	}

	log.Infof(
		ipte.InfoDoneChainCFG,
		o.Opts.Table,
		o.Opts.Chain,
	)

	return nil
}

// LogJumpRules for inserting to index 1 in a given chain a loggin rule.
// The rule is used to log packets on default chains were we apply the jump to custom NAT.
// Method uses operator.Opts.Table & operator.Opts.Chain to set the table and chain parameters.
// Method also uses o.Opts.Src, o.Opts.Dest, o.Opts.Protocol
func (o *Operator) LogJumpRules(t bool) error {
	ruleArgs := GetLogRule(o.Opts.Src, o.Opts.Protocol, o.Opts.Chain, o.Opts.LogLevel)
	if t {
		err := o.InsertRule(1, ruleArgs)
		if err != nil {
			return err
		}
	} else {
		err := o.RemoveRule(ruleArgs)
		if err != nil {
			return err
		}
	}

	return nil
}
