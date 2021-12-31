package iptables

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/sirupsen/logrus"
	"github.com/ulfox/iptlb/state"
	ipte "github.com/ulfox/iptlb/utils/logs"
)

type checkInput = func(src string, dest []string) error

// Operator for managing the iptable rules.
type Operator struct {
	Storage *state.DB
	IPT     *iptables.IPTables
	Opts    *OperatorOpts
	Logger  *logrus.Logger
	Cache   struct {
		Src, RulesType, Protocol, LogLevel, Profile, Chain, Table string
		Dest                                                      []string
		ChainLogging                                              bool
	}
}

// OperatorOpts is a struct used by iptlb.Operator to configure iptables
type OperatorOpts struct {
	Src, RulesType, Path, Profile, Protocol, LogLevel, Table, Chain string
	Dest, RuleArgs                                                  []string
	Delete, Reset, ChainLogging, CreateRules, UseState              bool
	CheckInput                                                      checkInput
}

// NewOperatorFactory creates a new iptlb.Operator
func NewOperatorFactory(o *OperatorOpts, l *logrus.Logger) (*Operator, error) {
	db, err := state.NewStateFactory(o.Path)
	if err != nil {
		l.Fatal(err)
	}

	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}

	state := &Operator{
		Storage: db,
		Opts:    o,
		IPT:     ipt,
		Logger:  l,
	}

	return state, nil
}

// Target method to allow chain method usage.
// For example operator.Target("someTable", "someChain").CreateChain()
func (o *Operator) Target(t, c string) *Operator {
	o.Opts.Table = t
	o.Opts.Chain = c

	return o
}

func (o *Operator) copyToCache() {
	o.Cache.Src = o.Opts.Src
	o.Cache.RulesType = o.Opts.RulesType
	o.Cache.Dest = o.Opts.Dest
	o.Cache.Protocol = o.Opts.Protocol
	o.Cache.LogLevel = o.Opts.LogLevel
	o.Cache.Profile = o.Opts.Profile
	o.Cache.Chain = o.Opts.Chain
	o.Cache.Table = o.Opts.Table
	o.Cache.ChainLogging = o.Opts.ChainLogging
}

func (o *Operator) copyFromCache() {
	o.Opts.Src = o.Cache.Src
	o.Opts.RulesType = o.Cache.RulesType
	o.Opts.Dest = o.Cache.Dest
	o.Opts.Protocol = o.Cache.Protocol
	o.Opts.LogLevel = o.Cache.LogLevel
	o.Opts.Profile = o.Cache.Profile
	o.Opts.Chain = o.Cache.Chain
	o.Opts.Table = o.Cache.Table
	o.Opts.ChainLogging = o.Cache.ChainLogging
}

// Configure is the main function that runs after we initiate operator.
// It checks the inputs and decides if it will create/delete/reset a profie
func (o *Operator) Configure() error {
	log := o.Logger.WithFields(logrus.Fields{
		"Component": "Operator",
		"Stage":     "Configure",
	})

	if o.Opts.Delete && o.Opts.Reset {
		return fmt.Errorf(ipte.ErrFlagReset)
	}

	if o.Opts.Delete {
		log.Warnf(ipte.WarnDelete, o.Opts.Profile)
		exists, err := o.ProfileExists()
		if err != nil {
			return err
		}

		if exists {
			return o.DeleteProfile()
		}
		return nil
	}

	if o.Opts.Reset {
		log.Warnf(ipte.WarnReset, o.Opts.Profile)
		exists, err := o.ProfileExists()
		if err != nil {
			return err
		}

		o.copyToCache()
		if exists {
			err := o.DeleteProfile()
			if err != nil {
				return err
			}
		}

		o.copyFromCache()
	}

	err := o.Opts.CheckInput(o.Opts.Src, o.Opts.Dest)
	if err != nil {
		return err
	}
	log.Info(ipte.InfoInputValidation)

	err = o.AddProfile()
	if err != nil {
		return err
	}

	return nil
}

// ProfileExists method for checking if a given profile exists
func (o *Operator) ProfileExists() (bool, error) {
	data, err := o.Storage.GetPath(o.Opts.Profile)
	if err != nil {
		if data == nil {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetChainName method used to generate the custom dnat chain name that is created
// to host the nat loadbalancing rules
func (o *Operator) GetChainName(s string) string {
	return strings.Replace(
		fmt.Sprintf(
			"IPTLB_%s_%s",
			strings.ToUpper(s),
			strings.ToUpper(o.Opts.Profile),
		),
		"-",
		"_",
		-1,
	)
}

// GetCustomNatJumpRule method for creating a jump rule to the custom dnat chain.
// If backend is client, the jump rule is applied in the OUTPUT nat chain.
// If backend is proxy, the jump rule is applied in the PREROUTING nat chain.
// If backend is server, the jump rule is applied in the INPUT nat chain.
func (o *Operator) GetCustomNatJumpRule(t string) []string {
	if o.Opts.RulesType == "client" {
		o.Target("nat", "OUTPUT")
	} else if o.Opts.RulesType == "proxy" {
		o.Target("nat", "PREROUTING")
	} else if o.Opts.RulesType == "server" {
		o.Target("nat", "INPUT")
	}

	return []string{
		"-p",
		o.Opts.Protocol,
		"-d",
		strings.Split(o.Opts.Src, ":")[0],
		"--dport",
		strings.Split(o.Opts.Src, ":")[1],
		"-j",
		t,
	}
}

// CheckIPV4 simple method for checking if a socket addres is a correct
// ipv4 address
func (o *Operator) CheckIPV4(ip string) error {
	ipSlice := strings.Split(ip, ".")

	for _, oct := range ipSlice {
		octInt, err := strconv.Atoi(oct)
		if err != nil {
			return nil
		}
		if octInt < 0 || octInt > 255 {
			return fmt.Errorf(ipte.ErrInvalidIPV4, ip)
		}
	}

	return nil
}

// AddProfile method for creating/updating a profile and invoking
// the NATLBRules and InsertRule Methods that apply the LB logic
func (o *Operator) AddProfile() error {
	log := o.Logger.WithFields(logrus.Fields{
		"Stage": "AddProfile",
	})

	err := o.CheckIPV4(o.Opts.Src)
	if err != nil {
		return err
	}

	if o.Opts.UseState && !o.Opts.Reset {
		goto addProfileAfterDBSync
	}
	err = o.Storage.AddSource(o.Opts.Profile, o.Opts.Src)
	if err != nil {
		return err
	}
	for _, j := range o.Opts.Dest {
		err = o.CheckIPV4(j)
		if err != nil {
			return err
		}
	}
	err = o.Storage.AddDestinations(o.Opts.Profile, o.Opts.Dest)
	if err != nil {
		return err
	}
	err = o.Storage.AddProtocol(o.Opts.Profile, o.Opts.Protocol)
	if err != nil {
		return err
	}
	err = o.Storage.AddLogLevel(o.Opts.Profile, o.Opts.LogLevel)
	if err != nil {
		return err
	}
	err = o.Storage.AddLogEnabled(o.Opts.Profile, o.Opts.ChainLogging)
	if err != nil {
		return err
	}
	err = o.Storage.AddRulesBackend(o.Opts.Profile, o.Opts.RulesType)
	if err != nil {
		return err
	}

addProfileAfterDBSync:
	if !o.Opts.CreateRules {
		goto endOfAddProfile
	}

	// Check if nat chains exist. Create if it does not
	err = o.Target("nat", o.GetChainName("nat")).
		CreateChain()
	if err != nil {
		return err
	}

	err = o.GetState()
	if err != nil {
		return err
	}

	err = o.NATLBRules(true)
	if err != nil {
		return err
	}

	// Check if rule in nat exists for jumping to custom chain. Create if it does not
	o.Opts.RuleArgs = o.GetCustomNatJumpRule(o.GetChainName(o.Opts.Table))

	err = o.InsertRule(1, o.Opts.RuleArgs)
	if err != nil {
		return err
	}

	if o.Opts.ChainLogging {
		err = o.LogJumpRules(true)
		if err != nil {
			return err
		}
	}

endOfAddProfile:
	log.Infof(
		ipte.InfoProfileCFG,
		o.Opts.Profile,
	)

	return nil
}

// DeleteProfile method for deleting a profile. It will first delete the rules and chains
// and last the profile entries from the local state
func (o *Operator) DeleteProfile() error {
	log := o.Logger.WithFields(logrus.Fields{
		"Stage": "DeleteProfile",
	})

	// Check if nat chains exist. Delete if it does
	o.Target("nat", o.GetChainName("nat"))

	err := o.GetState()
	if err != nil {
		return err
	}

	var rules []string
	var exists bool

	if !o.Opts.CreateRules {
		goto endOfDeleteProfile
	}

	err = o.NATLBRules(false)
	if err != nil {
		return err
	}

	// Check if rule in nat exists for jumping to custom chain. Delete if it does
	exists, err = o.IPT.ChainExists(o.Opts.Table, o.Opts.Chain)
	if err != nil {
		return err
	}
	if !exists {
		goto endOfDeleteProfile
	}

	o.Opts.RuleArgs = o.GetCustomNatJumpRule(o.GetChainName(o.Opts.Table))
	err = o.RemoveRule(o.Opts.RuleArgs)
	if err != nil {
		return err
	}

	err = o.LogJumpRules(false)
	if err != nil {
		return err
	}

	// Check if there are other rules that may exist and delete them
	// Here we will delete any rule that matches the following condition
	// rule -> HasSuffix(fmt.Sprintf("-J %s", o.GetChainName(o.Table)))
	rules, err = o.IPT.List(o.Opts.Table, o.Opts.Chain)
	if err != nil {
		return err
	}
	for _, j := range rules {
		if strings.HasSuffix(j, fmt.Sprintf("-j %s", o.GetChainName(o.Opts.Table))) {
			o.Opts.RuleArgs = strings.Split(j, " ")[1:]
			err = o.RemoveRule(o.Opts.RuleArgs)
			if err != nil {
				return err
			}
		}
	}

	err = o.Target("nat", o.GetChainName("nat")).FlushChain()
	if err != nil {
		return err
	}

	err = o.Target("nat", o.GetChainName("nat")).DeleteChain()
	if err != nil {
		return err
	}

endOfDeleteProfile:
	err = o.Storage.DeleteProfile(o.Opts.Profile)
	if err != nil {
		if err.Error() == fmt.Sprintf(ipte.ErrProfileNotExist, o.Opts.Profile) {
			log.Warn(err)
			return nil
		}
		return err
	}

	log.Infof(ipte.InfoProfileDelete, o.Opts.Profile)

	return nil
}

// GetStateSrc for reading the local source state for a given profile
func (o *Operator) GetStateSrc() error {
	src, err := o.Storage.GetPath(fmt.Sprintf("%s.source", o.Opts.Profile))
	if err != nil {
		return err
	}

	o.Opts.Src = src.(string)

	return nil
}

// GetStateDest for reading the local destination state for a given profile
func (o *Operator) GetStateDest() error {
	destObj, err := o.Storage.GetPath(
		fmt.Sprintf("%s.destination", o.Opts.Profile),
	)
	if err != nil {
		return err
	}

	o.Storage.AssertFactory.Input(destObj)
	if o.Storage.AssertFactory.GetError() != nil {
		return o.Storage.AssertFactory.GetError()
	}
	dest, err := o.Storage.AssertFactory.GetArray()
	if err != nil {
		return err
	}

	o.Opts.Dest = dest

	return err
}

// GetStateProtocol for reading the local protocol state for a given profile
func (o *Operator) GetStateProtocol() error {
	protocol, err := o.Storage.GetPath(fmt.Sprintf("%s.protocol", o.Opts.Profile))
	if err != nil {
		return err
	}

	o.Opts.Protocol = protocol.(string)

	return nil
}

// GetStateLogLevel for reading the local logLevel state for a given profile
func (o *Operator) GetStateLogLevel() error {
	logLevel, err := o.Storage.GetPath(fmt.Sprintf("%s.logLevel", o.Opts.Profile))
	if err != nil {
		return err
	}

	o.Opts.LogLevel = logLevel.(string)

	return nil
}

// GetStateProtocol for reading the local logEnabled state for a given profile
func (o *Operator) GetStateLogEnabled() error {
	logEnabled, err := o.Storage.GetPath(fmt.Sprintf("%s.logEnabled", o.Opts.Profile))
	if err != nil {
		return err
	}

	o.Opts.ChainLogging = logEnabled.(bool)

	return nil
}

// GetStateRulesBackend for reading the local rulesBackend state for a given profile
func (o *Operator) GetStateRulesBackend() error {
	rulesBackend, err := o.Storage.GetPath(fmt.Sprintf("%s.rulesBackend", o.Opts.Profile))
	if err != nil {
		return err
	}

	o.Opts.RulesType = rulesBackend.(string)

	return nil
}

// GetState for invoking the GetStateSrc and GetStateDest methods
func (o *Operator) GetState() error {
	err := o.GetStateSrc()
	if err != nil {
		return err
	}

	err = o.GetStateDest()
	if err != nil {
		return err
	}

	err = o.GetStateProtocol()
	if err != nil {
		return err
	}

	err = o.GetStateLogLevel()
	if err != nil {
		return err
	}

	err = o.GetStateLogEnabled()
	if err != nil {
		return err
	}

	err = o.GetStateRulesBackend()
	if err != nil {
		return err
	}

	return nil
}
