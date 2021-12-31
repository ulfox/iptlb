package state

import (
	"fmt"
	"strings"

	"github.com/ulfox/dby/db"
	ipte "github.com/ulfox/iptlb/utils/logs"
)

// DB for managing the state of iptlb.
// Src is the source address that we will capture
//
// Dest are the destination addresses that we will be forwarding
// requests sent to Src
//
// Rules keeps information about the iptable rules that have been
// applied. Format is: table.chain.ruleN
//
type DB struct {
	*db.Storage
	AssertFactory *db.AssertData
	Rules         *map[string]map[string][]string
}

// NewStateFactory for creating a new yaml db manager
func NewStateFactory(path string) (*DB, error) {
	yamlDBManager, err := db.NewStorageFactory(path)
	if err != nil {
		return nil, err
	}

	state := &DB{
		Storage:       yamlDBManager,
		AssertFactory: db.NewConvertFactory(),
	}

	return state, nil
}

func (d *DB) checkSource(profile, src string) error {
	keys, err := d.Storage.FindKeys("source")
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		return nil
	}

	for _, j := range keys {
		value, err := d.Storage.GetPath(j)
		if err != nil {
			return nil
		}

		if src == value.(string) {
			if strings.Split(j, ".")[0] == profile {
				return nil
			}
			return fmt.Errorf(
				fmt.Sprintf(
					ipte.ErrSourceAlreadyExists,
					src,
					strings.Split(j, ".")[0],
					strings.Split(j, ".")[0],
					strings.Split(j, ".")[0],
				),
			)
		}
	}

	return nil
}

func (d *DB) checkKey(profile, key string) error {
	keys, err := d.Storage.FindKeys(key)
	if err != nil {
		return err
	}

	for _, v := range keys {
		if strings.HasPrefix(v, profile) {
			return fmt.Errorf(ipte.ErrKeyAlreadyExists, strings.Split(v, ".")[0], profile)
		}
	}
	return nil
}

// AddSource writing src (ipv4:port) on local state
func (d *DB) AddSource(profile, src string) error {
	err := d.checkSource(profile, src)
	if err != nil {
		return err
	}

	err = d.checkKey(profile, "source")
	if err != nil {
		return err
	}

	err = d.Storage.Upsert(
		fmt.Sprintf("%s.%s", profile, "source"),
		src,
	)
	if err != nil {
		return err
	}

	return nil
}

// AddDestinations for writing the dest aray of ([ipv4:port,...]) on local state
func (d *DB) AddDestinations(profile string, dest []string) error {
	err := d.checkKey(profile, "destination")
	if err != nil {
		return err
	}

	err = d.Storage.Upsert(
		fmt.Sprintf("%s.%s", profile, "destination"),
		dest,
	)
	if err != nil {
		return err
	}

	return nil
}

// DeleteProfile for deleting a profile from the local state
func (d *DB) DeleteProfile(profile string) error {
	err := d.checkKey(profile, profile)
	if err == nil {
		return fmt.Errorf(fmt.Sprintf(ipte.ErrProfileNotExist, profile))
	}

	err = d.Storage.Delete(profile)
	if err != nil {
		return nil
	}

	return nil
}

func (d *DB) AddProtocol(profile, protocol string) error {
	err := d.Storage.Upsert(
		fmt.Sprintf("%s.%s", profile, "protocol"),
		protocol,
	)
	if err != nil {
		return err
	}

	return nil
}

func (d *DB) AddLogLevel(profile, logLevel string) error {
	err := d.Storage.Upsert(
		fmt.Sprintf("%s.%s", profile, "logLevel"),
		logLevel,
	)
	if err != nil {
		return err
	}

	return nil
}

func (d *DB) AddLogEnabled(profile string, logEnabled bool) error {
	err := d.Storage.Upsert(
		fmt.Sprintf("%s.%s", profile, "logEnabled"),
		logEnabled,
	)
	if err != nil {
		return err
	}

	return nil
}

func (d *DB) AddRulesBackend(profile, rulesBackend string) error {
	err := d.Storage.Upsert(
		fmt.Sprintf("%s.%s", profile, "rulesBackend"),
		rulesBackend,
	)
	if err != nil {
		return err
	}

	return nil
}
