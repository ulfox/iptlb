package utils

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

func emptyStringE(s string) error {
	if s == "" {
		return fmt.Errorf("string [%s] is empty", s)
	}

	return nil
}

// CheckInputs checks if input src & dest strings can be split into ip/port pairs
func CheckInputs(src string, dest []string) error {
	// Check if src addr is an ip/port pair
	srcAddrSlice := strings.Split(src, ":")
	if len(srcAddrSlice) != 2 {
		return fmt.Errorf("source address [%s] is not valid. Expected ip:port", src)
	}

	if es := emptyStringE(srcAddrSlice[0]); es != nil {
		return errors.Wrap(es, fmt.Sprintf("source [%s]", src))
	}
	if es := emptyStringE(srcAddrSlice[1]); es != nil {
		return errors.Wrap(es, fmt.Sprintf("source [%s]", src))
	}

	for _, j := range dest {
		strSlice := strings.Split(j, ":")
		if len(strSlice) != 2 {
			return fmt.Errorf("destination address [%s] is not valid. Expected ip:port", j)
		}

		if es := emptyStringE(strSlice[0]); es != nil {
			return errors.Wrap(es, fmt.Sprintf("destination [%s]", j))
		}
		if es := emptyStringE(strSlice[1]); es != nil {
			return errors.Wrap(es, fmt.Sprintf("destination [%s]", j))
		}
	}

	return nil
}
