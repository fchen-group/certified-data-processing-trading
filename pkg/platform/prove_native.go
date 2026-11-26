//go:build !ego

package platform

import "errors"

const HardwareBuild = false

func Prove([]byte) ([]byte, error) { return nil, errors.New("build enclave with ego-go and -tags ego") }
