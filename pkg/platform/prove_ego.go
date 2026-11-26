//go:build ego

package platform

import "github.com/edgelesssys/ego/enclave"

const HardwareBuild = true

func Prove(data []byte) ([]byte, error) { return enclave.GetRemoteReport(data) }
