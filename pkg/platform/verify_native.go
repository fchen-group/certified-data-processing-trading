//go:build !dcap

package platform

import (
	"errors"
	"certified-data-processing-trading/pkg/protocol"
)

func Verify([]byte, protocol.Hash, []byte) error {
	return errors.New("build client with -tags dcap and EGo verification libraries; no insecure fallback")
}
