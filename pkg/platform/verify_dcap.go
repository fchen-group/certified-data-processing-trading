//go:build dcap

package platform

import (
	"bytes"
	"errors"
	"github.com/edgelesssys/ego/eclient"
	"certified-data-processing-trading/pkg/protocol"
)

func Verify(report []byte, measurement protocol.Hash, data []byte) error {
	r, e := eclient.VerifyRemoteReport(report)
	if e != nil {
		return e
	}
	if r.Debug || !bytes.Equal(r.UniqueID, measurement[:]) || !bytes.Equal(r.Data, data) {
		return errors.New("SGX measurement, debug flag or report data mismatch")
	}
	return nil
}
