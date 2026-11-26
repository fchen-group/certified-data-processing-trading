package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"time"

	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/deployment"
	"certified-data-processing-trading/pkg/localio"
	"certified-data-processing-trading/pkg/platform"
	"certified-data-processing-trading/pkg/protocol"
	"certified-data-processing-trading/pkg/worker"
)

func main() {
	if e := run(); e != nil {
		log.Fatal(e)
	}
}
func run() error {
	tid := flag.Uint64("tid", 0, "registered trade ID")
	input := flag.String("input", "", "host ciphertext file (no plaintext secrets)")
	listen := flag.String("listen", ":8443", "TLS listen address")
	dev := flag.String("dev-config", "", "explicit native-only development chain configuration")
	publicCert := flag.String("dev-cert-out", "", "native-only public certificate for out-of-band pinning")
	maxInput := flag.Int64("max-input-bytes", worker.MaxCiphertextBytes, "input cap; may lower, not exceed the compiled resource policy")
	initTimings := flag.Bool("timings", false, "log nonsecret initialization stage timings")
	flag.Parse()
	var c chain.Config
	if platform.HardwareBuild {
		if *dev != "" || *publicCert != "" {
			return fmt.Errorf("development options forbidden in SGX build")
		}
		if e := protocol.StrictJSON(deployment.Runtime, &c); e != nil {
			return e
		}
		if c.Development {
			return fmt.Errorf("development RPC forbidden in measured SGX image")
		}
	} else {
		if *dev == "" {
			return fmt.Errorf("native worker requires -dev-config; use ego-go for hardware")
		}
		if e := localio.ReadJSON(*dev, &c); e != nil {
			return e
		}
		if !c.Development || *publicCert == "" {
			return fmt.Errorf("development config and certificate output required")
		}
	}
	if *tid == 0 || *input == "" || *maxInput <= 0 || *maxInput > worker.MaxCiphertextBytes {
		return fmt.Errorf("tid, input and input limit within the compiled policy required")
	}
	debug.SetMemoryLimit(worker.GoMemoryTarget)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ledger, e := chain.Dial(ctx, c)
	if e != nil {
		return e
	}
	defer ledger.Close()
	t, e := ledger.Trade(ctx, *tid, true)
	if e != nil {
		return e
	}
	if t.Status != 2 {
		return fmt.Errorf("worker requires funded trade")
	}
	loader := func() ([]byte, error) {
		return worker.ReadInput(*input, *maxInput)
	}
	s, e := worker.New(ledger, ledger.Domain(*tid), loader, platform.Prove, !platform.HardwareBuild)
	if e != nil {
		return e
	}
	if *publicCert != "" {
		if e = localio.Write(*publicCert, s.CertificatePEM()); e != nil {
			return e
		}
	}
	if *initTimings {
		t := s.InitializationTimings()
		log.Printf("initialization hardware=%t key_and_certificate_ns=%d report_ns=%d total_ns=%d", platform.HardwareBuild, t.KeyAndCertificate, t.Report, t.Total)
	}
	server := &http.Server{Addr: *listen, Handler: s.Handler(), TLSConfig: s.TLSConfig(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	// No keys, inputs, plaintext results or receipts are logged to the host.
	log.Printf("worker listening on %s; hardware=%t", *listen, platform.HardwareBuild)
	return server.ListenAndServeTLS("", "")
}
