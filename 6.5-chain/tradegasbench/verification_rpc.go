package main

import (
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strings"
)

// A verifier may use archive-capable endpoints without changing the measured
// chain, contract, code hash or development mode in the immutable run record.
type verificationRPC struct {
	RPC          string `json:"rpc"`
	RPCSPKI      string `json:"rpc_spki"`
	SecondaryRPC string `json:"secondary_rpc"`
}

func (v verificationRPC) apply(r *record) error {
	u, err := url.Parse(v.RPC)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid verification RPC")
	}
	if r.Chain.Development {
		if u.Scheme != "http" || (u.Hostname() != "localhost" && !net.ParseIP(u.Hostname()).IsLoopback()) {
			return errors.New("local verification requires loopback HTTP")
		}
	} else {
		pin, err := hex.DecodeString(v.RPCSPKI)
		if u.Scheme != "https" || err != nil || len(pin) != 32 {
			return errors.New("verification requires HTTPS and a SHA-256 SPKI pin")
		}
		other, err := url.Parse(v.SecondaryRPC)
		if err != nil || strings.EqualFold(u.Hostname(), other.Hostname()) {
			return errors.New("independent verification RPC hosts required")
		}
	}
	c := r.Chain
	c.RPC, c.RPCSPKI = v.RPC, v.RPCSPKI
	if err := secondary(c, v.SecondaryRPC); err != nil {
		return err
	}
	r.Chain, r.SecondaryRPC = c, v.SecondaryRPC
	return nil
}
