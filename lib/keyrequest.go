//go:build pkcs11
// +build pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"gitee.com/zhaochuninhefei/fabric-ca-gm/internal/pkg/api"
	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
)

// GetKeyRequest constructs and returns api.KeyRequest object based on the bccsp
// configuration options
func GetKeyRequest(cfg *CAConfig) *api.KeyRequest {
	if cfg.CSP.SwOpts != nil {
		return &api.KeyRequest{Algo: "ecdsa", Size: cfg.CSP.SwOpts.SecLevel}
	} else if cfg.CSP.Pkcs11Opts != nil {
		return &api.KeyRequest{Algo: "ecdsa", Size: cfg.CSP.Pkcs11Opts.SecLevel}
	} else {
		return api.NewKeyRequest()
	}
}

func GetGMKeyRequest(cfg *CAConfig) *api.KeyRequest {
	if cfg.CSP.SwOpts != nil {
		return &api.KeyRequest{Algo: bccsp.GMSM2, Size: cfg.CSP.SwOpts.SecLevel}
	}
	return api.NewGMKeyRequest()
}
