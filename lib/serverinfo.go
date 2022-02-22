/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"gitee.com/zhaochuninhefei/fabric-ca-gm/internal/pkg/api"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/lib/metadata"
)

func newCAInfoEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Path:    "cainfo",
		Methods: []string{"GET", "POST", "HEAD"},
		Handler: cainfoHandler,
		Server:  s,
	}
}

// Handle is the handler for the GET or POST /cainfo request
func cainfoHandler(ctx *serverRequestContextImpl) (interface{}, error) {
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	resp := &api.CAInfoResponseNet{}
	err = ca.fillCAInfo(resp)
	if err != nil {
		return nil, err
	}
	resp.Version = metadata.GetVersion()
	return resp, nil
}
