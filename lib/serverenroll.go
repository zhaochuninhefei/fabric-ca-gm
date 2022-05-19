/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"encoding/asn1"
	"encoding/pem"
	"time"

	"gitee.com/zhaochuninhefei/cfssl-gm/config"
	"gitee.com/zhaochuninhefei/cfssl-gm/csr"
	cferr "gitee.com/zhaochuninhefei/cfssl-gm/errors"
	"gitee.com/zhaochuninhefei/cfssl-gm/signer"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/internal/pkg/api"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/internal/pkg/util"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/lib/caerrors"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/lib/server/user"
	"gitee.com/zhaochuninhefei/gmgo/x509"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
	"github.com/pkg/errors"
)

const (
	commonNameLength             = 64
	serialNumberLength           = 64
	countryNameLength            = 2
	localityNameLength           = 128
	stateOrProvinceNameLength    = 128
	organizationNameLength       = 64
	organizationalUnitNameLength = 64
)

var (
	// The X.509 BasicConstraints object identifier (RFC 5280, 4.2.1.9)
	basicConstraintsOID   = asn1.ObjectIdentifier{2, 5, 29, 19}
	commonNameOID         = asn1.ObjectIdentifier{2, 5, 4, 3}
	serialNumberOID       = asn1.ObjectIdentifier{2, 5, 4, 5}
	countryOID            = asn1.ObjectIdentifier{2, 5, 4, 6}
	localityOID           = asn1.ObjectIdentifier{2, 5, 4, 7}
	stateOID              = asn1.ObjectIdentifier{2, 5, 4, 8}
	organizationOID       = asn1.ObjectIdentifier{2, 5, 4, 10}
	organizationalUnitOID = asn1.ObjectIdentifier{2, 5, 4, 11}
)

func newEnrollEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Path:      "enroll",
		Methods:   []string{"POST"},
		Handler:   enrollHandler,
		Server:    s,
		successRC: 201,
	}
}

func newReenrollEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Path:      "reenroll",
		Methods:   []string{"POST"},
		Handler:   reenrollHandler,
		Server:    s,
		successRC: 201,
	}
}

// Handle an enroll request, guarded by basic authentication
func enrollHandler(ctx *serverRequestContextImpl) (interface{}, error) {
	zclog.Debug("===== ca服务端开始处理enroll请求")
	id, err := ctx.BasicAuthentication()
	if err != nil {
		return nil, err
	}
	resp, err := handleEnroll(ctx, id)
	if err != nil {
		return nil, err
	}
	err = ctx.ui.LoginComplete()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Handle a reenroll request, guarded by token authentication
func reenrollHandler(ctx *serverRequestContextImpl) (interface{}, error) {
	// Authenticate the caller
	id, err := ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}
	return handleEnroll(ctx, id)
}

// Handle the common processing for enroll and reenroll
func handleEnroll(ctx *serverRequestContextImpl, id string) (interface{}, error) {
	zclog.Debugf("===== 请求证书的用户信息 Name:%s Type:%s", ctx.ui.GetName(), ctx.ui.GetType())
	var req api.EnrollmentRequestNet
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}
	// Get the targeted CA
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	// Set expiry based on the requested CA profile else use expiry from the default profile
	// 从ca配置中读取 ca.Config.Signing.Default : signing.default
	// zclog.Debugf("===== lib/serverenroll.go handleEnroll before req.NotAfter : %s , req.SignRequest.NotAfter: %s", req.NotAfter.Format(time.RFC3339), req.SignRequest.NotAfter.Format(time.RFC3339))
	profile := ca.Config.Signing.Default
	if req.Profile != "" && ca.Config.Signing != nil &&
		ca.Config.Signing.Profiles != nil && ca.Config.Signing.Profiles[req.Profile] != nil {
		profile = ca.Config.Signing.Profiles[req.Profile]
	}
	req.NotAfter = time.Now().Round(time.Minute).Add(profile.Expiry).UTC()

	notBefore, notAfter, err := ca.getCACertExpiry()
	if err != nil {
		return nil, errors.New("Failed to get CA certificate information")
	}

	// Make sure requested expiration for enrollment certificate is not after CA certificate
	// expiration
	if !notAfter.IsZero() && req.NotAfter.After(notAfter) {
		zclog.Debugf("Requested expiry '%s' is after the CA certificate expiry '%s'. Will use CA cert expiry",
			req.NotAfter, notAfter)
		req.NotAfter = notAfter
	}
	// Make sure that requested expiration for enrollment certificate is not before CA certificate
	// expiration
	if !notBefore.IsZero() && req.NotBefore.Before(notBefore) {
		zclog.Debugf("Requested expiry '%s' is before the CA certificate expiry '%s'. Will use CA cert expiry",
			req.NotBefore, notBefore)
		req.NotBefore = notBefore
	}
	// zclog.Debugf("===== lib/serverenroll.go handleEnroll after req.NotAfter : %s , req.SignRequest.NotAfter: %s", req.NotAfter.Format(time.RFC3339), req.SignRequest.NotAfter.Format(time.RFC3339))

	// Process the sign request from the caller.
	// Make sure it is authorized and do any swizzling appropriate to the request.
	// 内部使用caller补充了OU信息
	err = processSignRequest(id, &req.SignRequest, ca, ctx)
	if err != nil {
		return nil, err
	}
	// Get an attribute extension if one is being requested
	ext, err := ctx.GetAttrExtension(req.AttrReqs, req.Profile)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to find requested attributes")
	}
	// If there is an extension requested, add it to the request
	if ext != nil {
		// zclog.Debugf("Adding attribute extension to CSR: %+v", ext)
		req.Extensions = append(req.Extensions, *ext)
	}
	// Sign the certificate
	// 使用cfssl-gm，已实现国密改造
	cert, err := ca.enrollSigner.Sign(req.SignRequest)
	if err != nil {
		return nil, errors.WithMessage(err, "Certificate signing failure")
	}
	// Add server info to the response
	resp := &api.EnrollmentResponseNet{
		Cert: util.B64Encode(cert),
	}
	err = ca.fillCAInfo(&resp.ServerInfo)
	if err != nil {
		return nil, err
	}
	// Success
	zclog.Debugf("===== 用户:%s (Type:%s)的证书拉取请求成功", ctx.ui.GetName(), ctx.ui.GetType())
	return resp, nil
}

// Process the sign request.
// Make any authorization checks needed, depending on the contents
// of the CSR (Certificate Signing Request).
// In particular, if the request is for an intermediate CA certificate,
// the caller must have the "hf.IntermediateCA" attribute.
// Check to see that CSR values do not exceed the character limit
// as specified in RFC 3280, page 103.
// Set the OU fields of the request.
func processSignRequest(id string, req *signer.SignRequest, ca *CA, ctx *serverRequestContextImpl) error {
	// Decode and parse the request into a CSR so we can make checks
	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return caerrors.NewHTTPErr(400, caerrors.ErrBadCSR, "CSR Decode failed")
	}
	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return cferr.Wrap(cferr.CSRError,
			cferr.BadRequest, errors.New("not a certificate or csr"))
	}
	var csrReq *x509.CertificateRequest
	var err error
	// if IsGMConfig() {
	// 	sm2csrReq, err := gx509.ParseCertificateRequest(block.Bytes)
	// 	if err == nil {
	// 		csrReq = ParseSm2CertificateRequest2X509(sm2csrReq)
	// 	}
	// } else {
	// 	csrReq, err = x509.ParseCertificateRequest(block.Bytes)
	// }
	csrReq, err = x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	// zclog.Debugf("===== req.Subject: %#v", req.Subject)
	// zclog.Debugf("Processing sign request: id=%s, CommonName=%s, Subject=%#v", id, csrReq.Subject.CommonName, csrReq.Subject)
	if (req.Subject != nil && req.Subject.CN != id) || csrReq.Subject.CommonName != id {
		return caerrors.NewHTTPErr(403, caerrors.ErrCNInvalidEnroll, "The CSR subject common name must equal the enrollment ID")
	}
	isForCACert, err := isRequestForCASigningCert(csrReq, ca, req.Profile)
	if err != nil {
		return err
	}
	if isForCACert {
		// This is a request for a CA certificate, so make sure the caller
		// has the 'hf.IntermediateCA' attribute
		err := ca.attributeIsTrue(id, "hf.IntermediateCA")
		if err != nil {
			return caerrors.NewAuthorizationErr(caerrors.ErrInvokerMissAttr, "Enrolled failed: %s", err)
		}
	}
	// Check the CSR input length
	err = csrInputLengthCheck(csrReq)
	if err != nil {
		return caerrors.NewHTTPErr(400, caerrors.ErrInputValidCSR, "CSR input validation failed: %s", err)
	}
	caller, err := ctx.GetCaller()
	if err != nil {
		return err
	}
	// Set the OUs in the request appropriately.
	setRequestOUs(req, caller)
	zclog.Debug("===== Finished processing sign request")
	return nil
}

// Check to see if this is a request for a CA signing certificate.
// This can occur if the profile or the CSR has the IsCA bit set.
// See the X.509 BasicConstraints extension (RFC 5280, 4.2.1.9).
func isRequestForCASigningCert(csrReq *x509.CertificateRequest, ca *CA, profile string) (bool, error) {
	// Check the profile to see if the IsCA bit is set
	sp := getSigningProfile(ca, profile)
	if sp == nil {
		return false, errors.Errorf("Invalid profile: '%s'", profile)
	}
	if sp.CAConstraint.IsCA {
		zclog.Debugf("Request is for a CA signing certificate as set in profile '%s'", profile)
		return true, nil
	}
	// Check the CSR to see if the IsCA bit is set
	for _, val := range csrReq.Extensions {
		if val.Id.Equal(basicConstraintsOID) {
			var constraints csr.BasicConstraints
			var rest []byte
			var err error
			if rest, err = asn1.Unmarshal(val.Value, &constraints); err != nil {
				return false, caerrors.NewHTTPErr(400, caerrors.ErrBadCSR, "Failed parsing CSR constraints: %s", err)
			} else if len(rest) != 0 {
				return false, caerrors.NewHTTPErr(400, caerrors.ErrBadCSR, "Trailing data after X.509 BasicConstraints")
			}
			if constraints.IsCA {
				zclog.Debug("Request is for a CA signing certificate as indicated in the CSR")
				return true, nil
			}
		}
	}
	// The IsCA bit was not set
	zclog.Debug("Request is not for a CA signing certificate")
	return false, nil
}

func getSigningProfile(ca *CA, profile string) *config.SigningProfile {
	if profile == "" {
		return ca.Config.Signing.Default
	}
	return ca.Config.Signing.Profiles[profile]
}

// Checks to make sure that character limits are not exceeded for CSR fields
func csrInputLengthCheck(req *x509.CertificateRequest) error {
	zclog.Debug("Checking CSR fields to make sure that they do not exceed maximum character limits")

	for _, n := range req.Subject.Names {
		value := n.Value.(string)
		switch {
		case n.Type.Equal(commonNameOID):
			if len(value) > commonNameLength {
				return errors.Errorf("The CN '%s' exceeds the maximum character limit of %d", value, commonNameLength)
			}
		case n.Type.Equal(serialNumberOID):
			if len(value) > serialNumberLength {
				return errors.Errorf("The serial number '%s' exceeds the maximum character limit of %d", value, serialNumberLength)
			}
		case n.Type.Equal(organizationalUnitOID):
			if len(value) > organizationalUnitNameLength {
				return errors.Errorf("The organizational unit name '%s' exceeds the maximum character limit of %d", value, organizationalUnitNameLength)
			}
		case n.Type.Equal(organizationOID):
			if len(value) > organizationNameLength {
				return errors.Errorf("The organization name '%s' exceeds the maximum character limit of %d", value, organizationNameLength)
			}
		case n.Type.Equal(countryOID):
			if len(value) > countryNameLength {
				return errors.Errorf("The country name '%s' exceeds the maximum character limit of %d", value, countryNameLength)
			}
		case n.Type.Equal(localityOID):
			if len(value) > localityNameLength {
				return errors.Errorf("The locality name '%s' exceeds the maximum character limit of %d", value, localityNameLength)
			}
		case n.Type.Equal(stateOID):
			if len(value) > stateOrProvinceNameLength {
				return errors.Errorf("The state name '%s' exceeds the maximum character limit of %d", value, stateOrProvinceNameLength)
			}
		}
	}

	return nil
}

// Set the OU fields of the sign request based on the identity's type and affiliation.
// For example, if the type is 'peer' and the affiliation is 'a.b.c', the
// OUs become 'OU=c,OU=b,OU=a,OU=peer'.
// This is necessary because authorization decisions are made based on the OU fields,
// so we ignore any OU values specified in the enroll request and set them according
// to the type and affiliation.
func setRequestOUs(req *signer.SignRequest, caller user.User) {
	s := req.Subject
	if s == nil {
		s = &signer.Subject{}
	}
	names := []csr.Name{}
	// Add non-OU fields from request
	for _, name := range s.Names {
		if name.C != "" || name.L != "" || name.O != "" || name.ST != "" || name.SerialNumber != "" {
			name.OU = ""
			names = append(names, name)
		}
	}
	// Add an OU field with the type
	// zclog.Debugf("===== lib/serverenroll.go setRequestOUs caller.GetType: %s\n", caller.GetType())
	names = append(names, csr.Name{OU: caller.GetType()})
	for _, aff := range caller.GetAffiliationPath() {
		names = append(names, csr.Name{OU: aff})
	}
	// zclog.Debugf("===== lib/serverenroll.go setRequestOUs names: %v\n", names)
	// Replace with new names
	s.Names = names
	req.Subject = s
	// zclog.Debugf("===== lib/serverenroll.go setRequestOUs req.Subject: %#v\n", req.Subject)
}
