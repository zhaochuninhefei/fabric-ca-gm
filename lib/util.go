/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	http "gitee.com/zhaochuninhefei/gmgo/gmhttp"

	"gitee.com/zhaochuninhefei/gmgo/x509"

	"gitee.com/zhaochuninhefei/fabric-ca-gm/internal/pkg/api"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/lib/caerrors"
	tls "gitee.com/zhaochuninhefei/gmgo/gmtls"
	certinfo "gitee.com/zhaochuninhefei/gmgo/x509"
	gx509 "gitee.com/zhaochuninhefei/gmgo/x509"
	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

var clientAuthTypes = map[string]tls.ClientAuthType{
	"noclientcert":               tls.NoClientCert,
	"requestclientcert":          tls.RequestClientCert,
	"requireanyclientcert":       tls.RequireAnyClientCert,
	"verifyclientcertifgiven":    tls.VerifyClientCertIfGiven,
	"requireandverifyclientcert": tls.RequireAndVerifyClientCert,
}

// BytesToX509Cert converts bytes (PEM or DER) to an X509 certificate
func BytesToX509Cert(bytes []byte) (*x509.Certificate, error) {
	dcert, _ := pem.Decode(bytes)
	if dcert != nil {
		bytes = dcert.Bytes
	}
	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Buffer was neither PEM nor DER encoding")
	}
	return cert, err
}

// TODO 国密改造
// LoadPEMCertPool loads a pool of PEM certificates from list of files
func LoadPEMCertPool(certFiles []string) (*gx509.CertPool, error) {
	certPool := gx509.NewCertPool()

	if len(certFiles) > 0 {
		for _, cert := range certFiles {
			log.Debugf("Reading cert file: %s", cert)
			pemCerts, err := ioutil.ReadFile(cert)
			if err != nil {
				return nil, err
			}

			log.Debugf("Appending cert %s to pool", cert)
			if !certPool.AppendCertsFromPEM(pemCerts) {
				return nil, errors.New("Failed to load cert pool")
			}
		}
	}

	return certPool, nil
}

// UnmarshalConfig unmarshals a configuration file
func UnmarshalConfig(config interface{}, vp *viper.Viper, configFile string,
	server bool) error {

	vp.SetConfigFile(configFile)
	err := vp.ReadInConfig()
	if err != nil {
		return errors.Wrapf(err, "Failed to read config file '%s'", configFile)
	}

	err = vp.Unmarshal(config)
	if err != nil {
		return errors.Wrapf(err, "Incorrect format in file '%s'", configFile)
	}
	if server {
		serverCfg := config.(*ServerConfig)
		err = vp.Unmarshal(&serverCfg.CAcfg)
		if err != nil {
			return errors.Wrapf(err, "Incorrect format in file '%s'", configFile)
		}
	}
	return nil
}

func getMaxEnrollments(userMaxEnrollments int, caMaxEnrollments int) (int, error) {
	log.Debugf("Max enrollment value verification - User specified max enrollment: %d, CA max enrollment: %d", userMaxEnrollments, caMaxEnrollments)
	if userMaxEnrollments < -1 {
		return 0, caerrors.NewHTTPErr(400, caerrors.ErrInvalidMaxEnroll, "Max enrollment in registration request may not be less than -1, but was %d", userMaxEnrollments)
	}
	switch caMaxEnrollments {
	case -1:
		if userMaxEnrollments == 0 {
			// The user is requesting the matching limit of the CA, so gets infinite
			return caMaxEnrollments, nil
		}
		// There is no CA max enrollment limit, so simply use the user requested value
		return userMaxEnrollments, nil
	case 0:
		// The CA max enrollment is 0, so registration is disabled.
		return 0, caerrors.NewHTTPErr(400, caerrors.ErrInvalidMaxEnroll, "Registration is disabled")
	default:
		switch userMaxEnrollments {
		case -1:
			// User requested infinite enrollments is not allowed
			return 0, caerrors.NewHTTPErr(400, caerrors.ErrInvalidMaxEnroll, "Registration for infinite enrollments is not allowed")
		case 0:
			// User is requesting the current CA maximum
			return caMaxEnrollments, nil
		default:
			// User is requesting a specific positive value; make sure it doesn't exceed the CA maximum.
			if userMaxEnrollments > caMaxEnrollments {
				return 0, caerrors.NewHTTPErr(400, caerrors.ErrInvalidMaxEnroll, "Requested enrollments (%d) exceeds maximum allowable enrollments (%d)", userMaxEnrollments, caMaxEnrollments)
			}
			// otherwise, use the requested maximum
			return userMaxEnrollments, nil
		}
	}
}

func addQueryParm(req *http.Request, name, value string) {
	url := req.URL.Query()
	url.Add(name, value)
	req.URL.RawQuery = url.Encode()
}

// IdentityDecoder decodes streams of data coming from the server into an Identity object
func IdentityDecoder(decoder *json.Decoder) error {
	var id api.IdentityInfo
	err := decoder.Decode(&id)
	if err != nil {
		return err
	}
	fmt.Printf("Name: %s, Type: %s, Affiliation: %s, Max Enrollments: %d, Attributes: %+v\n", id.ID, id.Type, id.Affiliation, id.MaxEnrollments, id.Attributes)
	return nil
}

// TODO 代码补充
// AffiliationDecoder decodes streams of data coming from the server into an Affiliation object
func AffiliationDecoder(decoder *json.Decoder) error {
	var aff api.AffiliationInfo
	err := decoder.Decode(&aff)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", aff.Name)
	return nil
}

// CertificateDecoder is needed to keep track of state, to see how many certificates
// have been returned for each enrollment ID.
type CertificateDecoder struct {
	certIDCount map[string]int
	storePath   string
}

// NewCertificateDecoder returns decoder for certificates
func NewCertificateDecoder(storePath string) *CertificateDecoder {
	cd := &CertificateDecoder{}
	cd.certIDCount = make(map[string]int)
	cd.storePath = storePath
	return cd
}

// CertificateDecoder decodes streams of data coming from the server
func (cd *CertificateDecoder) CertificateDecoder(decoder *json.Decoder) error {
	var cert certPEM
	err := decoder.Decode(&cert)
	if err != nil {
		return err
	}
	block, rest := pem.Decode([]byte(cert.PEM))
	if block == nil || len(rest) > 0 {
		return errors.New("Certificate decoding error")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	enrollmentID := certificate.Subject.CommonName
	if cd.storePath != "" {
		err = cd.storeCert(enrollmentID, cd.storePath, []byte(cert.PEM))
		if err != nil {
			return err
		}
	}
	result, err := certinfo.CertificateText(certificate)
	if err != nil {
		return err
	}
	fmt.Printf(result)
	return nil
}

// storeCert stores the certificate on the file system
func (cd *CertificateDecoder) storeCert(enrollmentID, storePath string, cert []byte) error {
	cd.certIDCount[enrollmentID] = cd.certIDCount[enrollmentID] + 1

	err := os.MkdirAll(storePath, os.ModePerm)
	if err != nil {
		return err
	}

	var filePath string
	singleCertName := fmt.Sprintf("%s.pem", enrollmentID)
	switch cd.certIDCount[enrollmentID] {
	case 1: // Only one certificate returned, don't need to append number to certificate file name
		filePath = filepath.Join(storePath, singleCertName)
	case 2: // Two certificates returned, rename the old certificate to have number at the end
		err := os.Rename(filepath.Join(storePath, singleCertName), filepath.Join(storePath, fmt.Sprintf("%s-1.pem", enrollmentID)))
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("Failed to rename certificate: %s", singleCertName))
		}
		filePath = filepath.Join(storePath, fmt.Sprintf("%s-%d.pem", enrollmentID, cd.certIDCount[enrollmentID]))
	default:
		filePath = filepath.Join(storePath, fmt.Sprintf("%s-%d.pem", enrollmentID, cd.certIDCount[enrollmentID]))
	}

	err = ioutil.WriteFile(filePath, cert, 0644)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Failed to store certificate at: %s", storePath))
	}

	return nil
}

// TODO 国密改造
// SM2证书请求 转换 X509 证书请求
func ParseSm2CertificateRequest2X509(sm2req *gx509.CertificateRequest) *x509.CertificateRequest {
	x509req := &x509.CertificateRequest{
		Raw:                      sm2req.Raw,                      // Complete ASN.1 DER content (CSR, signature algorithm and signature).
		RawTBSCertificateRequest: sm2req.RawTBSCertificateRequest, // Certificate request info part of raw ASN.1 DER content.
		RawSubjectPublicKeyInfo:  sm2req.RawSubjectPublicKeyInfo,  // DER encoded SubjectPublicKeyInfo.
		RawSubject:               sm2req.RawSubject,               // DER encoded Subject.

		Version:            sm2req.Version,
		Signature:          sm2req.Signature,
		SignatureAlgorithm: x509.SignatureAlgorithm(sm2req.SignatureAlgorithm),

		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(sm2req.PublicKeyAlgorithm),
		PublicKey:          sm2req.PublicKey,

		Subject: sm2req.Subject,

		// Attributes is the dried husk of a bug and shouldn't be used.
		Attributes: sm2req.Attributes,

		// Extensions contains raw X.509 extensions. When parsing CSRs, this
		// can be used to extract extensions that are not parsed by this
		// package.
		Extensions: sm2req.Extensions,

		// ExtraExtensions contains extensions to be copied, raw, into any
		// marshaled CSR. Values override any extensions that would otherwise
		// be produced based on the other fields but are overridden by any
		// extensions specified in Attributes.
		//
		// The ExtraExtensions field is not populated when parsing CSRs, see
		// Extensions.
		ExtraExtensions: sm2req.ExtraExtensions,

		// Subject Alternate Name values.
		DNSNames:       sm2req.DNSNames,
		EmailAddresses: sm2req.EmailAddresses,
		IPAddresses:    sm2req.IPAddresses,
	}
	return x509req
}

var providerName string

func IsGMConfig() bool {
	if providerName == "" {
		return false
	}
	if strings.ToUpper(providerName) == "GM" {
		return true
	}
	return false
}

func SetProviderName(name string) {
	providerName = name
}
