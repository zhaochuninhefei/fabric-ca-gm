/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"
	_ "time" // for ocspSignerFromConfig

	_ "gitee.com/zhaochuninhefei/cfssl-gm/cli" // for ocspSignerFromConfig
	"gitee.com/zhaochuninhefei/cfssl-gm/config"
	"gitee.com/zhaochuninhefei/cfssl-gm/csr"
	_ "gitee.com/zhaochuninhefei/cfssl-gm/ocsp" // for ocspSignerFromConfig
	"gitee.com/zhaochuninhefei/cfssl-gm/signer"
	"gitee.com/zhaochuninhefei/cfssl-gm/signer/local"
	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/factory"
	cspsigner "gitee.com/zhaochuninhefei/fabric-gm/bccsp/signer"
	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/utils"
	gtls "gitee.com/zhaochuninhefei/gmgo/gmtls"
	"gitee.com/zhaochuninhefei/gmgo/sm2"
	gx509 "gitee.com/zhaochuninhefei/gmgo/x509"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
	"github.com/pkg/errors"
)

// GetDefaultBCCSP returns the default BCCSP
func GetDefaultBCCSP() bccsp.BCCSP {
	return factory.GetDefault()
}

// InitBCCSP initializes BCCSP
func InitBCCSP(optsPtr **factory.FactoryOpts, mspDir, homeDir string) (bccsp.BCCSP, error) {
	err := ConfigureBCCSP(optsPtr, mspDir, homeDir)
	if err != nil {
		return nil, err
	}
	csp, err := GetBCCSP(*optsPtr, homeDir)
	if err != nil {
		return nil, err
	}
	return csp, nil
}

// GetBCCSP returns BCCSP
func GetBCCSP(opts *factory.FactoryOpts, homeDir string) (bccsp.BCCSP, error) {

	// Get BCCSP from the opts
	csp, err := factory.GetBCCSPFromOpts(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to get BCCSP with opts")
	}
	return csp, nil
}

// makeFileNamesAbsolute makes all relative file names associated with CSP absolute,
// relative to 'homeDir'.
func makeFileNamesAbsolute(opts *factory.FactoryOpts, homeDir string) error {
	var err error
	if opts != nil && opts.SwOpts != nil && opts.SwOpts.FileKeystore != nil {
		fks := opts.SwOpts.FileKeystore
		fks.KeyStorePath, err = MakeFileAbs(fks.KeyStorePath, homeDir)
	}
	return err
}

// BccspBackedSigner attempts to create a signer using csp bccsp.BCCSP. This csp could be SW (golang crypto)
// PKCS11 or whatever BCCSP-conformant library is configured
func BccspBackedSigner(caFile, keyFile string, policy *config.Signing, csp bccsp.BCCSP) (signer.Signer, error) {
	_, cspSigner, parsedCa, err := GetSignerFromCertFile(caFile, csp)
	if err != nil {
		// Fallback: attempt to read out of keyFile and import
		zclog.Debugf("===== No key found in BCCSP keystore, attempting fallback")
		var key bccsp.Key
		var signer crypto.Signer

		key, err = ImportBCCSPKeyFromPEM(keyFile, csp, false)
		if err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("Could not find the private key in BCCSP keystore nor in keyfile '%s'", keyFile))
		}

		signer, err = cspsigner.New(csp, key)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed initializing CryptoSigner")
		}
		cspSigner = signer
	}
	signer, err := local.NewSigner(cspSigner, parsedCa, signer.DefaultSigAlgo(cspSigner), policy)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create new signer")
	}
	return signer, nil
}

// getBCCSPKeyOpts generates a key as specified in the request.
// This supports ECDSA and RSA.
// 国密改造后只支持sm2
func getBCCSPKeyOpts(kr *csr.KeyRequest, ephemeral bool) (opts bccsp.KeyGenOpts, err error) {
	if kr == nil {
		return &bccsp.SM2KeyGenOpts{Temporary: ephemeral}, nil
	}
	zclog.Debugf("===== generate key from request: algo=%s, size=%d", kr.Algo(), kr.Size())
	switch kr.Algo() {
	// case "rsa":
	// 	switch kr.Size() {
	// 	case 2048:
	// 		return &bccsp.RSA2048KeyGenOpts{Temporary: ephemeral}, nil
	// 	case 3072:
	// 		return &bccsp.RSA3072KeyGenOpts{Temporary: ephemeral}, nil
	// 	case 4096:
	// 		return &bccsp.RSA4096KeyGenOpts{Temporary: ephemeral}, nil
	// 	default:
	// 		// Need to add a way to specify arbitrary RSA key size to bccsp
	// 		return nil, errors.Errorf("Invalid RSA key size: %d", kr.Size())
	// 	}
	// case "ecdsa":
	// 	switch kr.Size() {
	// 	case 256:
	// 		return &bccsp.ECDSAP256KeyGenOpts{Temporary: ephemeral}, nil
	// 	case 384:
	// 		return &bccsp.ECDSAP384KeyGenOpts{Temporary: ephemeral}, nil
	// 	case 521:
	// 		// Need to add curve P521 to bccsp
	// 		// return &bccsp.ECDSAP512KeyGenOpts{Temporary: false}, nil
	// 		return nil, errors.New("Unsupported ECDSA key size: 521")
	// 	default:
	// 		return nil, errors.Errorf("Invalid ECDSA key size: %d", kr.Size())
	// 	}
	case bccsp.SM2:
		return &bccsp.SM2KeyGenOpts{Temporary: ephemeral}, nil
	default:
		return nil, errors.Errorf("Invalid algorithm: %s", kr.Algo())
	}
}

// 根据国密x509证书中获取私钥与Signer。
// GetSignerFromCert load private key represented by ski and return bccsp signer that conforms to crypto.Signer
func GetSignerFromCert(cert *gx509.Certificate, csp bccsp.BCCSP) (bccsp.Key, crypto.Signer, error) {
	if csp == nil {
		return nil, nil, errors.New("CSP was not initialized")
	}
	// zclog.Infof("===== internal/pkg/util/csp.go GetSignerFromCert: begin csp.KeyImport,cert.PublicKey is %T   csp:%T", cert.PublicKey, csp)
	// switch cert.PublicKey.(type) {
	// case sm2.PublicKey:
	// 	zclog.Infof("===== internal/pkg/util/csp.go GetSignerFromCert: cert is sm2 puk")
	// default:
	// 	zclog.Infof("===== internal/pkg/util/csp.go GetSignerFromCert: cert is default puk")
	// }

	// sm2cert := sw.ParseX509Certificate2Sm2(cert)
	// get the public key in the right format
	// 从国密x509证书中获取证书公钥
	certPubK, err := csp.KeyImport(cert, &bccsp.GMX509PublicKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to import certificate's public key")
	}
	ski := certPubK.SKI()
	kname := hex.EncodeToString(ski)
	// zclog.Infof("===== internal/pkg/util/csp.go GetSignerFromCert: begin csp.GetKey kname:%s", kname)
	// Get the key given the SKI value
	privateKey, err := csp.GetKey(ski)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Could not find matching private key for SKI")
	}
	// BCCSP returns a public key if the private key for the SKI wasn't found, so
	// we need to return an error in that case.
	if !privateKey.Private() {
		return nil, nil, errors.Errorf("The private key associated with the certificate with SKI '%s' was not found", kname)
	}
	// Construct and initialize the signer
	signer, err := cspsigner.New(csp, privateKey)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to load ski from bccsp")
	}
	// zclog.Info("===== internal/pkg/util/csp.go GetSignerFromCert successfuul")
	return privateKey, signer, nil
}

// 根据x509证书文件获取对应的私钥、Signer以及x509证书。
// GetSignerFromCertFile load skiFile and load private key represented by ski and return bccsp signer that conforms to crypto.Signer
func GetSignerFromCertFile(certFile string, csp bccsp.BCCSP) (bccsp.Key, crypto.Signer, *gx509.Certificate, error) {
	// zclog.Infof("===== internal/pkg/util/csp.go GetSignerFromCertFile:certFile:,%s", certFile)
	// Load cert file
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "Could not read certFile '%s'", certFile)
	}
	// TODO 修改为国密
	// // Parse certificate
	// parsedCa, err := helpers.ParseCertificatePEM(certBytes)
	// if err != nil {
	// 	return nil, nil, nil, err
	// }
	// // Get the signer from the cert
	// key, cspSigner, err := GetSignerFromCert(parsedCa, csp)
	// return key, cspSigner, parsedCa, err

	// cert, err := helpers.ParseCertificatePEM(certBytes)
	cert, _ := gx509.ReadCertificateFromPem(certBytes)
	// if err != nil || cert == nil {
	// 	zclog.Infof("===== error = %s,尝试作为 gm cert 读入!", err.Error())
	// 	sm2Cert, err := gx509.ReadCertificateFromPem(certBytes)
	// 	if err != nil {
	// 		return nil, nil, nil, err
	// 	}
	// 	cert = sw.ParseSm2Certificate2X509(sm2Cert)
	// }
	key, cspSigner, err := GetSignerFromCert(cert, csp)
	// zclog.Infof("===== KEY = %T error = %v", key, err)
	return key, cspSigner, cert, err
}

// BCCSPKeyRequestGenerate generates keys through BCCSP
// somewhat mirroring to cfssl/req.KeyRequest.Generate()
func BCCSPKeyRequestGenerate(req *csr.CertificateRequest, myCSP bccsp.BCCSP) (bccsp.Key, crypto.Signer, error) {
	zclog.Infof("===== generating key: %+v", req.KeyRequest)
	keyOpts, err := getBCCSPKeyOpts(req.KeyRequest, false)
	if err != nil {
		return nil, nil, err
	}
	key, err := myCSP.KeyGen(keyOpts)
	if err != nil {
		return nil, nil, err
	}
	cspSigner, err := cspsigner.New(myCSP, key)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed initializing CryptoSigner")
	}
	return key, cspSigner, nil
}

// ImportBCCSPKeyFromPEM attempts to create a private BCCSP key from a pem file keyFile
func ImportBCCSPKeyFromPEM(keyFile string, myCSP bccsp.BCCSP, temporary bool) (bccsp.Key, error) {
	keyBuff, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := utils.PEMtoPrivateKey(keyBuff, nil)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed parsing private key from %s", keyFile))
	}
	// TODO 国密对应
	// switch key := key.(type) {
	switch key.(type) {
	case *sm2.PrivateKey:
		opts := &factory.FactoryOpts{
			ProviderName: "SW",
			SwOpts: &factory.SwOpts{
				HashFamily: bccsp.SM3,
				SecLevel:   256,
				FileKeystore: &factory.FileKeystoreOpts{
					KeyStorePath: keyFile,
				},
			},
			UsingGM: "Y",
		}
		csp, err := factory.GetBCCSPFromOpts(opts)
		if err != nil {
			return nil, errors.Errorf("Failed to convert SM2 private key from %s: %s", keyFile, err.Error())
		}
		block, _ := pem.Decode(keyBuff)
		priv, err := csp.KeyImport(block.Bytes, &bccsp.SM2PrivateKeyImportOpts{Temporary: true})
		if err != nil {
			return nil, errors.Errorf("Failed to convert SM2 private key from %s: %s", keyFile, err.Error())
		}
		return priv, nil
	// case *ecdsa.PrivateKey:
	// TODO 国密对应，去除对ECDSA的支持
	// priv, err := utils.PrivateKeyToDER(key)
	// if err != nil {
	// 	return nil, errors.WithMessage(err, fmt.Sprintf("Failed to convert ECDSA private key for '%s'", keyFile))
	// }
	// sk, err := myCSP.KeyImport(priv, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: temporary})
	// if err != nil {
	// 	return nil, errors.WithMessage(err, fmt.Sprintf("Failed to import ECDSA private key for '%s'", keyFile))
	// }
	// return sk, nil
	// return nil, errors.Errorf("Failed to import ECDSA key from %s; ECDSA private key import is not supported", keyFile)
	// case *rsa.PrivateKey:
	// 	return nil, errors.Errorf("Failed to import RSA key from %s; RSA private key import is not supported", keyFile)
	default:
		return nil, errors.Errorf("Failed to import key from %s: invalid secret key type", keyFile)
	}
}

// LoadX509KeyPair reads and parses a public/private key pair from a pair
// of files. The files must contain PEM encoded data. The certificate file
// may contain intermediate certificates following the leaf certificate to
// form a certificate chain. On successful return, Certificate.Leaf will
// be nil because the parsed form of the certificate is not retained.
//
// This function originated from crypto/tls/tls.go and was adapted to use a
// BCCSP Signer
func LoadX509KeyPair(certFile, keyFile string, csp bccsp.BCCSP) (*gtls.Certificate, error) {

	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	cert := &gtls.Certificate{}
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return nil, errors.Errorf("Failed to find PEM block in file %s", certFile)
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return nil, errors.Errorf("Failed to find certificate PEM data in file %s, but did find a private key; PEM inputs may have been switched", certFile)
		}
		return nil, errors.Errorf("Failed to find \"CERTIFICATE\" PEM block in file %s after skipping PEM blocks of the following types: %v", certFile, skippedBlockTypes)
	}

	sm2Cert, err := gx509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	// x509Cert := sw.ParseSm2Certificate2X509(sm2Cert)
	_, cert.PrivateKey, err = GetSignerFromCert(sm2Cert, csp)
	if err != nil {
		if keyFile != "" {
			zclog.Debugf("===== Could not load TLS certificate with BCCSP: %s", err)
			zclog.Debugf("===== Attempting fallback with certfile %s and keyfile %s", certFile, keyFile)
			fallbackCerts, err := gtls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, errors.Wrapf(err, "Could not get the private key %s that matches %s", keyFile, certFile)
			}
			cert = &fallbackCerts
		} else {
			return nil, errors.WithMessage(err, "Could not load TLS certificate with BCCSP")
		}

	}

	return cert, nil
}

func LoadX509KeyPairSM2(certFile, keyFile string, csp bccsp.BCCSP) (*gtls.Certificate, error) {

	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	cert := &gtls.Certificate{}
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return nil, errors.Errorf("Failed to find PEM block in file %s", certFile)
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return nil, errors.Errorf("Failed to find certificate PEM data in file %s, but did find a private key; PEM inputs may have been switched", certFile)
		}
		return nil, errors.Errorf("Failed to find \"CERTIFICATE\" PEM block in file %s after skipping PEM blocks of the following types: %v", certFile, skippedBlockTypes)
	}

	sm2Cert, err := gx509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	// x509Cert := sw.ParseSm2Certificate2X509(sm2Cert)
	_, cert.PrivateKey, err = GetSignerFromCert(sm2Cert, csp)
	if err != nil {
		if keyFile != "" {
			zclog.Debugf("===== Could not load TLS certificate with BCCSP: %s", err)
			zclog.Debugf("===== Attempting fallback with certfile %s and keyfile %s", certFile, keyFile)
			fallbackCerts, err := gtls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, errors.Wrapf(err, "Could not get the private key %s that matches %s", keyFile, certFile)
			}
			cert = &fallbackCerts
		} else {
			return nil, errors.WithMessage(err, "Could not load TLS certificate with BCCSP")
		}

	}

	return cert, nil
}
