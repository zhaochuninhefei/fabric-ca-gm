package lib

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/mail"
	"time"

	"gitee.com/zhaochuninhefei/cfssl-gm/certdb"
	"gitee.com/zhaochuninhefei/cfssl-gm/csr"
	"gitee.com/zhaochuninhefei/cfssl-gm/log"
	"gitee.com/zhaochuninhefei/cfssl-gm/signer"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/internal/pkg/util"
	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/sw"
	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/x509"
	"github.com/pkg/errors"
)

// 证书签名
func signCert(req signer.SignRequest, ca *CA) (cert []byte, err error) {
	// fmt.Printf("===== lib/gmca.go signCert: CA服务端开始做证书签名\n")
	// fmt.Printf("===== lib/gmca.go signCert req : %#v\n", req.Subject)
	// 注意，这里只把 req.Request 转为pem，丢掉了 req.Subject 信息
	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return nil, errors.Errorf("decode error")
	}
	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.Errorf("not a csr")
	}
	// 生成证书模板,由于之前转换的block中丢掉了req.Subject，这里需要在生成模板之后补充req.Subject中的OU信息。
	template, err := parseCertificateRequestWithSubject(block.Bytes, *req.Subject)
	if err != nil {
		log.Errorf("===== lib/gmca.go signCert: parseCertificateRequest error:[%s]", err)
		return nil, err
	}

	certfile := ca.Config.CA.Certfile
	//certfile := req.Profile
	// log.Infof("===== lib/gmca.go signCert:certifle = %s", certfile)
	// 读取CA证书文件，获取CA的私钥与x509证书
	rootkey, _, rootca, err := util.GetSignerFromCertFile(certfile, ca.csp)
	if err != nil {

		return nil, err
	}
	// log.Infof("===== lib/gmca.go signCert:rootca = %v", rootca)
	// rootca := ParseX509Certificate2Sm2(x509cert)
	// 使用CA的私钥与x509证书给template签名，生成对应证书，并转为pem字节数组
	cert, err = sw.CreateCertificateToMem(template, rootca, rootkey)
	if err != nil {
		return nil, err
	}
	// log.Infof("===== lib/gmca.go signCert:template = %v\n Type = %T", template, template.PublicKey)
	// 将pem字节数组转为x509证书
	clientCert, err := x509.ReadCertificateFromPem(cert)
	// log.Infof("===== lib/gmca.go signCert:template.SerialNumber---,%v", template.SerialNumber)
	// log.Infof("===== lib/gmca.go signCert:clientCert--,%v", clientCert)
	// log.Infof("===== lib/gmca.go signCert:cert--,%v", cert)
	// log.Infof("===== lib/gmca.go signCert:req.Label--,%v", req.Label)
	// log.Infof("===== lib/gmca.go signCert:clientCert.NotAfter--,%v", clientCert.NotAfter)
	// log.Info("===== lib/gmca.go signCert: Exit ParseCertificate")
	if err == nil {
		log.Infof("===== lib/gmca.go signCert: the sign cert len [%d]", len(cert))
	}

	var certRecord = certdb.CertificateRecord{
		Serial:  template.SerialNumber.String(),
		AKI:     hex.EncodeToString(clientCert.AuthorityKeyId),
		CALabel: req.Label,
		Status:  "good",
		Expiry:  clientCert.NotAfter,
		PEM:     string(cert),
	}
	//aki := hex.EncodeToString(cert.AuthorityKeyId)
	//serial := util.GetSerialAsHex(cert.SerialNumber)

	err = ca.certDBAccessor.InsertCertificate(certRecord)
	if err != nil {
		log.Errorf("===== lib/gmca.go signCert error InsertCertificate:[%s]", err)
	}

	return
}

//生成证书
func createGmSm2Cert(key bccsp.Key, req *csr.CertificateRequest, priv crypto.Signer) (cert []byte, err error) {
	// log.Infof("===== lib/gmca.go createGmSm2Cert key :%T", key)

	csrPEM, err := generate(priv, req, key)
	if err != nil {
		log.Errorf("===== lib/gmca.go createGmSm2Cert generate error:%s", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.Errorf("===== lib/gmca.go createGmSm2Cert sm2 csr DecodeFailed")
	}

	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.Errorf("===== lib/gmca.go createGmSm2Cert sm2 not a csr")
	}
	sm2Template, err := parseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	// log.Infof("===== lib/gmca.go createGmSm2Cert key is %T   ---%T", sm2Template.PublicKey, sm2Template)
	cert, err = sw.CreateCertificateToMem(sm2Template, sm2Template, key)
	return
}

// 补充OU信息
func parseCertificateRequestWithSubject(csrBytes []byte, subject signer.Subject) (template *x509.Certificate, err error) {
	template, err = parseCertificateRequest(csrBytes)
	log.Infof("===== lib/gmca.go parseCertificateRequestWithSubject before template.Subject: %#v , subject: %#v", template.Subject, subject)
	if len(subject.Names) > 0 {
		if len(template.Subject.OrganizationalUnit) == 0 {
			var tmpOUs []string
			for _, csrName := range subject.Names {
				if csrName.OU != "" {
					tmpOUs = append(tmpOUs, csrName.OU)
				}
			}
			template.Subject.OrganizationalUnit = tmpOUs
		} else {
			tmpOUs := template.Subject.OrganizationalUnit
			for _, csrName := range subject.Names {
				ouAdd := csrName.OU
				if ouAdd == "" {
					continue
				}
				needAdd := true
				for _, ouExist := range tmpOUs {
					if ouAdd == ouExist {
						needAdd = false
						break
					}
				}
				if needAdd {
					tmpOUs = append(tmpOUs, ouAdd)
				}
			}
			template.Subject.OrganizationalUnit = tmpOUs
		}
	}
	log.Infof("===== lib/gmca.go parseCertificateRequestWithSubject after template.Subject: %#v , subject: %#v", template.Subject, subject)
	return
}

// 证书请求转换成证书  参数为  block .Bytes
func parseCertificateRequest(csrBytes []byte) (template *x509.Certificate, err error) {
	csrv, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}
	err = csrv.CheckSignature()
	if err != nil {
		return nil, err
	}
	template = &x509.Certificate{
		Subject:            csrv.Subject,
		PublicKeyAlgorithm: csrv.PublicKeyAlgorithm,
		PublicKey:          csrv.PublicKey,
		SignatureAlgorithm: csrv.SignatureAlgorithm,
		DNSNames:           csrv.DNSNames,
		IPAddresses:        csrv.IPAddresses,
		EmailAddresses:     csrv.EmailAddresses,
	}
	// fmt.Printf("===== lib/gmca.go parseCertificateRequest:algorithn = %v, %v\n", template.PublicKeyAlgorithm, template.SignatureAlgorithm)
	// log.Infof("===== lib/gmca.go parseCertificateRequest:publicKey :%T", template.PublicKey)
	// 固定有效期间: 100000小时,约11.4年
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().Add(time.Hour * 100000)

	for _, val := range csrv.Extensions {
		// Check the CSR for the X.509 BasicConstraints (RFC 5280, 4.2.1.9)
		// extension and append to template if necessary
		if val.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
			var constraints csr.BasicConstraints
			// var rest []byte
			// if rest, err = asn1.Unmarshal(val.Value, &constraints); err != nil {
			// 	//return nil, cferr.Wrap(cferr.CSRError, cferr.ParseFailed, err)
			// } else if len(rest) != 0 {
			// 	//return nil, cferr.Wrap(cferr.CSRError, cferr.ParseFailed, errors.New("x509: trailing data after X.509 BasicConstraints"))
			// }
			asn1.Unmarshal(val.Value, &constraints)

			template.BasicConstraintsValid = true
			template.IsCA = constraints.IsCA
			template.MaxPathLen = constraints.MaxPathLen
			template.MaxPathLenZero = template.MaxPathLen == 0
		}
	}
	serialNumber := make([]byte, 20)
	_, err = io.ReadFull(rand.Reader, serialNumber)
	if err != nil {
		return nil, err
	}

	// SetBytes interprets buf as the bytes of a big-endian
	// unsigned integer. The leading byte should be masked
	// off to ensure it isn't negative.
	serialNumber[0] &= 0x7F

	template.SerialNumber = new(big.Int).SetBytes(serialNumber)

	return
}

// 证书请求 转成 国密证书请求
func generate(priv crypto.Signer, req *csr.CertificateRequest, key bccsp.Key) (csr []byte, err error) {
	// log.Info("===== lib/gmca.go generate")
	sigAlgo := signerAlgo(priv)
	if sigAlgo == x509.UnknownSignatureAlgorithm {
		return nil, errors.Errorf("===== lib/gmca.go generate Private key is unavailable")
	}
	// log.Info("===== lib/gmca.go generate begin create sm2.CertificateRequest")
	// TODO 添加错误日志
	reqName := req.Name()
	var tpl = x509.CertificateRequest{
		Subject:            reqName,
		SignatureAlgorithm: sigAlgo,
	}
	for i := range req.Hosts {
		if ip := net.ParseIP(req.Hosts[i]); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(req.Hosts[i]); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, req.Hosts[i])
		}
	}

	if req.CA != nil {
		err = appendCAInfoToCSRSm2(req.CA, &tpl)
		if err != nil {
			err = fmt.Errorf("===== lib/gmca.go generate sm2 GenerationFailed")
			return
		}
	}
	csr, err = sw.CreateSm2CertificateRequestToMem(&tpl, key)
	log.Info("===== lib/gmca.go generate exit generate")
	return
}

func signerAlgo(priv crypto.Signer) x509.SignatureAlgorithm {
	switch priv.Public().(type) {
	case *sm2.PublicKey:
		return x509.SM2WithSM3
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// // appendCAInfoToCSR appends CAConfig BasicConstraint extension to a CSR
// func appendCAInfoToCSR(reqConf *csr.CAConfig, csreq *x509.CertificateRequest) error {
// 	pathlen := reqConf.PathLength
// 	if pathlen == 0 && !reqConf.PathLenZero {
// 		pathlen = -1
// 	}
// 	val, err := asn1.Marshal(csr.BasicConstraints{true, pathlen})

// 	if err != nil {
// 		return err
// 	}

// 	csreq.ExtraExtensions = []pkix.Extension{
// 		{
// 			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
// 			Value:    val,
// 			Critical: true,
// 		},
// 	}
// 	return nil
// }

// appendCAInfoToCSR appends CAConfig BasicConstraint extension to a CSR
func appendCAInfoToCSRSm2(reqConf *csr.CAConfig, csreq *x509.CertificateRequest) error {
	pathlen := reqConf.PathLength
	if pathlen == 0 && !reqConf.PathLenZero {
		pathlen = -1
	}
	val, err := asn1.Marshal(csr.BasicConstraints{IsCA: true, MaxPathLen: pathlen})

	if err != nil {
		return err
	}

	csreq.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Value:    val,
			Critical: true,
		},
	}

	return nil
}
