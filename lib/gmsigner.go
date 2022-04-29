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

// 使用CA作为签署者生成x509证书
func createCertByCA(req signer.SignRequest, ca *CA) (cert []byte, err error) {
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
	// 基于req.Request(证书请求csr)生成证书模板
	template, err := createCertTemplateByCertificateRequest(block.Bytes)
	if err != nil {
		log.Errorf("===== lib/gmca.go signCert: parseCertificateRequest error:[%s]", err)
		return nil, err
	}
	// 补充OU与证书期限
	err = fillOUAndNotAfter(template, req)
	if err != nil {
		log.Errorf("===== lib/gmca.go createCertByCA: fillOUAndNotAfter error:[%s]", err)
		return nil, err
	}
	// 获取CA证书路径
	caCertFile := ca.Config.CA.Certfile
	//certfile := req.Profile
	// log.Infof("===== lib/gmca.go createCertByCA:certifle = %s", certfile)
	// 读取CA证书文件，获取CA的私钥与其x509证书
	caRootkey, _, caRootCert, err := util.GetSignerFromCertFile(caCertFile, ca.csp)
	if err != nil {
		return nil, err
	}
	// log.Infof("===== lib/gmca.go createCertByCA:rootca = %v", rootca)
	// rootca := ParseX509Certificate2Sm2(x509cert)
	// 使用CA的私钥与其x509证书给template签名，生成对应证书，并转为pem字节数组
	cert, err = sw.CreateCertificateToMem(template, caRootCert, caRootkey)
	if err != nil {
		return nil, err
	}
	// log.Infof("===== lib/gmca.go createCertByCA:template = %v\n Type = %T", template, template.PublicKey)
	// 将pem字节数组转为x509证书
	clientCert, err := x509.ReadCertificateFromPem(cert)
	if err != nil {
		return nil, err
	}
	// log.Infof("===== lib/gmca.go createCertByCA:template.SerialNumber---,%v", template.SerialNumber)
	// log.Infof("===== lib/gmca.go createCertByCA:clientCert--,%v", clientCert)
	// log.Infof("===== lib/gmca.go createCertByCA:cert--,%v", cert)
	// log.Infof("===== lib/gmca.go createCertByCA:req.Label--,%v", req.Label)
	// log.Infof("===== lib/gmca.go createCertByCA:clientCert.NotAfter--,%v", clientCert.NotAfter)
	// log.Info("===== lib/gmca.go createCertByCA: Exit ParseCertificate")
	log.Infof("===== lib/gmca.go createCertByCA: 生成的证书长度 [%d]", len(cert))
	// 将生成的证书插入DB
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
		log.Errorf("===== lib/gmca.go createCertByCA error InsertCertificate:[%s]", err)
	}
	return
}

// 生成自签名的CA根证书
func createRootCACert(key bccsp.Key, req *csr.CertificateRequest, priv crypto.Signer) (cert []byte, err error) {
	log.Infof("===== lib/gmca.go createRootCACert key :%T", key)
	// 生成标准的国密x509证书请求
	csrPEM, err := createCertificateRequest(priv, req, key)
	if err != nil {
		log.Errorf("===== lib/gmca.go createRootCACert generate error:%s", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.Errorf("===== lib/gmca.go createRootCACert sm2 csr DecodeFailed")
	}

	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.Errorf("===== lib/gmca.go createRootCACert sm2 not a csr")
	}
	// 根据证书请求生成x509证书模板，需要补充证书期限信息
	certTemplate, err := createCertTemplateByCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 补充模板的证书期限
	certTemplate.NotBefore = time.Now()
	// 作为CA自签名的根证书，使用期限最长的 defaultRootCACertificateExpiration
	certTemplate.NotAfter = time.Now().Add(parseDuration(defaultRootCACertificateExpiration))
	// log.Infof("===== lib/gmca.go createRootCACert key is %T   ---%T", sm2Template.PublicKey, sm2Template)
	// 生成自签名的CA根证书
	cert, err = sw.CreateCertificateToMem(certTemplate, certTemplate, key)
	return
}

// 补充OU信息
func fillOUAndNotAfter(template *x509.Certificate, req signer.SignRequest) error {
	subject := req.Subject
	// log.Infof("===== lib/gmca.go parseCertificateRequestWithSubject before template.Subject: %#v , subject: %#v", template.Subject, subject)
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
	// log.Infof("===== lib/gmca.go parseCertificateRequestWithSubject after template.Subject: %#v , subject: %#v", template.Subject, subject)
	template.NotBefore = time.Now()
	// log.Infof("===== lib/gmca.go parseCertificateRequestWithSubject req.NotAfter: %s", req.NotAfter.Format(time.RFC3339))
	if req.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(defaultIssuedCertificateExpiration)
	} else {
		template.NotAfter = req.NotAfter
	}
	// log.Infof("===== lib/gmca.go parseCertificateRequestWithSubject template.NotAfter: %s", template.NotAfter.Format(time.RFC3339))
	return nil
}

// 根据证书请求生成x509证书模板
//  注意，生成的模板缺少证书期限
func createCertTemplateByCertificateRequest(csrBytes []byte) (template *x509.Certificate, err error) {
	csrv, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}
	err = csrv.CheckSignature()
	if err != nil {
		return nil, err
	}
	// log.Infof("===== lib/gmca.go parseCertificateRequest: csrv :%#v", csrv)
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

// 生成标准的国密x509证书请求
func createCertificateRequest(priv crypto.Signer, req *csr.CertificateRequest, key bccsp.Key) (csr []byte, err error) {
	// log.Info("===== lib/gmca.go generate")
	sigAlgo := signerAlgo(priv)
	if sigAlgo == x509.UnknownSignatureAlgorithm {
		return nil, errors.Errorf("===== lib/gmca.go generate Private key type is unsupported")
	}
	// log.Info("===== lib/gmca.go generate begin create sm2.CertificateRequest")
	reqName := req.Name()
	// 生成证书申请模板
	var tpl = x509.CertificateRequest{
		Subject:            reqName,
		SignatureAlgorithm: sigAlgo,
	}
	// 根据req.Hosts补充SAN字段 优先顺序 IP > EMail > DNS
	for i := range req.Hosts {
		if ip := net.ParseIP(req.Hosts[i]); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(req.Hosts[i]); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, req.Hosts[i])
		}
	}
	// 请求CA证书时，补充BasicConstraints信息
	if req.CA != nil {
		err = appendCAInfoToCSR(req.CA, &tpl)
		if err != nil {
			err = fmt.Errorf("===== lib/gmca.go generate sm2 GenerationFailed")
			return
		}
	}
	csr, err = sw.CreateSm2CertificateRequestToMem(&tpl, key)
	log.Info("===== lib/gmca.go generate exit generate")
	return
}

// 检查并获取签名算法
func signerAlgo(priv crypto.Signer) x509.SignatureAlgorithm {
	switch priv.Public().(type) {
	case *sm2.PublicKey:
		return x509.SM2WithSM3
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// appendCAInfoToCSR appends CAConfig BasicConstraint extension to a CSR
func appendCAInfoToCSR(reqConf *csr.CAConfig, csreq *x509.CertificateRequest) error {
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
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, // BasicConstraints的OID
			Value:    val,
			Critical: true,
		},
	}
	return nil
}
