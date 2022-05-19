/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"gitee.com/zhaochuninhefei/cfssl-gm/config"
	"gitee.com/zhaochuninhefei/cfssl-gm/revoke"
	"gitee.com/zhaochuninhefei/cfssl-gm/signer"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/internal/pkg/api"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/internal/pkg/util"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/lib/attr"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/lib/attrmgr"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/lib/caerrors"
	cr "gitee.com/zhaochuninhefei/fabric-ca-gm/lib/server/certificaterequest"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/lib/server/idemix"
	"gitee.com/zhaochuninhefei/fabric-ca-gm/lib/server/user"
	http "gitee.com/zhaochuninhefei/gmgo/gmhttp"
	gmux "gitee.com/zhaochuninhefei/gmgo/mux"
	"gitee.com/zhaochuninhefei/gmgo/x509"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

// ServerRequestContext defines the functionality of a server request context object
type ServerRequestContext interface {
	BasicAuthentication() (string, error)
	TokenAuthentication() (string, error)
	GetCaller() (user.User, error)
	HasRole(role string) error
	ChunksToDeliver(string) (int, error)
	GetReq() *http.Request
	GetQueryParm(name string) string
	GetBoolQueryParm(name string) (bool, error)
	GetResp() http.ResponseWriter
	GetCertificates(cr.CertificateRequest, string) (*sqlx.Rows, error)
	IsLDAPEnabled() bool
	ReadBody(interface{}) error
	ContainsAffiliation(string) error
	CanActOnType(string) error
}

// serverRequestContextImpl represents an HTTP request/response context in the server
type serverRequestContextImpl struct {
	req            *http.Request
	resp           http.ResponseWriter
	endpoint       *serverEndpoint
	ca             *CA
	enrollmentID   string
	enrollmentCert *x509.Certificate
	ui             user.User
	caller         user.User
	body           struct {
		read bool   // true after body is read
		buf  []byte // the body itself
		err  error  // any error from reading the body
	}
	callerRoles map[string]bool
}

// newServerRequestContext is the constructor for a serverRequestContextImpl
func newServerRequestContext(r *http.Request, w http.ResponseWriter, se *serverEndpoint) *serverRequestContextImpl {
	return &serverRequestContextImpl{
		req:      r,
		resp:     w,
		endpoint: se,
	}
}

// BasicAuthentication authenticates the caller's username and password
// found in the authorization header and returns the username
func (ctx *serverRequestContextImpl) BasicAuthentication() (string, error) {
	r := ctx.req
	// Get the authorization header
	authHdr := r.Header.Get("authorization")
	if authHdr == "" {
		return "", caerrors.NewHTTPErr(401, caerrors.ErrNoAuthHdr, "No authorization header")
	}
	// Extract the username and password from the header
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", caerrors.NewAuthenticationErr(caerrors.ErrNoUserPass, "No user/pass in authorization header")
	}
	// zclog.Debugf("===== username: %s/n", username)
	// Get the CA that is targeted by this request
	ca, err := ctx.GetCA()
	if err != nil {
		return "", err
	}
	// Error if max enrollments is disabled for this CA
	// zclog.Debugf("ca.Config: %+v", ca.Config)
	caMaxEnrollments := ca.Config.Registry.MaxEnrollments
	if caMaxEnrollments == 0 {
		return "", caerrors.NewAuthenticationErr(caerrors.ErrEnrollDisabled, "Enroll is disabled")
	}
	// Get the user info object for this user
	ctx.ui, err = ca.registry.GetUser(username, nil)
	if err != nil {
		return "", caerrors.NewAuthenticationErr(caerrors.ErrInvalidUser, "Failed to get user: %s", err)
	}
	// zclog.Debugf("===== 从ca.registry获取到注册用户 Name:%s Type:%s\n", ctx.ui.GetName(), ctx.ui.GetType())
	attempts := ctx.ui.GetFailedLoginAttempts()
	allowedAttempts := ca.Config.Cfg.Identities.PasswordAttempts
	if allowedAttempts > 0 {
		if attempts == ca.Config.Cfg.Identities.PasswordAttempts {
			msg := fmt.Sprintf("Incorrect password entered %d times, max incorrect password limit of %d reached", attempts, ca.Config.Cfg.Identities.PasswordAttempts)
			zclog.Error(msg)
			return "", caerrors.NewHTTPErr(401, caerrors.ErrPasswordAttempts, msg)
		}
	}

	// Check the user's password and max enrollments if supported by registry
	err = ctx.ui.Login(password, caMaxEnrollments)
	if err != nil {
		return "", caerrors.NewAuthenticationErr(caerrors.ErrInvalidPass, "Login failure: %s", err)
	}
	// Store the enrollment ID associated with this server request context
	ctx.enrollmentID = username
	ctx.caller, err = ctx.GetCaller()
	if err != nil {
		return "", err
	}
	zclog.Debugf("===== caller:(Name:%s , Type:%s) ui:((Name:%s , Type:%s) enrollmentID:%s", ctx.caller.GetName(), ctx.caller.GetType(), ctx.ui.GetName(), ctx.ui.GetType(), username)
	// Return the username
	return username, nil
}

// TokenAuthentication authenticates the caller by token
// in the authorization header.
// Returns the enrollment ID or error.
func (ctx *serverRequestContextImpl) TokenAuthentication() (string, error) {
	r := ctx.req
	// Get the authorization header
	authHdr := r.Header.Get("authorization")
	if authHdr == "" {
		return "", caerrors.NewHTTPErr(401, caerrors.ErrNoAuthHdr, "No authorization header")
	}
	// Get the CA
	ca, err := ctx.GetCA()
	if err != nil {
		return "", err
	}
	// Get the request body
	body, err := ctx.ReadBodyBytes()
	if err != nil {
		return "", err
	}
	if idemix.IsToken(authHdr) {
		return ctx.verifyIdemixToken(authHdr, r.Method, r.URL.RequestURI(), body)
	}
	return ctx.verifyX509Token(ca, authHdr, r.Method, r.URL.RequestURI(), body)
}

func (ctx *serverRequestContextImpl) verifyIdemixToken(authHdr, method, uri string, body []byte) (string, error) {
	zclog.Debug("Caller is using Idemix credential")
	var err error

	ctx.enrollmentID, err = ctx.ca.issuer.VerifyToken(authHdr, method, uri, body)
	if err != nil {
		return "", err
	}

	caller, err := ctx.GetCaller()
	if err != nil {
		return "", err
	}

	if caller.IsRevoked() {
		return "", caerrors.NewAuthorizationErr(caerrors.ErrRevokedID, "Enrollment ID is revoked, unable to process request")
	}

	return ctx.enrollmentID, nil
}

func (ctx *serverRequestContextImpl) verifyX509Token(ca *CA, authHdr, method, uri string, body []byte) (string, error) {
	zclog.Debug("===== Caller is using a x509 certificate")
	// Verify the token; the signature is over the header and body
	// 检查http请求携带的token是否有效，并返回对应的x509证书
	cert, err2 := util.VerifyTokenFromHttpRequest(ca.csp, authHdr, method, uri, body, ca.server.Config.CompMode1_3)
	if err2 != nil {
		return "", caerrors.NewAuthenticationErr(caerrors.ErrInvalidToken, "Invalid token in authorization header: %s", err2)
	}
	// 确认是否是reenroll请求且忽略证书到期检查。
	// determine if this being called for a reenroll and the ignore cert expiry property isset
	// passed to the verify certificate to force it's checking of expiry time to be effectively ignored
	reenrollIgnoreCertExpiry := ctx.endpoint.Path == "reenroll" && ctx.ca.Config.CA.ReenrollIgnoreCertExpiry
	// 检查http携带的证书cert是否是由本ca签署的
	// Make sure the caller's cert was issued by this CA
	err2 = ca.VerifyCertificate(cert, reenrollIgnoreCertExpiry)
	if err2 != nil {
		return "", caerrors.NewAuthenticationErr(caerrors.ErrUntrustedCertificate, "Untrusted certificate: %s", err2)
	}
	// 从x509证书获取Subject.CommonName作为EnrollmentID
	id := util.GetEnrollmentIDFromX509Certificate(cert)
	zclog.Debugf("Checking for revocation/expiration of certificate owned by '%s'", id)
	// 检查证书是否过期或被撤销
	// VerifyCertificate ensures that the certificate passed in hasn't
	// expired and checks the CRL for the server.
	expired, checked := revoke.VerifyCertificate(cert)
	if !checked {
		return "", caerrors.NewHTTPErr(401, caerrors.ErrCertRevokeCheckFailure, "Failed while checking for revocation")
	}
	if expired {
		zclog.Debugf("Expired Certificate")
		if reenrollIgnoreCertExpiry {
			// 根据reenrollIgnoreCertExpiry决定是否忽略证书过期
			zclog.Infof("Ignoring expired certificate for re-enroll operation")
		} else {
			return "", caerrors.NewAuthenticationErr(caerrors.ErrCertExpired,
				"The certificate in the authorization header is a revoked or expired certificate")
		}
	}
	// 根据aki与serialNumber从ca本地数据库中读取对应的证书
	aki := hex.EncodeToString(cert.AuthorityKeyId)
	serial := util.GetSerialAsHex(cert.SerialNumber)
	aki = strings.ToLower(strings.TrimLeft(aki, "0"))
	serial = strings.ToLower(strings.TrimLeft(serial, "0"))
	certificate, err := ca.GetCertificate(serial, aki)
	if err != nil {
		return "", err
	}
	// 再次检查证书是否被撤销
	if certificate.Status == "revoked" {
		return "", caerrors.NewAuthenticationErr(caerrors.ErrCertRevoked, "The certificate in the authorization header is a revoked certificate")
	}
	// 将x509证书的Subject.CommonName设置为请求上下文的EnrollmentID
	ctx.enrollmentID = id
	// 设置请求上下文的x509证书
	ctx.enrollmentCert = cert
	// 将x509证书的Subject.CommonName对应的注册用户取出并设置为请求上下文的caller
	ctx.caller, err = ctx.GetCaller()
	if err != nil {
		return "", err
	}
	zclog.Debugf("Successful token authentication of '%s'", id)
	return id, nil
}

// GetECert returns the enrollment certificate of the caller, assuming
// token authentication was successful.
func (ctx *serverRequestContextImpl) GetECert() *x509.Certificate {
	return ctx.enrollmentCert
}

// GetCA returns the CA to which this request is targeted and checks to make sure the database has been initialized
func (ctx *serverRequestContextImpl) GetCA() (*CA, error) {
	_, err := ctx.getCA()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to get CA instance")
	}
	if ctx.ca.db == nil || !ctx.ca.db.IsInitialized() {
		err := ctx.ca.initDB(ctx.ca.server.dbMetrics)
		if err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("%s handler failed to initialize DB", strings.TrimLeft(ctx.req.URL.String(), "/")))
		}
		err = ctx.ca.issuer.Init(false, ctx.ca.db, ctx.ca.levels)
		if err != nil {
			return nil, nil
		}
	}
	return ctx.ca, nil
}

// GetCA returns the CA to which this request is targeted
func (ctx *serverRequestContextImpl) getCA() (*CA, error) {
	if ctx.ca == nil {
		// Get the CA name
		name, err := ctx.getCAName()
		if err != nil {
			return nil, err
		}
		// Get the CA by its name
		ctx.ca, err = ctx.endpoint.Server.GetCA(name)
		if err != nil {
			return nil, err
		}
	}
	return ctx.ca, nil
}

// GetAttrExtension returns an attribute extension to place into a signing request
func (ctx *serverRequestContextImpl) GetAttrExtension(attrReqs []*api.AttributeRequest, profile string) (*signer.Extension, error) {
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	ui, err := ca.registry.GetUser(ctx.enrollmentID, nil)
	if err != nil {
		return nil, err
	}
	allAttrs, err := ui.GetAttributes(nil)
	if err != nil {
		return nil, err
	}
	// 如果没有特意指定哪些扩展属性，就按照ca账户注册时各属性的ecert字段获取默认的扩展属性
	if attrReqs == nil {
		// 根据 ecert 是否为true过滤默认属性
		attrReqs = getDefaultAttrReqs(allAttrs)
		if attrReqs == nil {
			// No attributes are being requested, so we are done
			return nil, nil
		}
	}
	// 获取对应属性
	attrs, err := ca.attrMgr.ProcessAttributeRequests(
		convertAttrReqs(attrReqs), // 接口转换:[]*api.AttributeRequest -> []attrmgr.AttributeRequest
		convertAttrs(allAttrs),    // 接口转换:[]api.Attribute -> []attrmgr.Attribute
	)
	if err != nil {
		return nil, err
	}
	if attrs != nil {
		buf, err := json.Marshal(attrs)
		if err != nil {
			errors.Wrap(err, "Failed to marshal attributes")
		}
		ext := &signer.Extension{
			ID:       config.OID(attrmgr.AttrOID),
			Critical: false,
			Value:    hex.EncodeToString(buf),
		}
		zclog.Debugf("Attribute extension being added to certificate is: %s", attrs.Attrs)
		return ext, nil
	}
	return nil, nil
}

// caNameReqBody is a sparse request body to unmarshal only the CA name
type caNameReqBody struct {
	CAName string `json:"caname,omitempty"`
}

// getCAName returns the targeted CA name for this request
func (ctx *serverRequestContextImpl) getCAName() (string, error) {
	// Check the query parameters first
	ca := ctx.req.URL.Query().Get("ca")
	if ca != "" {
		return ca, nil
	}
	// Next, check the request body, if there is one
	var body caNameReqBody
	_, err := ctx.TryReadBody(&body)
	if err != nil {
		return "", err
	}
	if body.CAName != "" {
		return body.CAName, nil
	}
	// No CA name in the request body either, so use the default CA name
	return ctx.endpoint.Server.CA.Config.CA.Name, nil
}

// ReadBody reads the request body and JSON unmarshals into 'body'
func (ctx *serverRequestContextImpl) ReadBody(body interface{}) error {
	empty, err := ctx.TryReadBody(body)
	if err != nil {
		return err
	}
	if empty {
		return caerrors.NewHTTPErr(400, caerrors.ErrEmptyReqBody, "Empty request body")
	}
	return nil
}

// TryReadBody reads the request body into 'body' if not empty
func (ctx *serverRequestContextImpl) TryReadBody(body interface{}) (bool, error) {
	buf, err := ctx.ReadBodyBytes()
	if err != nil {
		return false, err
	}
	empty := len(buf) == 0
	if !empty {
		err = json.Unmarshal(buf, body)
		if err != nil {
			return true, caerrors.NewHTTPErr(400, caerrors.ErrBadReqBody, "Invalid request body: %s; body=%s",
				err, string(buf))
		}
	}
	return empty, nil
}

// ReadBodyBytes reads the request body and returns bytes
func (ctx *serverRequestContextImpl) ReadBodyBytes() ([]byte, error) {
	if !ctx.body.read {
		r := ctx.req
		buf, err := ioutil.ReadAll(r.Body)
		ctx.body.buf = buf
		ctx.body.err = err
		ctx.body.read = true
	}
	err := ctx.body.err
	if err != nil {
		return nil, caerrors.NewHTTPErr(500, caerrors.ErrReadingReqBody, "Failed reading request body: %s", err)
	}
	return ctx.body.buf, nil
}

func (ctx *serverRequestContextImpl) GetUser(userName string) (user.User, error) {
	ca, err := ctx.getCA()
	if err != nil {
		return nil, err
	}
	registry := ca.registry

	user, err := registry.GetUser(userName, nil)
	if err != nil {
		return nil, err
	}

	err = ctx.CanManageUser(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// CanManageUser determines if the caller has the right type and affiliation to act on on a user
func (ctx *serverRequestContextImpl) CanManageUser(user user.User) error {
	userAff := strings.Join(user.GetAffiliationPath(), ".")
	err := ctx.ContainsAffiliation(userAff)
	if err != nil {
		return err
	}

	userType := user.GetType()
	err = ctx.CanActOnType(userType)
	if err != nil {
		return err
	}

	return nil
}

// CanModifyUser determines if the modifications to the user are allowed
func (ctx *serverRequestContextImpl) CanModifyUser(req *api.ModifyIdentityRequest, checkAff bool, checkType bool, checkAttrs bool, userToModify user.User) error {
	if checkAff {
		reqAff := req.Affiliation
		zclog.Debugf("Checking if caller is authorized to change affiliation to '%s'", reqAff)
		err := ctx.ContainsAffiliation(reqAff)
		if err != nil {
			return err
		}
	}

	if checkType {
		reqType := req.Type
		zclog.Debugf("Checking if caller is authorized to change type to '%s'", reqType)
		err := ctx.CanActOnType(reqType)
		if err != nil {
			return err
		}
	}

	if checkAttrs {
		reqAttrs := req.Attributes
		zclog.Debugf("Checking if caller is authorized to change attributes to %+v", reqAttrs)
		err := attr.CanRegisterRequestedAttributes(reqAttrs, userToModify, ctx.caller)
		if err != nil {
			return caerrors.NewAuthorizationErr(caerrors.ErrRegAttrAuth, "Failed to register attributes: %s", err)
		}
	}

	return nil
}

// 根据ctx.enrollmentID获取对应的注册用户作为caller返回。
// GetCaller gets the user who is making this server request
func (ctx *serverRequestContextImpl) GetCaller() (user.User, error) {
	if ctx.caller != nil {
		return ctx.caller, nil
	}

	var err error
	id := ctx.enrollmentID
	if id == "" {
		return nil, caerrors.NewAuthenticationErr(caerrors.ErrCallerIsNotAuthenticated, "Caller is not authenticated")
	}
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	// Get the user info object for this user
	ctx.caller, err = ca.registry.GetUser(id, nil)
	if err != nil {
		return nil, caerrors.NewAuthenticationErr(caerrors.ErrGettingUser, "Failed to get user")
	}
	return ctx.caller, nil
}

// ContainsAffiliation returns an error if the requested affiliation does not contain the caller's affiliation
func (ctx *serverRequestContextImpl) ContainsAffiliation(affiliation string) error {
	validAffiliation, err := ctx.containsAffiliation(affiliation)
	if err != nil {
		return errors.WithMessage(err, "Failed to validate if caller has authority to act on affiliation")
	}
	if !validAffiliation {
		return caerrors.NewAuthorizationErr(caerrors.ErrCallerNotAffiliated, "Caller does not have authority to act on affiliation '%s'", affiliation)
	}
	return nil
}

// containsAffiliation returns true if the requested affiliation contains the caller's affiliation
func (ctx *serverRequestContextImpl) containsAffiliation(affiliation string) (bool, error) {
	caller, err := ctx.GetCaller()
	if err != nil {
		return false, err
	}

	callerAffiliationPath := user.GetAffiliation(caller)
	zclog.Debugf("Checking to see if affiliation '%s' contains caller's affiliation '%s'", affiliation, callerAffiliationPath)

	// If the caller has root affiliation return "true"
	if callerAffiliationPath == "" {
		zclog.Debug("Caller has root affiliation")
		return true, nil
	}

	if affiliation == callerAffiliationPath {
		return true, nil
	}

	callerAffiliationPath = callerAffiliationPath + "."
	if strings.HasPrefix(affiliation, callerAffiliationPath) {
		return true, nil
	}

	return false, nil
}

// IsRegistrar returns an error if the caller is not a registrar
func (ctx *serverRequestContextImpl) IsRegistrar() error {
	_, isRegistrar, err := ctx.isRegistrar()
	if err != nil {
		return err
	}
	if !isRegistrar {
		return caerrors.NewAuthorizationErr(caerrors.ErrMissingRegAttr, "Caller is not a registrar")
	}

	return nil
}

// isRegistrar returns back true if the caller is a registrar along with the types the registrar is allowed to register
func (ctx *serverRequestContextImpl) isRegistrar() (string, bool, error) {
	caller, err := ctx.GetCaller()
	if err != nil {
		return "", false, err
	}

	zclog.Debugf("Checking to see if caller '%s' is a registrar", caller.GetName())

	rolesStr, err := caller.GetAttribute("hf.Registrar.Roles")
	if err != nil {
		return "", false, caerrors.NewAuthorizationErr(caerrors.ErrRegAttrAuth, "'%s' is not a registrar", caller.GetName())
	}

	// Has some value for attribute 'hf.Registrar.Roles' then user is a registrar
	if rolesStr.Value != "" {
		return rolesStr.Value, true, nil
	}

	return "", false, nil
}

// CanActOnType returns true if the caller has the proper authority to take action on specific type
func (ctx *serverRequestContextImpl) CanActOnType(userType string) error {
	canAct, err := ctx.canActOnType(userType)
	if err != nil {
		return errors.WithMessage(err, "Failed to verify if user can act on type")
	}
	if !canAct {
		return caerrors.NewAuthorizationErr(caerrors.ErrCallerNotAffiliated, "Registrar does not have authority to act on type '%s'", userType)
	}
	return nil
}

func (ctx *serverRequestContextImpl) canActOnType(requestedType string) (bool, error) {
	caller, err := ctx.GetCaller()
	if err != nil {
		return false, err
	}

	zclog.Debugf("Checking to see if caller '%s' can act on type '%s'", caller.GetName(), requestedType)

	typesStr, isRegistrar, err := ctx.isRegistrar()
	if err != nil {
		return false, err
	}
	if !isRegistrar {
		return false, caerrors.NewAuthorizationErr(caerrors.ErrRegAttrAuth, "'%s' is not allowed to manage users", caller.GetName())
	}

	if util.ListContains(typesStr, "*") {
		return true, nil
	}

	var types []string
	if typesStr != "" {
		types = strings.Split(typesStr, ",")
	} else {
		types = make([]string, 0)
	}
	if requestedType == "" {
		requestedType = "client"
	}
	if !strContained(requestedType, types) {
		zclog.Debugf("Caller with types '%s' is not authorized to act on '%s'", types, requestedType)
		return false, nil
	}

	return true, nil
}

func strContained(needle string, haystack []string) bool {
	for _, s := range haystack {
		if strings.EqualFold(s, needle) {
			return true
		}
	}
	return false
}

// HasRole returns an error if the caller does not have the attribute or the value is false for a boolean attribute
func (ctx *serverRequestContextImpl) HasRole(role string) error {
	hasRole, err := ctx.hasRole(role)
	if err != nil {
		return err
	}
	if !hasRole {
		return caerrors.NewAuthorizationErr(caerrors.ErrMissingRole, "Caller has a value of 'false' for attribute/role '%s'", role)
	}
	return nil
}

// HasRole returns true if the caller has the attribute and value of the attribute is true
func (ctx *serverRequestContextImpl) hasRole(role string) (bool, error) {
	if ctx.callerRoles == nil {
		ctx.callerRoles = make(map[string]bool)
	}

	roleStatus, hasRole := ctx.callerRoles[role]
	if hasRole {
		return roleStatus, nil
	}

	caller, err := ctx.GetCaller()
	if err != nil {
		return false, err
	}

	roleAttr, err := caller.GetAttribute(role)
	if err != nil {
		return false, caerrors.NewAuthorizationErr(caerrors.ErrInvokerMissAttr, "Invoker does not have following role'%s': '%s'", role, err)
	}
	roleStatus, err = strconv.ParseBool(roleAttr.Value)
	if err != nil {
		return false, caerrors.NewHTTPErr(400, caerrors.ErrInvalidBool, "Failed to get boolean value of '%s': '%s'", role, err)
	}
	ctx.callerRoles[role] = roleStatus

	return ctx.callerRoles[role], nil
}

// GetVar returns the parameter path variable from the URL
func (ctx *serverRequestContextImpl) GetVar(name string) (string, error) {
	vars := gmux.Vars(ctx.req)
	if vars == nil {
		return "", caerrors.NewHTTPErr(500, caerrors.ErrHTTPRequest, "Failed to correctly handle HTTP request")
	}
	value := vars[name]
	return value, nil
}

// GetBoolQueryParm returns query parameter from the URL
func (ctx *serverRequestContextImpl) GetBoolQueryParm(name string) (bool, error) {
	var err error

	value := false
	param := ctx.req.URL.Query().Get(name)
	if param != "" {
		value, err = strconv.ParseBool(strings.ToLower(param))
		if err != nil {
			return false, caerrors.NewHTTPErr(400, caerrors.ErrUpdateConfigRemoveAff, "Failed to correctly parse value of '%s' query parameter: %s", name, err)
		}
	}

	return value, nil
}

// GetQueryParm returns the value of query param based on name
func (ctx *serverRequestContextImpl) GetQueryParm(name string) string {
	return ctx.req.URL.Query().Get(name)
}

// GetReq returns the http.Request
func (ctx *serverRequestContextImpl) GetReq() *http.Request {
	return ctx.req
}

// GetResp returns the http.ResponseWriter
func (ctx *serverRequestContextImpl) GetResp() http.ResponseWriter {
	return ctx.resp
}

// GetCertificates executes the DB query to get back certificates based on the filters passed in
func (ctx *serverRequestContextImpl) GetCertificates(req cr.CertificateRequest, callerAff string) (*sqlx.Rows, error) {
	return ctx.ca.certDBAccessor.GetCertificates(req, callerAff)
}

// ChunksToDeliver returns the number of chunks to deliver per flush
func (ctx *serverRequestContextImpl) ChunksToDeliver(envVar string) (int, error) {
	var chunkSize int
	var err error

	if envVar == "" {
		chunkSize = 100
	} else {
		chunkSize, err = strconv.Atoi(envVar)
		if err != nil {
			return 0, caerrors.NewHTTPErr(500, caerrors.ErrParsingIntEnvVar, "Incorrect format specified for environment variable '%s', an integer value is required: %s", envVar, err)
		}
	}
	return chunkSize, nil
}

// Registry returns the registry for the ca
func (ctx *serverRequestContextImpl) GetRegistry() user.Registry {
	return ctx.ca.registry
}

func (ctx *serverRequestContextImpl) GetCAConfig() *CAConfig {
	return ctx.ca.Config
}

func (ctx *serverRequestContextImpl) IsLDAPEnabled() bool {
	return ctx.ca.Config.LDAP.Enabled
}

func convertAttrReqs(attrReqs []*api.AttributeRequest) []attrmgr.AttributeRequest {
	rtn := make([]attrmgr.AttributeRequest, len(attrReqs))
	for i := range attrReqs {
		rtn[i] = attrmgr.AttributeRequest(attrReqs[i])
	}
	return rtn
}

func convertAttrs(attrs []api.Attribute) []attrmgr.Attribute {
	rtn := make([]attrmgr.Attribute, len(attrs))
	for i := range attrs {
		rtn[i] = attrmgr.Attribute(&attrs[i])
	}
	return rtn
}

// Return attribute requests for attributes which should by default be added to an ECert
func getDefaultAttrReqs(attrs []api.Attribute) []*api.AttributeRequest {
	count := 0
	for _, attr := range attrs {
		if attr.ECert {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	reqs := make([]*api.AttributeRequest, count)
	count = 0
	for _, attr := range attrs {
		if attr.ECert {
			reqs[count] = &api.AttributeRequest{Name: attr.Name}
			count++
		}
	}
	return reqs
}
