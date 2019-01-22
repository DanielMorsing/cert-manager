/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package acme

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	acme "github.com/jetstack/cert-manager/pkg/acme/client"
	acmemw "github.com/jetstack/cert-manager/pkg/acme/client/middleware"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util"
	cmerrors "github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	acmecl "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

type Helper interface {
	ClientForIssuer(iss cmapi.GenericIssuer) (acme.Interface, error)
	ReadPrivateKey(sel cmapi.SecretKeySelector, ns string) (*rsa.PrivateKey, error)
}

// Helper is a structure that provides 'glue' between cert-managers API types and
// constructs, and ACME clients.
// For example, it can be used to obtain an ACME client for a IssuerRef that is
// correctly configured (e.g. with user agents, timeouts, proxy handling etc)
type helperImpl struct {
	SecretLister corelisters.SecretLister

	ClusterResourceNamespace string
}

var _ Helper = &helperImpl{}

// NewHelper is a helper that constructs a new Helper structure with the given
// secret lister.
func NewHelper(lister corelisters.SecretLister, ns string) Helper {
	return &helperImpl{
		SecretLister:             lister,
		ClusterResourceNamespace: ns,
	}
}

// PrivateKeySelector will default the SecretKeySelector with a default secret key
// if one is not already specified.
func PrivateKeySelector(sel cmapi.SecretKeySelector) cmapi.SecretKeySelector {
	if len(sel.Key) == 0 {
		sel.Key = corev1.TLSPrivateKeyKey
	}
	return sel
}

// ReadPrivateKey will attempt to read and parse an ACME private key from a secret.
// If the referenced secret or key within that secret does not exist, an error will
// be returned.
// A *rsa.PrivateKey will be returned here, as ACME private keys can currently
// only be RSA.
func (h *helperImpl) ReadPrivateKey(sel cmapi.SecretKeySelector, ns string) (*rsa.PrivateKey, error) {
	sel = PrivateKeySelector(sel)

	s, err := h.SecretLister.Secrets(ns).Get(sel.Name)
	if err != nil {
		return nil, err
	}

	data, ok := s.Data[sel.Key]
	if !ok {
		return nil, cmerrors.NewInvalidData("No secret data found for key %q in secret %q", sel.Key, sel.Name)
	}

	// DecodePrivateKeyBytes already wraps errors with NewInvalidData.
	pk, err := pki.DecodePrivateKeyBytes(data)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return nil, cmerrors.NewInvalidData("ACME private key in %q is not of type RSA", sel.Name)
	}

	return rsaKey, nil
}

// ClientWithKey will construct a new ACME client for the provided Issuer, using
// the given RSA private key.
func ClientWithKey(iss cmapi.GenericIssuer, pk *rsa.PrivateKey) (acme.Interface, error) {
	acmeSpec := iss.GetSpec().ACME
	if acmeSpec == nil {
		return nil, fmt.Errorf("issuer %q is not an ACME issuer. Ensure the 'acme' stanza is correctly specified on your Issuer resource", iss.GetObjectMeta().Name)
	}
	acmeStatus := iss.GetStatus().ACME
	accountURI := ""
	if acmeStatus != nil && acmeStatus.URI != "" {
		accountURI = acmeStatus.URI
	}
	acmeCl := &acmecl.Client{
		HTTPClient:   buildHTTPClient(acmeSpec.SkipTLSVerify),
		Key:          pk,
		DirectoryURL: acmeSpec.Server,
		UserAgent:    util.CertManagerUserAgent,
	}
	acmeCl.SetAccountURL(accountURI)

	return acmemw.NewLogger(acmeCl), nil
}

// ClientForIssuer will return a properly configure ACME client for the given
// Issuer resource.
// If the private key for the Issuer does not exist, an error will be returned.
// If the provided issuer is not an ACME Issuer, an error will be returned.
func (h *helperImpl) ClientForIssuer(iss cmapi.GenericIssuer) (acme.Interface, error) {
	acmeSpec := iss.GetSpec().ACME
	if acmeSpec == nil {
		return nil, fmt.Errorf("issuer %q is not an ACME issuer. Ensure the 'acme' stanza is correctly specified on your Issuer resource", iss.GetObjectMeta().Name)
	}

	ns := iss.GetObjectMeta().Namespace
	if ns == "" {
		ns = h.ClusterResourceNamespace
	}

	pk, err := h.ReadPrivateKey(acmeSpec.PrivateKey, ns)
	if err != nil {
		return nil, err
	}

	return ClientWithKey(iss, pk)
}

// buildHTTPClient returns an HTTP client to be used by the ACME client.
// For the time being, we construct a new HTTP client on each invocation.
// This is because we need to set the 'skipTLSVerify' flag on the HTTP client
// itself.
// In future, we may change to having two global HTTP clients - one that ignores
// TLS connection errors, and the other that does not.
func buildHTTPClient(skipTLSVerify bool) *http.Client {
	return acme.NewInstrumentedClient(&http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialTimeout,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: skipTLSVerify},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: time.Second * 30,
	})
}

var timeout = time.Duration(5 * time.Second)

func dialTimeout(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, addr)
}

// InspectError returns a struct containing information about the error
// it was given.
func InspectError(err *acmecl.Error) *ErrorInfo {
	problem := getProblem(err.Type)

	info := &ErrorInfo{
		Error: err,
	}
	if problem == "compound" {
		for _, s := range err.Subproblems {
			addProblem(info, getProblem(s.Type))
		}
		return info
	}
	addProblem(info, problem)
	return info
}

func getProblem(s string) string {
	// Letsencrypt/boulder currently uses a non-IETF namespace for its URNs,
	// but the last element follows
	// Other implementations have been known to use lower-case for their URNs

	split := strings.Split(s, ":")
	return strings.ToLower(split[len(split)-1])
}

func addProblem(info *ErrorInfo, problem string) {
	switch problem {
	case "ratelimited":
		info.Ratelimit = true
		info.RetryAt = retryAt(info.Error.Header.Get("Retry-After"))
	case "accountdoesnotexist", "invalidcontact", "rejectedidentifier", "unauthorized", "unsupportedcontact",
		"unsupportedidentifier":
		info.NeedsConfigChange = true
	case "alreadyrevoked", "serverinternal", "badrevocationreason":
		// TODO(dmo): figure these ones out
	case "badcsr", "badsignaturealgorithm", "incorrectresponse", "malformed", "tls":
		info.LogicError = true
	case "badnonce":
		info.RetryAt = time.Now().Add(-1 * time.Second)
	case "caa", "dns", "externalaccountrequired", "useractionrequired":
		info.NeedsRemediation = true
	default:
		// TODO(dmo): figure out the right thing here
	}
}

type ErrorInfo struct {
	Error             *acmecl.Error
	NeedsConfigChange bool
	NeedsRemediation  bool

	LogicError bool

	Ratelimit bool
	RetryAt   time.Time
}

// retryAt parses a Retry-After HTTP header value,
// trying to convert v into an int (seconds) or use http.ParseTime otherwise.
// It returns zero time if v cannot be parsed.
//
// Copied from x/crypto/acme
func retryAt(v string) time.Time {
	if i, err := strconv.Atoi(v); err == nil {
		return time.Now().Add(time.Duration(i) * time.Second)
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return time.Time{}
	}
	return t
}
