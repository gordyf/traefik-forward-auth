package handlers

import (
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"

	"github.com/gordyf/traefik-forward-auth/api/storage/v1alpha1"

	"github.com/gordyf/traefik-forward-auth/configuration"

	"github.com/gordyf/traefik-forward-auth/authentication"

	"github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	internallog "github.com/gordyf/traefik-forward-auth/log"

	"github.com/gordyf/traefik-forward-auth/authorization"
)

const (
	impersonateUserHeader  = "Impersonate-User"
	impersonateGroupHeader = "Impersonate-Group"
)

// Server implements the HTTP server handling forwardauth
type Server struct {
	userinfo      v1alpha1.UserInfoInterface
	authorizer    authorization.Authorizer
	log           logrus.FieldLogger
	config        *configuration.Config
	authenticator *authentication.Authenticator
}

// NewServer creates a new forwardauth server
func NewServer(userinfo v1alpha1.UserInfoInterface, config *configuration.Config) *Server {
	s := &Server{
		log:           internallog.NewDefaultLogger(config.LogLevel, config.LogFormat),
		config:        config,
		userinfo:      userinfo,
		authenticator: authentication.NewAuthenticator(config),
	}

	s.userinfo = userinfo

	return s
}

// RootHandler it the main handler (for / path)
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	logger := s.log.WithFields(logrus.Fields{
		"X-Forwarded-Method": r.Header.Get("X-Forwarded-Method"),
		"X-Forwarded-Proto":  r.Header.Get("X-Forwarded-Proto"),
		"X-Forwarded-Host":   r.Header.Get("X-Forwarded-Host"),
		"X-Forwarded-Prefix": r.Header.Get("X-Forwarded-Prefix"),
		"X-Forwarded-Uri":    r.Header.Get("X-Forwarded-Uri"),
		"Path":               r.URL.Path,
		"Host":               r.Host,
		"Method":             r.Method,
	})

	logger.Debug("Root request")

	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")
	r.URL, _ = neturl.Parse(authentication.GetRequestURI(r))

	if s.config.AuthHost == "" || len(s.config.CookieDomains) > 0 || r.Host == s.config.AuthHost {
		s.AuthHandler(w, r)
	} else {
		// Redirect the client to the authHost.
		url := r.URL
		url.Scheme = r.Header.Get("X-Forwarded-Proto")
		url.Host = s.config.AuthHost
		logger.Debugf("redirect to %v", url.String())
		http.Redirect(w, r, url.String(), 307)
	}
}

// AllowHandler handles the request as implicite "allow", returining HTTP 200 response to the Traefik
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, "Allow request")
		w.WriteHeader(200)
	}
}

// AuthHandler handles the request as requiring authentication.
// It validates the existing session, starting a new auth flow if the session is not valid.
// Finally it also performs authorization (if enabled) to ensure the logged-in subject is authorized to perform the request.
func (s *Server) AuthHandler(w http.ResponseWriter, r *http.Request) {
	// Logging setup
	logger := s.logger(r, "Authenticate request").WithFields(logrus.Fields{
		"X-Forwarded-Method": r.Header.Get("X-Forwarded-Method"),
		"X-Forwarded-Proto":  r.Header.Get("X-Forwarded-Proto"),
		"X-Forwarded-Host":   r.Header.Get("X-Forwarded-Host"),
		"X-Forwarded-Prefix": r.Header.Get("X-Forwarded-Prefix"),
		"X-Forwarded-Uri":    r.Header.Get("X-Forwarded-Uri"),
		"Path":               r.URL.Path,
		"Host":               r.Host,
		"Method":             r.Method,
	})

	// Get auth cookie
	c, err := r.Cookie(s.config.CookieName)
	if err != nil {
		logger.Info("missing auth cookie")
		s.notAuthenticated(logger, w, r)
		return
	}

	// Validate cookie
	id, err := s.authenticator.ValidateCookie(r, c)
	if err != nil {
		logger.Info(fmt.Sprintf("cookie validaton failure: %s", err.Error()))
		s.notAuthenticated(logger, w, r)
		return
	}

	// Validate user
	valid := s.authenticator.ValidateEmail(id.Email)
	if !valid {
		logger.WithFields(logrus.Fields{
			"email": id.Email,
		}).Errorf("Invalid email")
		http.Error(w, "Not authorized", 401)
		return
	}

	// Authorize user
	groups, err := s.getGroupsFromSession(r)
	if err != nil {
		logger.Errorf("error getting groups from session: %v", err)
		s.notAuthenticated(logger, w, r)
		return
	}

	if groups == nil {
		logger.Info("groups session data is missing, re-authenticating")
		s.notAuthenticated(logger, w, r)
		return
	}

	// Valid request
	logger.Debugf("Allow request from %s", id.Email)
	for _, headerName := range s.config.EmailHeaderNames {
		w.Header().Set(headerName, id.Email)
	}

	w.WriteHeader(200)
}

var removeHeaders = map[string]bool{
	strings.ToLower("Authorization"):        true,
	strings.ToLower(impersonateUserHeader):  true,
	strings.ToLower(impersonateGroupHeader): true,
}

// Traefik correctly removes any headers listed in the Connection header, but
// because it removes headers after forward auth has run, a specially crafted
// request can forward to the backend with the forward auth headers removed.
// Remove forward auth headers from the Connection header to ensure that they
// get passed to the backend.
func cleanupConnectionHeader(original string) string {
	headers := strings.Split(original, ",")
	passThrough := make([]string, 0, len(headers))
	for _, header := range headers {
		if remove := removeHeaders[strings.ToLower(strings.TrimSpace(header))]; !remove {
			passThrough = append(passThrough, header)
		}
	}
	return strings.TrimSpace(strings.Join(passThrough, ","))
}

// AuthCallbackHandler handles the request as a callback from authentication provider.
// It validates CSRF, exchanges code-token for id-token and extracts groups from the id-token.
func (s *Server) AuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Logging setup
	logger := s.logger(r, "Handling callback")

	// Check for CSRF cookie
	c, err := r.Cookie(s.config.CSRFCookieName)
	if err != nil {
		logger.Errorf("missing CSRF cookie: %v", err)
		http.Error(w, "Not authorized", 401)
		return
	}

	// Validate state
	valid, redirect, err := authentication.ValidateCSRFCookie(r, c)
	if !valid {
		logger.Errorf("error validating CSRF cookie: %v", err)
		http.Error(w, "Not authorized", 401)
		return
	}

	// Clear CSRF cookie
	http.SetCookie(w, s.authenticator.ClearCSRFCookie(r))

	provider := s.config.OIDCProvider

	// Mapping scope
	var scope []string
	if s.config.Scope != "" {
		scope = []string{s.config.Scope}
	} else {
		scope = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
	}

	oauth2Config := oauth2.Config{
		ClientID:     s.config.ClientID,
		ClientSecret: s.config.ClientSecret,
		RedirectURL:  s.authenticator.ComposeRedirectURI(r),
		Endpoint:     provider.Endpoint(),
		Scopes:       scope,
	}

	// Exchange code for token
	oauth2Token, err := oauth2Config.Exchange(s.config.OIDCContext, r.URL.Query().Get("code"))
	if err != nil {
		logger.Errorf("failed to exchange token: %v", err)
		http.Error(w, "Bad Gateway", 502)
		return
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		logger.Error("missing ID token")
		http.Error(w, "Bad Gateway", 502)
		return
	}

	// Parse and verify ID Token payload.
	verifier := provider.Verifier(&oidc.Config{ClientID: s.config.ClientID})
	idToken, err := verifier.Verify(s.config.OIDCContext, rawIDToken)
	if err != nil {
		logger.Errorf("failed to verify token: %v", err)
		http.Error(w, "Bad Gateway", 502)
		return
	}

	// Extract custom claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		logger.Errorf("failed to extract claims: %v", err)
		http.Error(w, "Bad Gateway", 502)
		return
	}

	email, ok := claims["email"]
	if ok {
		token := ""

		// Generate cookies
		c, err := s.authenticator.MakeIDCookie(r, email.(string), token)
		if err != nil {
			logger.Errorf("error generating secure session cookie: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}
		http.SetCookie(w, c)
		logger.WithFields(logrus.Fields{
			"user": claims["email"].(string),
		}).Infof("generated auth cookie")
	} else {
		logger.Warn("no email claim present in the ID token")
	}

	// If name in null, empty or whitespace, use email address for name
	name, ok := claims["name"]
	if !ok || (ok && strings.TrimSpace(name.(string)) == "") {
		name = email.(string)
	}

	http.SetCookie(w, s.authenticator.MakeNameCookie(r, name.(string)))
	logger.WithFields(logrus.Fields{
		"name": name.(string),
	}).Info("generated name cookie")

	// Mapping groups
	groups := []string{}
	groupsClaim, ok := claims[s.config.GroupsAttributeName].([]interface{})
	if ok {
		for _, g := range groupsClaim {
			groups = append(groups, g.(string))
		}
	} else {
		logger.Warnf("failed to get groups claim from the ID token (GroupsAttributeName: %s)", s.config.GroupsAttributeName)
	}

	if err := s.userinfo.Save(r, w, &v1alpha1.UserInfo{
		Username: name.(string),
		Email:    email.(string),
		Groups:   groups,
	}); err != nil {
		logger.Errorf("error saving session: %v", err)
		http.Error(w, "Bad Gateway", 502)
		return
	}

	// Redirect
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

// notAuthenticated is used to signal the request does not include a valid authentication data.
// If the request came from a browser (having "text/html" in the Accept header), authentication
// redirect is made to start a new auth flow. Otherwise the "Authenticatio expired" message
// is passed as one of the known content-types or as a plain text.
func (s *Server) notAuthenticated(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) {
	bestFormat := ""

	// Redirect if request accepts HTML. Fail if request is AJAX, image, etc
	acceptHeader := r.Header.Get("Accept")
	acceptParts := strings.Split(acceptHeader, ",")

	for i, acceptPart := range acceptParts {
		format := strings.Trim(strings.SplitN(acceptPart, ";", 2)[0], " ")
		if format == "text/html" || (i == 0 && format == "*/*") {
			s.authRedirect(logger, w, r)
			return
		} else if strings.HasPrefix(format, "application/json") {
			bestFormat = "json"
		} else if strings.HasPrefix(format, "application/xml") {
			bestFormat = "xml"
		}
	}
	logger.Warnf("Non-HTML request: %v", acceptHeader)

	errStr := "Authentication expired. Reload page to re-authenticate."
	if bestFormat == "json" {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error": "`+errStr+`"}`, 401)
	} else if bestFormat == "xml" {
		w.Header().Set("Content-Type", "application/xml")
		http.Error(w, `<errors><error>`+errStr+`</error></errors>`, 401)
	} else {
		http.Error(w, errStr, 401)
	}
}

// authRedirect generates CSRF cookie and redirests to authentication provider to start the authentication flow.
func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) {
	// Error indicates no cookie, generate nonce
	nonce, err := authentication.GenerateNonce()
	if err != nil {
		logger.Errorf("error generating nonce, %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	http.SetCookie(w, s.authenticator.MakeCSRFCookie(r, nonce))
	logger.Debug("sending CSRF cookie and a redirect to OIDC login")

	// Mapping scope
	var scope []string
	if s.config.Scope != "" {
		scope = []string{s.config.Scope}
	} else {
		scope = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
	}

	// clear existing claims session
	if err = s.userinfo.Clear(r, w); err != nil {
		logger.Errorf("error clearing session: %v", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     s.config.ClientID,
		ClientSecret: s.config.ClientSecret,
		RedirectURL:  s.authenticator.ComposeRedirectURI(r),
		Endpoint:     s.config.OIDCProvider.Endpoint(),
		Scopes:       scope,
	}

	state := fmt.Sprintf("%s:%s", nonce, authentication.GetRequestURL(r))

	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)

	return
}

// logger provides a new logger enriched with request info
func (s *Server) logger(r *http.Request, msg string) *logrus.Entry {
	// Create logger
	logger := s.log.WithFields(logrus.Fields{
		"source_ip": r.Header.Get("X-Forwarded-For"),
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"headers": r.Header,
	}).Debug(msg)

	return logger
}

// getGroupsFromSession returns list of groups present in the session
func (s *Server) getGroupsFromSession(r *http.Request) ([]string, error) {
	userInfo, err := s.userinfo.Get(r)
	if err != nil {
		return nil, err
	}
	return userInfo.Groups, nil
}
