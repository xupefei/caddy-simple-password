// Copyright 2025 Steffen Busch

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package simplepassword

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// simplePassword is a Caddy HTTP handler module that adds simple password authentication
// with cookie-based session persistence. It protects routes with a single shared password.
// Sessions are persisted via hashed-password cookies so users don't need to
// re-authenticate on every browser session.
type simplePassword struct {
	// SessionInactivityTimeout defines the maximum allowed period of inactivity before
	// a session expires and requires re-authentication. Default is 60 minutes.
	SessionInactivityTimeout time.Duration `json:"session_inactivity_timeout,omitempty"`

	// Password is the shared password. Supports Caddy placeholders
	// like {env.PASSWORD} or {file./path/to/password.txt}.
	Password string `json:"password,omitempty"`

	// password is the resolved password after placeholder replacement.
	password string

	// passwordHash is hex(SHA256(password)), computed once in Provision.
	passwordHash string

	// CookieName defines the name of the cookie used to store the session token.
	// Default is `sp_sess`.
	CookieName string `json:"cookie_name,omitempty"`

	// CookiePath specifies the path scope of the cookie.
	// This restricts where the cookie is sent on the server. Default is `/`.
	CookiePath string `json:"cookie_path,omitempty"`

	// CookieDomain specifies the domain scope of the cookie.
	CookieDomain string `json:"cookie_domain,omitempty"`

	// Filename of the custom template to use instead of the embedded default template.
	FormTemplateFile string `json:"form_template,omitempty"`

	// formTemplate is the parsed HTML template used to render the password form.
	formTemplate *template.Template

	// logger provides structured logging for the module.
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (simplePassword) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.simple_password",
		New: func() caddy.Module { return new(simplePassword) },
	}
}

// Provision sets up the module, initializes the logger, and applies default values.
func (m *simplePassword) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	repl := caddy.NewReplacer()

	// Set default values if not provided
	if m.CookieName == "" {
		m.CookieName = "sp_sess"
	}
	if m.CookiePath == "" {
		m.CookiePath = "/"
	}
	if m.SessionInactivityTimeout == 0 {
		m.SessionInactivityTimeout = 60 * time.Minute
	}

	// Replace placeholders in the password such as {env.PASSWORD}
	m.password = repl.ReplaceAll(m.Password, "")

	// Compute password hash for cookie value
	h := sha256.Sum256([]byte(m.password))
	m.passwordHash = hex.EncodeToString(h[:])

	// Provision the HTML template
	if err := m.provisionTemplate(); err != nil {
		return err
	}

	m.logger.Info("simple_password plugin configured",
		zap.String("Cookie name", m.CookieName),
		zap.String("Cookie path", m.CookiePath),
		zap.String("Cookie domain", m.CookieDomain),
		zap.String("Form Template File", m.FormTemplateFile),
		zap.Duration("Session Inactivity Timeout", m.SessionInactivityTimeout),
	)
	return nil
}

// Validate ensures the configuration is correct.
func (m *simplePassword) Validate() error {
	if m.SessionInactivityTimeout <= 0 {
		return fmt.Errorf("SessionInactivityTimeout must be a positive duration")
	}

	if m.password == "" {
		return fmt.Errorf("password must be defined")
	}

	return nil
}

// ServeHTTP handles incoming HTTP requests, checking for a valid session or prompting for a password.
func (m *simplePassword) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		m.logger.Error("Failed to retrieve caddy.Replacer from request context")
		return caddyhttp.Error(http.StatusInternalServerError, nil)
	}

	// Check for valid session cookie
	if cookie, err := r.Cookie(m.CookieName); err == nil {
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(m.passwordHash)) == 1 {
			return next.ServeHTTP(w, r)
		}
	}

	fd := formData{}

	if r.Method != http.MethodPost {
		m.showPasswordForm(w, fd)
		return nil
	}

	// Parse password from POST data.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return nil
	}

	submittedPassword := r.FormValue("password")
	if submittedPassword == "" {
		m.logger.Warn("Missing password in POST")
		m.showPasswordForm(w, fd)
		return nil
	}

	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(submittedPassword), []byte(m.password)) != 1 {
		m.logger.Warn("Invalid password attempt")
		fd.ErrorMessage = "Invalid password. Please try again."
		m.showPasswordForm(w, fd)
		return nil
	}

	// Set session cookie on successful authentication.
	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    m.passwordHash,
		Path:     m.CookiePath,
		Domain:   m.CookieDomain,
		MaxAge:   int(m.SessionInactivityTimeout.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	redirectURL := repl.ReplaceAll("{http.request.orig_uri}", r.URL.RequestURI())

	m.logger.Debug("Session ok, redirecting",
		zap.String("redirect_url", redirectURL),
		zap.String("current_request_uri", r.URL.RequestURI()),
	)

	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

// Interface guards to ensure simplePassword implements the necessary interfaces.
var (
	_ caddy.Module                = (*simplePassword)(nil)
	_ caddy.Provisioner           = (*simplePassword)(nil)
	_ caddy.Validator             = (*simplePassword)(nil)
	_ caddyhttp.MiddlewareHandler = (*simplePassword)(nil)
)
