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

package postauth2fa

import (
	"context"
	"encoding/base64"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// postauth2fa is a Caddy HTTP handler module that adds TOTP-based authentication.
// It protects routes with a single shared TOTP code — no usernames or passwords required.
// Features:
//   - Standalone TOTP authentication (no prior auth handler needed)
//   - Single shared TOTP secret configured directly in the Caddyfile
//   - Configurable inactivity timeout for sessions (JWT-based, stateless, cookie storage)
//   - Optional IP binding for session validation (enabled by default, can be disabled)
//   - Customizable session cookie name, path, and domain
//   - Customizable HTML form template for TOTP code entry
//   - Configurable TOTP code length (6 or 8 digits)
//   - Secure handling of secrets and keys (Caddy placeholders supported)
//   - No server-side session state: JWTs are stateless, reloads/restarts do not invalidate sessions
type postauth2fa struct {
	// SessionInactivityTimeout defines the maximum allowed period of inactivity before
	// a session expires and requires re-authentication. Default is 60 minutes.
	SessionInactivityTimeout time.Duration `json:"session_inactivity_timeout,omitempty"`

	// TOTPSecret is the shared TOTP secret (base32 encoded). Supports Caddy placeholders
	// like {env.TOTP_SECRET} or {file./path/to/secret.txt}.
	TOTPSecret string `json:"totp_secret,omitempty"`

	// totpSecretResolved is the resolved TOTP secret after placeholder replacement.
	totpSecretResolved string

	// CookieName defines the name of the cookie used to store the session token.
	// Default is `cpa_sess`.
	CookieName string `json:"cookie_name,omitempty"`

	// CookiePath specifies the path scope of the cookie.
	// This restricts where the cookie is sent on the server. Default is `/`.
	CookiePath string `json:"cookie_path,omitempty"`

	// CookieDomain specifies the domain scope of the cookie.
	CookieDomain string `json:"cookie_domain,omitempty"`

	// IPBinding controls whether the session is bound to the client IP address.
	// Accepts "true" (default) or "false". Can use Caddy placeholders.
	IPBinding string `json:"ip_binding,omitempty"`

	// Filename of the custom template to use instead of the embedded default template.
	FormTemplateFile string `json:"form_template,omitempty"`

	// TOTPCodeLength defines the expected length of the TOTP code (default: 6).
	TOTPCodeLength int `json:"totp_code_length,omitempty"`

	// formTemplate is the parsed HTML template used to render the TOTP form.
	formTemplate *template.Template

	// SignKey is the base64 encoded secret key used to sign the JWTs.
	SignKey string `json:"sign_key,omitempty"`

	// signKeyBytes is the base64 decoded secret key used to sign the JWTs.
	signKeyBytes []byte

	// logger provides structured logging for the module.
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (postauth2fa) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.postauth2fa",
		New: func() caddy.Module { return new(postauth2fa) },
	}
}

// Provision sets up the module, initializes the logger, and applies default values.
func (m *postauth2fa) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	repl := caddy.NewReplacer()

	// Set default values if not provided
	if m.CookieName == "" {
		m.CookieName = "cpa_sess"
	}
	if m.CookiePath == "" {
		m.CookiePath = "/"
	}
	if m.SessionInactivityTimeout == 0 {
		m.SessionInactivityTimeout = 60 * time.Minute
	}
	if m.TOTPCodeLength == 0 {
		m.TOTPCodeLength = 6
	}

	// Replace placeholders in the SignKey such as {file./path/to/jwt-secret.txt}
	m.SignKey = repl.ReplaceAll(m.SignKey, "")

	var err error
	m.signKeyBytes, err = base64.StdEncoding.DecodeString(m.SignKey)
	if err != nil {
		m.logger.Error("Failed to decode sign key", zap.Error(err))
		return err
	}

	// Replace placeholders in the TOTP secret such as {env.TOTP_SECRET}
	m.totpSecretResolved = repl.ReplaceAll(m.TOTPSecret, "")

	// Set default for IPBinding if not provided
	if m.IPBinding == "" {
		m.IPBinding = "true"
	}

	// Provision the HTML template
	if err = m.provisionTemplate(); err != nil {
		return err
	}

	// Log the chosen configuration values
	m.logger.Info("postauth2fa plugin configured",
		zap.String("Cookie name", m.CookieName),
		zap.String("Cookie path", m.CookiePath),
		zap.String("Cookie domain", m.CookieDomain),
		zap.String("Form Template File", m.FormTemplateFile),
		zap.String("IP Binding", m.IPBinding),
		zap.Duration("Session Inactivity Timeout", m.SessionInactivityTimeout),
		zap.Int("TOTP Code Length", m.TOTPCodeLength),
		// TOTPSecret and SignKey are omitted from the log output for security reasons.
	)
	return nil
}

// Validate ensures the configuration is correct.
func (m *postauth2fa) Validate() error {
	if m.SessionInactivityTimeout <= 0 {
		return fmt.Errorf("SessionInactivityTimeout must be a positive duration")
	}

	if m.totpSecretResolved == "" {
		return fmt.Errorf("totp_secret must be defined")
	}

	// Check if the base64 encoded sign key is set
	if m.SignKey == "" {
		return fmt.Errorf("SignKey must be defined")
	}

	// Check if the base64 decoded sign key has an appropriate length
	if len(m.signKeyBytes) < 32 {
		return fmt.Errorf("decoded sign key must be at least 32 bytes long, but it is %d bytes long, check the base64 encoded sign key", len(m.signKeyBytes))
	}

	// Validate TOTPCodeLength
	if !isValidTOTPCodeLength(m.TOTPCodeLength) {
		return fmt.Errorf("TOTPCodeLength must be 6 or 8")
	}

	return nil
}

// ServeHTTP handles incoming HTTP requests, checking for a valid session or prompting for a TOTP code.
func (m *postauth2fa) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		m.logger.Error("Failed to retrieve caddy.Replacer from request context")
		return caddyhttp.Error(http.StatusInternalServerError, nil)
	}

	// Retrieve the client IP address from the Caddy context.
	clientIP := getClientIP(r.Context(), r.RemoteAddr)

	logger := m.logger.With(
		zap.String("client_ip", clientIP),
	)

	// Replace placeholders in IPBinding (allows dynamic config)
	ipBindingValue := repl.ReplaceAll(m.IPBinding, "true")

	// Validate session
	if m.hasValidJWTCookie(w, r, clientIP, ipBindingValue) {
		return next.ServeHTTP(w, r)
	}

	formData := formData{
		TOTPCodeLength: m.TOTPCodeLength,
	}

	if r.Method != http.MethodPost {
		m.show2FAForm(w, formData)
		return nil
	}

	// Parse TOTP code from POST data.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return nil
	}

	totpCode := r.FormValue("totp_code")
	if totpCode == "" {
		logger.Warn("Missing TOTP code in POST")
		m.show2FAForm(w, formData)
		return nil
	}

	// Validate the TOTP code against the configured secret.
	valid, err := validateTOTPCode(totpCode, m.totpSecretResolved, m.TOTPCodeLength)
	if !valid || err != nil {
		logger.Warn("Invalid TOTP attempt", zap.Error(err))
		formData.ErrorMessage = "Invalid TOTP code. Please try again."
		m.show2FAForm(w, formData)
		return nil
	}

	// Create a new JWT session cookie on successful TOTP validation.
	m.createOrUpdateJWTCookie(w, clientIP)

	// Retrieve the unmodified request's original URI (e.g., full path before handle_path stripped it).
	redirectURL := repl.ReplaceAll("{http.request.orig_uri}", r.URL.RequestURI())

	logger.Debug("Session ok, redirecting",
		zap.String("redirect_url", redirectURL),
		zap.String("current_request_uri", r.URL.RequestURI()),
	)

	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

// getClientIP retrieves the client IP address directly from the Caddy context.
func getClientIP(ctx context.Context, remoteAddr string) string {
	clientIP, ok := ctx.Value(caddyhttp.VarsCtxKey).(map[string]any)["client_ip"]
	if ok {
		if ip, valid := clientIP.(string); valid {
			return ip
		}
	}
	// If the client IP is empty, extract it from the request's RemoteAddr.
	var err error
	clientIP, _, err = net.SplitHostPort(remoteAddr)
	if err != nil {
		// Use the complete RemoteAddr string as a last resort.
		clientIP = remoteAddr
	}
	return clientIP.(string)
}

func isValidTOTPCodeLength(length int) bool {
	return length == int(otp.DigitsSix) || length == int(otp.DigitsEight)
}

func validateTOTPCode(code, secret string, codeLength int) (bool, error) {
	opts := totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.Digits(codeLength),
		Algorithm: otp.AlgorithmSHA1,
	}
	return totp.ValidateCustom(code, secret, time.Now().UTC(), opts)
}

// Interface guards to ensure postauth2fa implements the necessary interfaces.
var (
	_ caddy.Module                = (*postauth2fa)(nil)
	_ caddy.Provisioner           = (*postauth2fa)(nil)
	_ caddy.Validator             = (*postauth2fa)(nil)
	_ caddyhttp.MiddlewareHandler = (*postauth2fa)(nil)
)
