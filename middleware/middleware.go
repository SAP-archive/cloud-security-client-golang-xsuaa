package middleware

import (
	"context"
	"errors"
	"fmt"
	xssecgo "github.com/SAP-samples/cloud-security-client-golang-xsuaa"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/config"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/validation"
	"github.com/dgrijalva/jwt-go/v4"

	"log"
	"net/http"
	"strings"
)

type XssecMiddleware struct {
	Options     Options
	XsuaaConfig config.XsuaaConfig
}

// New constructs a new Secure instance with supplied options.
func NewXssecMiddleware(xsuaaConfig config.XsuaaConfig, options ...Options) (*XssecMiddleware, error) {

	clientId := xsuaaConfig.ClientId

	if len(clientId) == 0 {
		return nil, errors.New("no ClientId available in xsuaa binding")
	}

	xsAppName := xsuaaConfig.XsAppName
	if len(xsAppName) == 0 {
		return nil, errors.New("no xsappname available in xsuaa binding")
	}

	url := xsuaaConfig.Url

	if len(url) == 0 {
		return nil, errors.New("no url available in xsuaa binding")
	}

	uaadomain := xsuaaConfig.UaaDomain

	if len(uaadomain) == 0 {
		return nil, errors.New("no url available in xsuaa binding")
	}

	var opts Options
	if len(options) == 0 {
		opts = Options{}
	} else {
		opts = options[0]
	}

	if opts.XssecProperty == "" {
		opts.XssecProperty = "user"
	}

	if opts.ErrorHandler == nil {
		opts.ErrorHandler = OnError
	}

	return &XssecMiddleware{
		Options:     opts,
		XsuaaConfig: xsuaaConfig,
	}, nil
}

// Just an error handler that can be used for custom purposes
type errorHandler func(w http.ResponseWriter, r *http.Request, err string)

// Options is a struct for specifying configuration options for the middleware.
type Options struct {

	// The name of the property in the request where the user information
	// from the JWT will be stored.
	// Default value: "user"
	XssecProperty string
	// The function that will be called when there's an error validating the token
	// Default value:
	ErrorHandler errorHandler
	// Debug flag turns on debugging output
	// Default: false
	Debug bool
	// Function to Validate JKU
	JKUValidator validation.JKUValidationFunc
	// Function to make xsuaa specific audience and clientId checks
	AudienceValidator validation.JWTValidationFunc
	// The function that will return the Key to validate the JWT.
	// It can be either a shared secret or a public key.
	// Default value: nil
	ValidationKeyGetter jwt.Keyfunc
}

func (m *XssecMiddleware) Handler(h http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Let secure process the request. If it returns an error,
		// that indicates the request should not continue.
		err := m.CheckJWT(w, r)

		// If there was an error, do not continue.
		if err != nil {
			return
		}

		h.ServeHTTP(w, r)
	})
}

// FromAuthHeader is a "TokenExtractor" that takes a give request and extracts
// the JWT token from the Authorization header.
func FromAuthHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil // No error, just no token
	}

	// TODO: Make this a bit more robust, parsing-wise
	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

func (m *XssecMiddleware) CheckJWT(w http.ResponseWriter, r *http.Request) error {

	// Use the specified token extractor to extract a token from the request
	token, err := FromAuthHeader(r)

	// If debugging is turned on, log the outcome
	if err != nil {
		m.logf("Error extracting JWT: %v", err)
	} else {
		m.logf("Token extracted: %s", token)
	}

	// If an error occurs, call the error handler and return an error
	if err != nil {
		m.Options.ErrorHandler(w, r, err.Error())
		return fmt.Errorf("Error extracting token: %v", err)
	}

	// Now create xsseccontext with the provided config and functions!
	xssecContext, err := xssecgo.NewXssecContext(token, m.XsuaaConfig,
		xssecgo.Options{

			ValidationKeyGetter: m.Options.ValidationKeyGetter,
			JKUValidator:        m.Options.JKUValidator,
			AudienceValidator:   m.Options.AudienceValidator,
		})

	// Check if there was an error in parsing...
	if err != nil {
		m.logf("Error creating security context: %v", err)
		m.Options.ErrorHandler(w, r, err.Error())
		return fmt.Errorf("Error parsing token: %v", err)
	}

	// If we get here, everything worked and we can set the
	// xssecproperty in context.
	newRequest := r.WithContext(context.WithValue(r.Context(), m.Options.XssecProperty, xssecContext))
	// Update the current request with the new context information.
	*r = *newRequest
	return nil
}

func OnError(w http.ResponseWriter, r *http.Request, err string) {
	http.Error(w, err, http.StatusUnauthorized)
}

func (m *XssecMiddleware) logf(format string, args ...interface{}) {
	if m.Options.Debug {
		log.Printf(format, args...)
	}
}
