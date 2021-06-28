package xssecgo

import (
	"encoding/json"
	"errors"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/config"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/util"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/validation"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/verification"
	"github.com/dgrijalva/jwt-go/v4"
	"strings"
	"time"
)

const XSAPPNAMEPREFIX = "$XSAPPNAME."

// Convenience DTO to allow direct access to properties from the token and additional methods to check for permission via scopes/attributes
type XssecContext struct {
	xsAppname string
	RawToken  jwt.Token
	Jti       string `json:"jti"`
	ExtAttr   struct {
		Enhancer          string `json:"enhancer"`
		Subaccountid      string `json:"subaccountid"`
		Zdn               string `json:"zdn"`
		Serviceinstanceid string `json:"serviceinstanceid"`
	} `json:"ext_attr"`
	XsSystemAttributes struct {
		XsRolecollections []string `json:"xs.rolecollections"`
	} `json:"xs.system.attributes"`
	GivenName        string `json:"given_name"`
	XsUserAttributes struct {
	} `json:"xs.user.attributes"`
	FamilyName string   `json:"family_name"`
	Sub        string   `json:"sub"`
	Scope      []string `json:"scope"`
	ClientID   string   `json:"client_id"`
	Cid        string   `json:"cid"`
	Azp        string   `json:"azp"`
	GrantType  string   `json:"grant_type"`
	UserID     string   `json:"user_id"`
	Origin     string   `json:"origin"`
	UserName   string   `json:"user_name"`
	Email      string   `json:"email"`
	AuthTime   int      `json:"auth_time"`
	RevSig     string   `json:"rev_sig"`
	Iat        int      `json:"iat"`
	Exp        int      `json:"exp"`
	Iss        string   `json:"iss"`
	Zid        string   `json:"zid"`
	Aud        []string `json:"aud"`

	scopesAsMap map[string]bool // for better processing and checks
}

// Options is a struct for specifying configuration options.
type Options struct {
	// The function that will return the Key to validate the JWT.
	// It can be either a shared secret or a public key.
	// Default value: nil
	ValidationKeyGetter jwt.Keyfunc

	// Function to Validate JKU
	JKUValidator validation.JKUValidationFunc

	// Function to make xsuaa specific audience and clientId checks
	AudienceValidator validation.JWTValidationFunc
}

func NewXssecContext(rawToken string, xsuaaConfig config.XsuaaConfig, xssecOptions ...Options) (*XssecContext, error) {

	var options Options
	if xssecOptions == nil || len(xssecOptions) == 0 {
		options = Options{}
	} else {
		options = xssecOptions[0]
	}

	// copy options
	validationKeyGetter := options.ValidationKeyGetter
	jkuValidator := options.JKUValidator
	audienceValidator := options.AudienceValidator

	if len(xsuaaConfig.ClientId) == 0 {
		return nil, errors.New("no ClientId available in xsuaa config")
	}

	if len(xsuaaConfig.XsAppName) == 0 {
		return nil, errors.New("no xsappname available in xsuaa config")
	}

	if len(xsuaaConfig.Url) == 0 {
		return nil, errors.New("no url available in xsuaa config")
	}

	if len(xsuaaConfig.UaaDomain) == 0 {
		return nil, errors.New("no UaaDomain available in xsuaa config")
	}

	// check different functions and initialize with default if not set by options!
	if jkuValidator == nil {
		jkuValidator = validation.JKUValidator
	}

	if validationKeyGetter == nil {
		validationKeyGetter = verification.ValidationKeyGetter(xsuaaConfig, jkuValidator)
	}

	if audienceValidator == nil {
		audienceValidator = validation.ValidateJWT
	}

	// decode and verify token with KeyFunc
	decodedToken, err := jwt.Parse(rawToken, validationKeyGetter, jwt.WithoutAudienceValidation(), jwt.WithLeeway(1*time.Minute))

	if err != nil {
		return nil, err
	}

	// use xsuaa specific checks to assure domain validity
	_, audienceErr := audienceValidator(decodedToken, xsuaaConfig.ClientId, xsuaaConfig.XsAppName)
	if audienceErr != nil {
		return nil, err
	}

	// lazy --> use raw json to convert to go struct
	// you might create a PR and map all custom claims to go :)
	jsonStringClaims, decodeErr := jwt.DecodeSegment(strings.Split(decodedToken.Raw, ".")[1])
	if decodeErr != nil {
		return nil, errors.New("something went wrong decoding body base64 to json")
	}

	var xssecContext XssecContext
	jsonErr := json.Unmarshal([]byte(jsonStringClaims), &xssecContext)

	if jsonErr != nil {
		return nil, errors.New("something went wrong converting json to go struct")
	}

	// fill additional infos for further processing in convenience methods like checkScope
	xssecContext.xsAppname = xsuaaConfig.XsAppName
	xssecContext.scopesAsMap = util.StringSliceToStringMap(xssecContext.Scope)

	return &xssecContext, nil
}

func (x *XssecContext) CheckLocalScope(scope string) bool {

	tokenScopes := x.Scope
	xsAppName := x.xsAppname
	scopesAsMap := x.scopesAsMap

	if len(scope) == 0 || tokenScopes == nil || len(tokenScopes) == 0 {
		return false
	}

	scopeName := xsAppName + "." + scope

	return scopesAsMap[scopeName]

}

func (x *XssecContext) CheckScope(scope string) bool {

	tokenScopes := x.Scope
	xsAppName := x.xsAppname
	scopesAsMap := x.scopesAsMap

	if len(scope) == 0 || tokenScopes == nil || len(tokenScopes) == 0 {
		return false
	}

	if len(scope) > len(XSAPPNAMEPREFIX) && scope[0:len(XSAPPNAMEPREFIX)-1] == XSAPPNAMEPREFIX {
		scope = strings.Replace(scope, XSAPPNAMEPREFIX, xsAppName+".", -1)

	}

	return scopesAsMap[scope]
}
