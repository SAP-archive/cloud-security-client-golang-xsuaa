package validation

import (
	"github.com/dgrijalva/jwt-go/v4"
)

type JKUValidationFunc func(jkuUrl, uaaDomain string) (bool, error)
type JWTValidationFunc func(decodedToken *jwt.Token, clientId, xsAppName string) (bool, error)
