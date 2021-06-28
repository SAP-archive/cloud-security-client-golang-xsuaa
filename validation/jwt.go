package validation

import (
	"errors"
	"fmt"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/util"
	"github.com/dgrijalva/jwt-go/v4"
	"strings"
)

const DOT = "."

// takes a decodedToken and checks for XSUAA specific rules (mostly if the audience fits to the configured clientId, xsapp from the XSUAA binding
func ValidateJWT(decodedToken *jwt.Token, clientId, xsAppName string) (bool, error) {

	if len(clientId) == 0 {
		return false, errors.New("No xsuaa clientId provided")
	}

	// get claims from token
	claims := decodedToken.Claims.(jwt.MapClaims)

	audiencesFromToken := claims["aud"].([]interface{})
	scopesFromToken := claims["scope"].([]interface{})
	cidFromToken := claims["cid"].(string)
	zidFromToken := claims["zid"].(string)

	if len(cidFromToken) == 0 {
		return false, errors.New("client Id not contained in access token. Giving up")
	}

	if len(zidFromToken) == 0 {
		return false, errors.New("identity Zone not contained in access token. Giving up")
	}

	isAudienceValid, err := ValidateJWTAudience(audiencesFromToken, scopesFromToken, cidFromToken, clientId, xsAppName)
	if err != nil {
		return false, err
	}

	return isAudienceValid, nil

}

func ValidateJWTAudience(audiencesFromToken []interface{}, scopesFromToken []interface{}, cidFromToken, clientId, xsAppName string) (bool, error) {

	allowedAudiences := ExtractAudiences(audiencesFromToken, scopesFromToken, cidFromToken)

	var clientIds []string
	// gather clientId and xsappName for better processing
	if len(xsAppName) > 0 {
		clientIds = []string{clientId, xsAppName}
	} else {
		clientIds = []string{clientId}
	}

	if validateSameClientId(cidFromToken, clientId) || validateAudienceOfXsuaaBrokerClone(clientIds, allowedAudiences) || validateDefault(clientIds, allowedAudiences) {
		return true, nil
	} else {
		return false, errors.New(fmt.Sprintf("Jwt token with audience: %v is not issued for these clientIds: %v ", allowedAudiences, clientIds))
	}

}

func validateSameClientId(cidFromToken, clientId string) bool {

	if len(cidFromToken) == 0 || len(clientId) == 0 {
		return false
	}

	return strings.TrimSpace(cidFromToken) == strings.TrimSpace(clientId)

}

func validateAudienceOfXsuaaBrokerClone(clientIds, allowedAudiences []string) bool {

	for _, clientId := range clientIds {

		if strings.Contains(clientId, "!b") { //isABrokerClientId!

			// check if the client belongs to a broker!
			for _, audience := range allowedAudiences {

				if strings.HasSuffix(audience, "|"+clientId) {
					return true
				}
			}
		}

	}

	return false

}

func validateDefault(clientIds, allowedAudiences []string) bool {

	stringMap := util.StringSliceToStringMap(allowedAudiences)

	for _, v := range clientIds {
		if stringMap[v] {
			return true
		}
	}

	return false

}

func ExtractAudiences(aud []interface{}, scopes []interface{}, cid string) []string {

	var audiences = map[string]bool{}
	tokenAudiences := aud

	for i := 0; i < len(tokenAudiences); i++ {
		var audience = tokenAudiences[i].(string)
		if strings.Index(audience, DOT) > -1 {
			// CF UAA derives the audiences from the scopes.
			// In case the scopes contains namespaces, these needs to be removed.
			var aud = strings.TrimSpace(audience[0:strings.Index(audience, DOT)])

			if len(aud) > 0 && !audiences[aud] {
				audiences[aud] = true
			}
		} else {
			audiences[audience] = true
		}
	}

	if len(audiences) == 0 {
		for i := 0; i < len(scopes); i++ {

			var scope = scopes[i].(string)
			if strings.Index(scope, DOT) > -1 {
				var aud = strings.TrimSpace(scope[0:strings.Index(scope, DOT)])

				if len(aud) > 0 && !audiences[aud] {
					audiences[aud] = true
				}
			}
		}
	}

	if len(cid) > 0 && !audiences[cid] {
		audiences[cid] = true
	}

	return util.MapToStringSlice(audiences)

}
