package validation

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var DEFAULT_AUDIENCES = []interface{}{"client", "foreignclient", "sb-test4!t1.data"}

const XSUAA_BROKER_XSAPPNAME = "brokerplanmasterapp!b123"

// validateToken(decodedToken.aud, decodedToken.scope, decodedToken.cid);

func TestAudienceMatchesClientId(t *testing.T) {

	isValid, err := ValidateJWTAudience(DEFAULT_AUDIENCES, nil, "", "client", "")

	assert.True(t, isValid, err)

}

func TestTokenWithoutAudiencesButScopes(t *testing.T) {

	var scopes = []interface{}{"client.read", "test1!t1.read", "client.write", "xsappid.namespace.ns.write", "openid", "client.read"}
	assertions := assert.New(t)

	audiences := ExtractAudiences(nil, scopes, "cid")

	assertions.Len(audiences, 4)
	assertions.Contains(audiences, "test1!t1")
	assertions.Contains(audiences, "client")
	assertions.Contains(audiences, "xsappid")

	audiences = ExtractAudiences(nil, scopes, "client")
	assertions.Len(audiences, 3)

}

func TestBrokerCloneTokenWithoutAudiencesAndWithoutScopes(t *testing.T) {

	isValid, err := ValidateJWTAudience(nil, nil, "sb-4711!b123|APP!b123", "sb-APP!b123", "APP!b123")

	assert.True(t, isValid, err)

}

func TestTokenAudienceMatchesAppId(t *testing.T) {

	audiences := []interface{}{"appId!t1"}

	isValid, err := ValidateJWTAudience(audiences, nil, "", "sb-appId!t1", "appId!t1")
	assert.True(t, isValid, err)

}

func TestTokenAudienceMatchesForeignClientId(t *testing.T) {

	isValid, err := ValidateJWTAudience(DEFAULT_AUDIENCES, nil, "", "any", "foreignclient")
	assert.True(t, isValid, err)

}

func TestClientIdMatchesTokenAudienceWithoutDot(t *testing.T) {

	audiences := []interface{}{"client", "foreignclient", "sb-test4!t1.data.x"}

	isValid, err := ValidateJWTAudience(audiences, nil, "", "sb-test4!t1", "")
	assert.True(t, isValid, err)

}

func TestBrokerClientIdMatchesCloneAudience(t *testing.T) {

	audiences := []interface{}{"sb-f7016e93-8665-4b73-9b46-f99d7808fe3c!b446|" + XSUAA_BROKER_XSAPPNAME}

	isValid, err := ValidateJWTAudience(audiences, nil, "", "sb-"+XSUAA_BROKER_XSAPPNAME, XSUAA_BROKER_XSAPPNAME)
	assert.True(t, isValid, err)

}

func TestBrokerClientIdDoesNotMatchCloneAudience(t *testing.T) {

	audiences := []interface{}{"sb-f7016e93-8665-4b73-9b46-f99d7808fe3c!b446|ANOTHERAPP!b12"}

	isValid, err := ValidateJWTAudience(audiences, nil, "", "sb-ANOTHERAPP!b12", "ANOTHERAPP!b12")
	assert.True(t, isValid, err)

}

func TestShouldFailWhenNoTokenAndAudienceMatches(t *testing.T) {

	isValid, err := ValidateJWTAudience(DEFAULT_AUDIENCES, nil, "", "any", "anyother")
	assert.False(t, isValid, err)

}

func TestShouldFilterEmptyAudiences(t *testing.T) {

	audiences := []interface{}{".", "test.", " .test2"}

	isValid, err := ValidateJWTAudience(audiences, nil, "", "any", "")
	assert.False(t, isValid, err)

}

func TestShouldFailWithEmptyAudiences(t *testing.T) {

	var audiences []interface{}

	isValid, err := ValidateJWTAudience(audiences, nil, "", "any", "")
	assert.False(t, isValid, err)

}
