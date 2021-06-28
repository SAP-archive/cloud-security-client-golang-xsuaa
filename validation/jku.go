package validation

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

func JKUValidator(jkuUrl, uaaDomain string) (bool, error) {

	if len(uaaDomain) == 0 {
		return false, errors.New("Service is not properly configured in VCAP_SERVICES, attribute uaadomain is missing. Use legacy-token-key.")
	}

	tokenKeyUrl, err := url.Parse(jkuUrl)
	if err != nil {
		return false, errors.New("URL not parsable within the header")
	}

	hostname := tokenKeyUrl.Hostname()

	//cut off subdomains (account dependent and check only for xsuaa component url)
	extractedUaaDomain := hostname[strings.Index(hostname, uaaDomain):]

	// check if jku host corresponds to uaaDomain (Do not trust anyone else!!)
	if extractedUaaDomain != uaaDomain {
		return false, errors.New(fmt.Sprintf("JKU of the JWT token (' %s ') does not match with the uaa domain (' %s '). Use legacy-token-key.", jkuUrl, uaaDomain))
	}

	return true, nil

}
