package helper

import (
	"fmt"
	xssecgo "github.com/SAP-samples/cloud-security-client-golang-xsuaa"
	"net/http"
)

func HasLocalScopesHandler(h http.Handler, localScopes []string, xssecProperty string) http.Handler {

	if xssecProperty == "" {
		xssecProperty = "user"
	}

	unsufficientScopeString := fmt.Sprintf("No sufficient scopes to call service. Scopes needed: %v", localScopes)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		dispatchErrorWithScopes := func() {

			http.Error(w, unsufficientScopeString, http.StatusForbidden)
		}

		// extract scopes from user
		xssecContext := r.Context().Value(xssecProperty).(*xssecgo.XssecContext)
		if xssecContext == nil {
			http.Error(w, "no xsseccontext found. seems like middleware is missing", http.StatusForbidden)
			return
		}

		if len(xssecContext.Scope) < len(localScopes) {
			dispatchErrorWithScopes()
		}

		for _, v := range localScopes {

			if !xssecContext.CheckLocalScope(v) {
				dispatchErrorWithScopes()
				return
			}

		}

		h.ServeHTTP(w, r) // all params present, proceed
	})
}
