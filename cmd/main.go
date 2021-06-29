package main

import (
	"fmt"
	xssecgo "github.com/SAP-samples/cloud-security-client-golang-xsuaa"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/config"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/middleware"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/middleware/helper"
	"net/http"
)

func main() {

	xssecMiddleware := middleware.XssecMiddleware{

		// take this env variables from your binding during runtime
		XsuaaConfig: config.XsuaaConfig{
			ClientId:  "clientId",
			XsAppName: "appName",
			Url:       "url",
			UaaDomain: "domain",
		},
	}

	http.Handle("api", xssecMiddleware.Handler(helper.HasLocalScopesHandler(func(writer http.ResponseWriter, request *http.Request) {

		// do something in your handler
		xssec := request.Context().Value("user").(*xssecgo.XssecContext)
		fmt.Println(xssec.FamilyName)
		fmt.Println(xssec.Email)

		// check scopes
		fmt.Println(xssec.Scope)

	}, []string{"admin"}, "")))

	http.ListenAndServe(":8080", nil)
}
