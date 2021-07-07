[![REUSE status](https://api.reuse.software/badge/github.com/SAP-samples/cloud-security-client-golang-xsuaa)](https://api.reuse.software/info/github.com/SAP-samples/cloud-security-client-golang-xsuaa)

# XSUAA Golang client library sample for SAP Business Technology Platform
Sample library to show how to use XSUAA in Golang applications running on SAP Business Technology Platform.

This is not an official library (**ITS A SAMPLE!!**) and therefore is not been maintained in the future or is been updated to solve further security issues or reflect the current state of https://www.npmjs.com/package/@sap/xssec or https://github.com/SAP/cloud-security-xsuaa-integration. It should rather act as an inspiration for people trying to reuse or initiate their Golang applications on SAP BTP.
The library has ported most of the functionality of the NodeJS xssec library (https://www.npmjs.com/package/@sap/xssec). As you can see there are also tests taken over from the xssec NodeJS lib to ensure the validation and verification algorithms are reflected as good as possible. But - as already stated - no guarantee if everything works as expected ;) If you find an error and/or want to add missign functionalities feel free to open a pull request (**with tests!**)


## Description

Library to work with xsuaa (For an introduction read [Article about extended services for UAA](https://blogs.sap.com/2020/08/20/demystifying-xsuaa-in-sap-cloud-foundry/)) using Golang in your application.

Awesome third party libs used to get this running:

- [github.com/dgrijalva/jwt-go/v4](github.com/dgrijalva/jwt-go/v4) For verification and parsing of the JWT
- [github.com/stretchr/testify/assert](github.com/stretchr/testify/assert) For unit tests
- [github.com/lestrrat-go/jwx/jwk](github.com/lestrrat-go/jwx/jwk) For handling public key retrieval (Jwks)
- [github.com/patrickmn/go-cache](github.com/patrickmn/go-cache) For caching public key

**This library is NOT using offline verification of XSUAA binding and instead only using JWKs.**

You are able to inject a custom configured Cache to fit this behavior to your needs (read further).

The library is split in two parts:

- **Xssec** as the base and providing most of the features to deal with XSUAA related security context.
- **Xssec middleware** that can be used within your router to automatically parse incoming Bearer Token and protect services to have at least a valid authentication against the configured XSUAA component

## Requirements

- **Golang v1.15**

## Download and Installation

Like with every Golang lib you just need to import it:

```golang
import (
        xssecgo "github.com/SAP-samples/cloud-security-client-golang-xsuaa"
        )
```

The library is by default not using a consistent state, but rather is been instantiated whenever you need a Security Context based on the JWT been found in the header.

Let's assume you have extracted a JWT from whatever source (Param, Authorization Header, ...) and now want to check if this token is valid and been provided by the bound XSUAA instance. All you need to do is passing the string together with a xsuaaConfiguration object and additional options (explained further)

```golang
	xsuaaConfig := config.XsuaaConfig{

		ClientId:  "clientId",
		XsAppName: "xsAppName",
		Url:       "url",
		UaaDomain: "uaa",
	}

	context, err := pkg.NewXssecContext(rawTokenString, xsuaaConfig, pkg.Options{})
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(context.FamilyName)
```

If the token been passed is "valid" you will get a XssecContext object that will offer access to all the data been available in the JWT and additional helper methods to check the scope for further permission checks.

### Configuration of Xssec

The option object been passed to the factory gives you the capabilites to adjust the validation and verification of the Xssec IF you need custom logic. A good example might be the **ValidationGetter** as this method is used to retrieve the JWK.
The **JKUValidator** is used to check the JKU with the configured domain. And might also be adjusted to your needs.

```golang
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
```

### Working with a cache

To avoid round trips during the Validation of the public key there is already a helper function implemented that can be used instead of the default one: **ValidationKeyGetterWithCacheDefault** (been found in the verification package). The function is leveraging the popular [github.com/patrickmn/go-cache](github.com/patrickmn/go-cache) lib.

A simple example of how to use a cache:

```golang

	// create xsuaa config from binding
	xsuaaConfig := config.XsuaaConfig{

		ClientId:  "clientId",
		XsAppName: "xsAppName",
		Url:       "url",
		UaaDomain: "uaa",
	}

	// initialize cache
	configCache := cache.New(8*time.Hour, 10*time.Hour)

	context, err := pkg.NewXssecContext(
		rawTokenString,
		xsuaaConfig,
		pkg.Options{
			ValidationKeyGetter: verification.ValidationKeyGetterWithCacheDefault(xsuaaConfig, configCache),
		})

	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(context.FamilyName)

```
Please consider making the cache a single instance outside of the config as though it will be persistent.
### Using the middleware

```golang
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

```

 

## Known Issues

Nothing found so far ;) 

## How to obtain support

[Create an issue](https://github.com/SAP-samples/cloud-security-client-golang-xsuaa/issues) in this repository if you find a bug or have questions about the content.
 
For additional support, [ask a question in SAP Community](https://answers.sap.com/questions/ask.html).

## Contributing

Contributions are welcome! Please open a pull request and we will provide feedback as soon as possible.

## License
Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This project is licensed under the Apache Software License, version 2.0 except as noted otherwise in the [LICENSE](LICENSES/Apache-2.0.txt) file.
