package main

import (
	"fmt"
	xssecgo "github.com/SAP-samples/cloud-security-client-golang-xsuaa"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/config"
)

var TEST_XSUAA_CONFIG_FOR_SCOPE_TOKEN config.XsuaaConfig = config.XsuaaConfig{

	ClientId:  "sb-hangman-solution!t5593",
	XsAppName: "hangman-solution!t5593",
	Url:       "https://cftraining.authentication.sap.hana.ondemand.com",
	UaaDomain: "authentication.sap.hana.ondemand.com",
}

const VALID_TOKEN_WITH_SCOPE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI2ZjQ1OGZkNWZmODY0NWY0YWMwNDNhNmU1YWViNGYxNSIsImV4dF9hdHRyIjp7ImVuaGFuY2VyIjoiWFNVQUEiLCJzdWJhY2NvdW50aWQiOiI0NmVmZmM0MC1lZjBjLTQ0OGQtYjZkZC0wMTlmNDBmYTBhZGUiLCJ6ZG4iOiJjZnRyYWluaW5nIn0sInhzLnN5c3RlbS5hdHRyaWJ1dGVzIjp7InhzLnJvbGVjb2xsZWN0aW9ucyI6WyJoYW5nbWFuLXVzZXJzIl19LCJnaXZlbl9uYW1lIjoiSm9obiIsInhzLnVzZXIuYXR0cmlidXRlcyI6e30sImZhbWlseV9uYW1lIjoiRG9lIiwic3ViIjoiMWQyODk5MDEtZGIxMC00YTk2LThjZmUtMWQ1MDg0YzNlYjc5Iiwic2NvcGUiOlsib3BlbmlkIiwiaGFuZ21hbi1zb2x1dGlvbiF0NTU5My5wbGF5SGFuZ21hbiIsInVhYS51c2VyIl0sImNsaWVudF9pZCI6InNiLWhhbmdtYW4tc29sdXRpb24hdDU1OTMiLCJjaWQiOiJzYi1oYW5nbWFuLXNvbHV0aW9uIXQ1NTkzIiwiYXpwIjoic2ItaGFuZ21hbi1zb2x1dGlvbiF0NTU5MyIsImdyYW50X3R5cGUiOiJhdXRob3JpemF0aW9uX2NvZGUiLCJ1c2VyX2lkIjoiMWQyODk5MDEtZGIxMC00YTk2LThjZmUtMWQ1MDg0YzNlYjc5Iiwib3JpZ2luIjoiYWNjb3VudHMuc2FwLmNvbSIsInVzZXJfbmFtZSI6IjEyMzQ1IiwiZW1haWwiOiJ0ZXN0QHNhcC5jb20iLCJhdXRoX3RpbWUiOjE2MDQ0ODEwOTMsInJldl9zaWciOiI4NGNiODQ0IiwiaWF0IjoxNjA0NDgxMDk0LCJleHAiOjUwMDAwMDAwMDAsImlzcyI6Imh0dHA6Ly9jZnRyYWluaW5nLmxvY2FsaG9zdDo4MDgwL3VhYS9vYXV0aC90b2tlbiIsInppZCI6IjQ2ZWZmYzQwLWVmMGMtNDQ4ZC1iNmRkLTAxOWY0MGZhMGFkZSIsImF1ZCI6WyJzYi1oYW5nbWFuLXNvbHV0aW9uIXQ1NTkzIiwidWFhIiwib3BlbmlkIiwiaGFuZ21hbi1zb2x1dGlvbiF0NTU5MyJdfQ.L4W2rhDLASoeQ9O6EvFXa-T6vOl79J7Zx9QFX-p3Z2rc8CDcNbeNwPcCEelqdv5U_ujd2kyDhgblL0vaeYLdwuPhYEXmIMNJ4R20TSfFSwj8IzvVoYCdsV7dKiU-BjXd6YLhVAjDOVZCS5Bc1WcNMec5JRBFiMnPDwbxdNE0E_nTZPZufooUO1IZZN4gg1jqDFj3ORsRdmAANvS-nXaJMlHuljj3X2QAYSPgpwm53CPKQFD2a745SOfoS7DO1IG_GoSgAcfWhHzTrpaftnfyZD5DaHn2AtxpA5YWJc7og76eFNlJWqyN554YTmzix8YW96KwvEErJpYz3okaOaiNVTxMn_C1q5f7-RUHAPqXsDAI9UK6vq51Q5eptlqlcytJBBMSX09FOL10XRtCKapPH4RKG3RBFs4OSW9HzcUGRRU2tNQ39usnmyQKv8gv1G0uzTHR2S-bDYSGgEUC5SktUwpB8MwCXw1j0exiUxO_MGRSTUFmLhZnRg4FWZGVAb554b7WdjKsnvlDGHH7tRZZpxv5yGt1d2F2OTig3bn1JaDxE0JL1GwI0B3YofCNO9JP_IY4MavDRhO34OaMP0gFB1mly-tUKRmiivJTbrGmyPIZKCP0bHECCWir0Y2l8NMcqn7kaMC0TxWaolbK1g8J1gnnyFYvAW3rfhtZPrh91u0"

func main() {

	// jwt to be checked
	rawTokenString := VALID_TOKEN_WITH_SCOPE
	//key, _ := util.GetRSAKeyFromString(TEST_PUBLIC_KEY)

	// create xsuaa config from binding
	xsuaaConfig := config.XsuaaConfig{

		ClientId:  "clientId",
		XsAppName: "xsAppName",
		Url:       "url",
		UaaDomain: "uaa",
	}

	// initialize cache
	//	configCache := cache.New(8*time.Hour, 10*time.Hour)

	context, err := xssecgo.NewXssecContext(
		rawTokenString,
		xsuaaConfig)

	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(context.FamilyName)
	fmt.Println(context)
	fmt.Println(context.CheckLocalScope("playHangman"))

}
