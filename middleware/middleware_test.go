package middleware

import (
	xssecgo "github.com/SAP-samples/cloud-security-client-golang-xsuaa"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/config"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/middleware/helper"
	"github.com/SAP-samples/cloud-security-client-golang-xsuaa/util"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/stretchr/testify/assert"

	"net/http"
	"net/http/httptest"
	"testing"
)

// {
//	"tenantmode": "dedicated",
//	"sburl": "https://internal-xsuaa.authentication.sap.hana.ondemand.com",
//	"clientid": "sb-hangman-solution!t5593",
//	"xsappname": "hangman-solution!t5593",
//	"url": "https://cftraining.authentication.sap.hana.ondemand.com",
//	"uaadomain": "authentication.sap.hana.ondemand.com",

const TEST_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----"
const TEST_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApvaSt7X7/nfXpVX8s9/Az1SqMJZAbDzJMNBfwzKZqOQ5UNYoUtDRWMhSQ0aYtV74iHF7fTKEE4VbVgj2aMxm2u3J+7hJGxa9Sxf0h7SKq/fEJa7y7zyADfaIbOZIdiPrDfUarICH+CjgAQIDW4de3+kWanpaZjDhd9BIqL/A2/ReRP1Qtdmt7bGyfG/toDIy8mwX44zeTcsOpS/zpHuDQF5BblY3SYWQ5NJgOHU8YL/QALw1dVE2qKJJyJx5lFNkyyJh/xRMK42HPMlvTWADuDz9OqO0H+FYlLSo4grBfg6Z0+9N0FRMiSjn+UKiLs7KRsH7gCWh/8MrMQ9tor672THHMt3PZZ9VYST+LEssp0y5Aeezic5j07XbqXUa6WAWec+RjMAgffkeJfbbh4iZ+0jpm+3p0U9018mRFCkjbiDDGUEJNzU2T6Cj7bECA+ZBtE4n9pLfYa44HRCwsBChd/TGyUbd1IgMStFpspRC3Hrk2Rb3wScNE5xRZ4owxvjMeHFgvVT+cCyHKEGSdON+sxes4JaOzXs339GNUq7LHaZGYK+NtjB5bwG2+B0JrUtJkOwFsmKYe+opod3v+fylzOjMxt12KASZtUZoSitMQGZ2isowhl7vuQwobsBWfgx2FArabcH4n/wlxFfqdyzIdJ4vbqyzInYAOm43B4aN/gsCAwEAAQ==\n-----END PUBLIC KEY-----"
const VALID_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJjNjgzMTEyNS0xZWQ2LTQxYjAtOGVhOC1lNjBhMzQxYTI3ODciLCJzdWIiOiI0MjUxMzAiLCJzY29wZSI6WyJvcGVuaWQiLCJ1YWEucmVzb3VyY2UiXSwiY2xpZW50X2lkIjoic2IteHNzZWN0ZXN0IiwiY2lkIjoic2IteHNzZWN0ZXN0IiwiYXpwIjoic2IteHNzZWN0ZXN0IiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6IjQyNTEzMCIsInVzZXJfbmFtZSI6Ik5PREVURVNUVVNFUiIsImVtYWlsIjoiTm9kZXRlc3RAc2FwLmNvbSIsIm9yaWdpbiI6InRlc3RpZHAiLCJnaXZlbl9uYW1lIjoiTm9kZXRlc3RGaXJzdE5hbWUiLCJmYW1pbHlfbmFtZSI6Ik5vZGV0ZXN0TGFzdE5hbWUiLCJpYXQiOjE0NzA4MTU0MzQsImV4cCI6MjEwMTUzNTQzNCwiaXNzIjoiaHR0cDovL3BhYXMubG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuIiwiemlkIjoidGVzdC1pZHoiLCJoZGIubmFtZWR1c2VyLnNhbWwiOiI8P3htbCB2ZXJzaW9uPVwiMS4wXCIgZW5jb2Rpbmc9XCJVVEYtOFwiPz48c2FtbDI6QXNzZXJ0aW9uIHhtbG5zOnNhbWwyPVwidXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvblwiIElEPVwiXzcxZWUxNzc2LTlkMmYtNDk3My1hY2E4LTllMjJiMjk2N2FjOFwiIElzc3VlSW5zdGFudD1cIjIwMTYtMDgtMTBUMDc6NDU6MzQuMzQ3WlwiIFZlcnNpb249XCIyLjBcIj48c2FtbDI6SXNzdWVyPlRTVC1zYW1sPC9zYW1sMjpJc3N1ZXI-PGRzOlNpZ25hdHVyZSB4bWxuczpkcz1cImh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNcIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09XCJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biNcIi8-PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09XCJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTFcIi8-PGRzOlJlZmVyZW5jZSBVUkk9XCIjXzcxZWUxNzc2LTlkMmYtNDk3My1hY2E4LTllMjJiMjk2N2FjOFwiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPVwiaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmVcIi8-PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09XCJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biNcIi8-PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPVwiaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTFcIi8-PGRzOkRpZ2VzdFZhbHVlPm91OHIzUjBXQkhHMWJwNEtLT3gxUHlWT2lZQT08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU-TGJSS3Yxci9oN0lNbWlTeXgxMFdrTTdKdWVrcm13eVZOc0I1M3BrRlJucmpDR1d0bUZrUXNrbnNMN2VUVU40K2djSkdXMHFHVFVtdlVrZlhFMU84cmYyQ21UY0MwMWNZc0dBWldiTnBPTE5tcFA5Z0c2NTcycHZlUnFqVFhMR1NpbE0yZWpKaXlscTJKbkZMaFhwZ3JuVGJDdlFXNmE5SlRwUnB2TXo4U2lTb2R4YXg3ckp3N0MweVp6VXE4NjJNNXlOamRvSUhoRWtuZ01jQzVMRERoZnBmNlRrUU1zeVZjTWFtRHFqVFM3V1RndmtRS2w1cGtPUEtFdWhUakNSN1A3S0Fla2VEbVlvcXM3eUVacnJkS0VpeFNZNGk1RjN3ZU0rZHcrQTF1ZTlqRjJLbWVSdmpveHMyaHdmc1d3VXZDeHkrMkpocjU0dmF0bXdlRzhkSTBRPT08L2RzOlNpZ25hdHVyZVZhbHVlPjwvZHM6U2lnbmF0dXJlPjxzYW1sMjpTdWJqZWN0PjxzYW1sMjpOYW1lSUQgRm9ybWF0PVwidXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6dW5zcGVjaWZpZWRcIj5OT0RFVEVTVFVTRVI8L3NhbWwyOk5hbWVJRD48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9XCJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyXCI-PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb25EYXRhIE5vdE9uT3JBZnRlcj1cIjIwMTYtMDgtMTBUMTE6NTA6MzQuMzQ3WlwiLz48L3NhbWwyOlN1YmplY3RDb25maXJtYXRpb24-PC9zYW1sMjpTdWJqZWN0PjxzYW1sMjpDb25kaXRpb25zIE5vdEJlZm9yZT1cIjIwMTYtMDgtMTBUMDc6NDU6MzQuMzQ3WlwiIE5vdE9uT3JBZnRlcj1cIjIwMTYtMDgtMTBUMTE6NTA6MzQuMzQ3WlwiLz48c2FtbDI6QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PVwiMjAxNi0wOC0xMFQwNzo1MDozNC4zNDdaXCIgU2Vzc2lvbk5vdE9uT3JBZnRlcj1cIjIwMTYtMDgtMTBUMDc6NTU6MzQuMzQ3WlwiPjxzYW1sMjpBdXRobkNvbnRleHQ-PHNhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwyOkF1dGhuQ29udGV4dD48L3NhbWwyOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDI6QXNzZXJ0aW9uPiIsImF6X2F0dHIiOnsiZXh0ZXJuYWxfZ3JvdXAiOiJkb21haW5ncm91cDEiLCJleHRlcm5hbF9pZCI6ImFiY2QxMjM0In0sImV4dF9hdHRyIjp7InNlcnZpY2VpbnN0YW5jZWlkIjoiYWJjZDEyMzQiLCJ6ZG4iOiJwYWFzIn0sInhzLnN5c3RlbS5hdHRyaWJ1dGVzIjp7InhzLnNhbWwuZ3JvdXBzIjpbIkNhbmFyeV9Sb2xlQnVpbGRlciJdLCJ4cy5yb2xlY29sbGVjdGlvbnMiOltdfSwieHMudXNlci5hdHRyaWJ1dGVzIjp7ImNvdW50cnkiOlsiVVNBIl19LCJhdWQiOlsic2IteHNzZWN0ZXN0Iiwib3BlbmlkIl19.Vc8sZEu_qEHqnz6NqTpTiRPl6WM-RbURtpmdHgigemIDXTLbsu4njQ2ZtZ78fJ6Q_4C61JdRO11MC_h5w7JHQ9vHVlizeNPd7e2XhhT_MSmaFnHWxJz-av3c9SgQsAMynBp-2-BIZvNSYT7jQLPQb9M_v93p2fXt4Tdw5h7aHwvXtGRKmC6cEvhjt9bRgN2nymhh35z128PIzai9rCevLvRZrnuDBPTWdaUYHGlNT-DDnyxPTDz6dgCqmeqz50uX6mvgC8i0X2qIZSfZJH5Q9ubZZ7RLU2EpWWK1svZIjk1ImckaQfVH2tX_P-fL2YemA_WC5-pRKyL0Kh9D7y7H4ZbQ9aanyh_bEwjSd0qUvMg6zSFGqFeiapmD3Z9OqQl5212VKenBovz61OJNnNQ5f4VNw17SD9zeFJN5aGZWTeLWPnH_9ec1hA8TDSbgq61RNr2oYbfNfAS9a99aL-b710hCCeeXI6cLxOtSGRorS2pYvQ3kGdbRxgcxq4hM70cjw2oJ60Iec-aFWiXZtmCEZyYn3RG0MNQXb3SzZg97vw-BMb5pRr4GNqguzg1BC_2Pzc_0yoQdM_YbnvNu4VWAJyFRhW1-OYbrAxxuVUxJak38lPlmChbaXWS3S1vqYJ-GVm9TMu0S1-0xHd7TiM3Mn_GgVd3gMK65s4JVUNovoKU"
const VALID_TOKEN_WITH_SCOPE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI2ZjQ1OGZkNWZmODY0NWY0YWMwNDNhNmU1YWViNGYxNSIsImV4dF9hdHRyIjp7ImVuaGFuY2VyIjoiWFNVQUEiLCJzdWJhY2NvdW50aWQiOiI0NmVmZmM0MC1lZjBjLTQ0OGQtYjZkZC0wMTlmNDBmYTBhZGUiLCJ6ZG4iOiJjZnRyYWluaW5nIn0sInhzLnN5c3RlbS5hdHRyaWJ1dGVzIjp7InhzLnJvbGVjb2xsZWN0aW9ucyI6WyJoYW5nbWFuLXVzZXJzIl19LCJnaXZlbl9uYW1lIjoiSm9obiIsInhzLnVzZXIuYXR0cmlidXRlcyI6e30sImZhbWlseV9uYW1lIjoiRG9lIiwic3ViIjoiMWQyODk5MDEtZGIxMC00YTk2LThjZmUtMWQ1MDg0YzNlYjc5Iiwic2NvcGUiOlsib3BlbmlkIiwiaGFuZ21hbi1zb2x1dGlvbiF0NTU5My5wbGF5SGFuZ21hbiIsInVhYS51c2VyIl0sImNsaWVudF9pZCI6InNiLWhhbmdtYW4tc29sdXRpb24hdDU1OTMiLCJjaWQiOiJzYi1oYW5nbWFuLXNvbHV0aW9uIXQ1NTkzIiwiYXpwIjoic2ItaGFuZ21hbi1zb2x1dGlvbiF0NTU5MyIsImdyYW50X3R5cGUiOiJhdXRob3JpemF0aW9uX2NvZGUiLCJ1c2VyX2lkIjoiMWQyODk5MDEtZGIxMC00YTk2LThjZmUtMWQ1MDg0YzNlYjc5Iiwib3JpZ2luIjoiYWNjb3VudHMuc2FwLmNvbSIsInVzZXJfbmFtZSI6IjEyMzQ1IiwiZW1haWwiOiJ0ZXN0QHNhcC5jb20iLCJhdXRoX3RpbWUiOjE2MDQ0ODEwOTMsInJldl9zaWciOiI4NGNiODQ0IiwiaWF0IjoxNjA0NDgxMDk0LCJleHAiOjUwMDAwMDAwMDAsImlzcyI6Imh0dHA6Ly9jZnRyYWluaW5nLmxvY2FsaG9zdDo4MDgwL3VhYS9vYXV0aC90b2tlbiIsInppZCI6IjQ2ZWZmYzQwLWVmMGMtNDQ4ZC1iNmRkLTAxOWY0MGZhMGFkZSIsImF1ZCI6WyJzYi1oYW5nbWFuLXNvbHV0aW9uIXQ1NTkzIiwidWFhIiwib3BlbmlkIiwiaGFuZ21hbi1zb2x1dGlvbiF0NTU5MyJdfQ.L4W2rhDLASoeQ9O6EvFXa-T6vOl79J7Zx9QFX-p3Z2rc8CDcNbeNwPcCEelqdv5U_ujd2kyDhgblL0vaeYLdwuPhYEXmIMNJ4R20TSfFSwj8IzvVoYCdsV7dKiU-BjXd6YLhVAjDOVZCS5Bc1WcNMec5JRBFiMnPDwbxdNE0E_nTZPZufooUO1IZZN4gg1jqDFj3ORsRdmAANvS-nXaJMlHuljj3X2QAYSPgpwm53CPKQFD2a745SOfoS7DO1IG_GoSgAcfWhHzTrpaftnfyZD5DaHn2AtxpA5YWJc7og76eFNlJWqyN554YTmzix8YW96KwvEErJpYz3okaOaiNVTxMn_C1q5f7-RUHAPqXsDAI9UK6vq51Q5eptlqlcytJBBMSX09FOL10XRtCKapPH4RKG3RBFs4OSW9HzcUGRRU2tNQ39usnmyQKv8gv1G0uzTHR2S-bDYSGgEUC5SktUwpB8MwCXw1j0exiUxO_MGRSTUFmLhZnRg4FWZGVAb554b7WdjKsnvlDGHH7tRZZpxv5yGt1d2F2OTig3bn1JaDxE0JL1GwI0B3YofCNO9JP_IY4MavDRhO34OaMP0gFB1mly-tUKRmiivJTbrGmyPIZKCP0bHECCWir0Y2l8NMcqn7kaMC0TxWaolbK1g8J1gnnyFYvAW3rfhtZPrh91u0"

// ´{
//  "jti": "c6831125-1ed6-41b0-8ea8-e60a341a2787",
//  "sub": "425130",
//  "scope": [
//    "openid",
//    "uaa.resource"
//  ],
//  "client_id": "sb-xssectest",
//  "cid": "sb-xssectest",
//  "azp": "sb-xssectest",
//  "grant_type": "password",
//  "user_id": "425130",
//  "user_name": "NODETESTUSER",
//  "email": "Nodetest@sap.com",
//  "origin": "testidp",
//  "given_name": "NodetestFirstName",
//  "family_name": "NodetestLastName",
//  "iat": 1470815434,
//  "exp": 2101535434,
//  "iss": "http://paas.localhost:8080/uaa/oauth/token",
//  "zid": "test-idz",
//  "hdb.nameduser.saml": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_71ee1776-9d2f-4973-aca8-9e22b2967ac8\" IssueInstant=\"2016-08-10T07:45:34.347Z\" Version=\"2.0\"><saml2:Issuer>TST-saml</saml2:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#_71ee1776-9d2f-4973-aca8-9e22b2967ac8\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>ou8r3R0WBHG1bp4KKOx1PyVOiYA=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>LbRKv1r/h7IMmiSyx10WkM7JuekrmwyVNsB53pkFRnrjCGWtmFkQsknsL7eTUN4+gcJGW0qGTUmvUkfXE1O8rf2CmTcC01cYsGAZWbNpOLNmpP9gG6572pveRqjTXLGSilM2ejJiylq2JnFLhXpgrnTbCvQW6a9JTpRpvMz8SiSodxax7rJw7C0yZzUq862M5yNjdoIHhEkngMcC5LDDhfpf6TkQMsyVcMamDqjTS7WTgvkQKl5pkOPKEuhTjCR7P7KAekeDmYoqs7yEZrrdKEixSY4i5F3weM+dw+A1ue9jF2KmeRvjoxs2hwfsWwUvCxy+2Jhr54vatmweG8dI0Q==</ds:SignatureValue></ds:Signature><saml2:Subject><saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">NODETESTUSER</saml2:NameID><saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml2:SubjectConfirmationData NotOnOrAfter=\"2016-08-10T11:50:34.347Z\"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore=\"2016-08-10T07:45:34.347Z\" NotOnOrAfter=\"2016-08-10T11:50:34.347Z\"/><saml2:AuthnStatement AuthnInstant=\"2016-08-10T07:50:34.347Z\" SessionNotOnOrAfter=\"2016-08-10T07:55:34.347Z\"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>",
//  "az_attr": {
//    "external_group": "domaingroup1",
//    "external_id": "abcd1234"
//  },
//  "ext_attr": {
//    "serviceinstanceid": "abcd1234",
//    "zdn": "paas"
//  },
//  "xs.system.attributes": {
//    "xs.saml.groups": [
//      "Canary_RoleBuilder"
//    ],
//    "xs.rolecollections": []
//  },
//  "xs.user.attributes": {
//    "country": [
//      "USA"
//    ]
//  },
//  "aud": [
//    "sb-xssectest",
//    "openid"
//  ]
//}

var TEST_XSUAA_CONFIG config.XsuaaConfig = config.XsuaaConfig{

	ClientId:  "sb-xssectest",
	XsAppName: "uaa",
	Url:       "https://lu356076.dhcp.wdf.sap.corp:30332/uaa-security",
	UaaDomain: "https://uaa.domain",
}

var TEST_XSUAA_CONFIG_FOR_SCOPE_TOKEN config.XsuaaConfig = config.XsuaaConfig{

	ClientId:  "sb-hangman-solution!t5593",
	XsAppName: "hangman-solution!t5593",
	Url:       "https://url.domain",
	UaaDomain: "https://uaa.domain",
}

func TestSecurityContextInMiddleware(t *testing.T) {

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.Context().Value("user").(*xssecgo.XssecContext)
		assert.Equal(t, val.FamilyName, "NodetestLastName")
	})

	key, _ := util.GetRSAKeyFromString(TEST_PUBLIC_KEY)
	// create the handler to test, using our custom "next" handler
	middleware, err := NewXssecMiddleware(TEST_XSUAA_CONFIG, Options{
		ValidationKeyGetter: jwt.KnownKeyfunc(jwt.SigningMethodRS256, key),
	})

	if err != nil {
		t.Error(err)
	}

	handlerToTest := middleware.Handler(nextHandler)

	// create a mock request to use
	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + VALID_TOKEN
	req := httptest.NewRequest("GET", "http://testing", nil)
	req.Header.Add("Authorization", bearer)
	// call the handler using a mock response recorder (we'll not use that anyway)
	w := httptest.NewRecorder()
	handlerToTest.ServeHTTP(w, req)

	resp := w.Result()
	assert.Equal(t, resp.StatusCode, 200)
}

func TestLocalScopesHandlerInMiddlewareShouldPass(t *testing.T) {

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.Context().Value("user").(*xssecgo.XssecContext)
		assert.Equal(t, "Doe", val.FamilyName)
	})

	key, _ := util.GetRSAKeyFromString(TEST_PUBLIC_KEY)
	// create the handler to test, using our custom "next" handler
	middleware, err := NewXssecMiddleware(TEST_XSUAA_CONFIG_FOR_SCOPE_TOKEN, Options{
		ValidationKeyGetter: jwt.KnownKeyfunc(jwt.SigningMethodRS256, key),
	})

	if err != nil {
		t.Error(err)
	}

	handlerToTest := middleware.Handler(helper.HasLocalScopesHandler(nextHandler, []string{"playHangman"}, ""))

	// create a mock request to use
	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + VALID_TOKEN_WITH_SCOPE
	req := httptest.NewRequest("GET", "http://testing", nil)
	req.Header.Add("Authorization", bearer)
	// call the handler using a mock response recorder (we'll not use that anyway)
	w := httptest.NewRecorder()
	handlerToTest.ServeHTTP(w, req)

	resp := w.Result()
	assert.Equal(t, resp.StatusCode, 200)
}

func TestLocalScopesHandlerInMiddlewareShouldFail(t *testing.T) {

	key, _ := util.GetRSAKeyFromString(TEST_PUBLIC_KEY)
	// create the handler to test, using our custom "next" handler
	middleware, err := NewXssecMiddleware(TEST_XSUAA_CONFIG_FOR_SCOPE_TOKEN, Options{
		ValidationKeyGetter: jwt.KnownKeyfunc(jwt.SigningMethodRS256, key),
	})

	if err != nil {
		t.Error(err)
	}

	handlerToTest := middleware.Handler(helper.HasLocalScopesHandler(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {}), []string{"anyScope"}, ""))

	// create a mock request to use
	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + VALID_TOKEN_WITH_SCOPE
	req := httptest.NewRequest("GET", "http://testing", nil)
	req.Header.Add("Authorization", bearer)
	// call the handler using a mock response recorder (we'll not use that anyway)
	w := httptest.NewRecorder()
	handlerToTest.ServeHTTP(w, req)

	resp := w.Result()
	assert.Equal(t, resp.StatusCode, 403)
}
