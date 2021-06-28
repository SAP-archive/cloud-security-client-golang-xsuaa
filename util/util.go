package util

import (
	"crypto/x509"
	"encoding/pem"
)

func MapToStringSlice(stringMap map[string]bool) []string {

	var stringSlice []string

	for k := range stringMap {
		stringSlice = append(stringSlice, k)
	}

	return stringSlice
}

func StringSliceToStringMap(stringSlice []string) map[string]bool {

	var stringMap = map[string]bool{}
	for _, v := range stringSlice {
		stringMap[v] = true
	}

	return stringMap

}

func GetRSAKeyFromString(key string) (interface{}, error) {

	decode, _ := pem.Decode([]byte(key))
	return x509.ParsePKIXPublicKey(decode.Bytes)

}
