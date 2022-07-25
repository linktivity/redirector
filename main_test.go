package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

func TestToken(t *testing.T) {
	token := ""
	projectNumber = ""
	// Verify the signature on the App Check token
	// Ensure the token is not expired
	t.Log(verify(token))
}

func verify(token string) (string, error) {
	payload, err := jwt.Parse(token, jwksFunc.Keyfunc)
	if err != nil {
		return "", errors.New("failed to parse token. " + err.Error())
	}

	if !payload.Valid {
		return "", errors.New("invalid token")
	} else if payload.Header["alg"] != "RS256" {
		// Ensure the token's header uses the algorithm RS256
		return "", errors.New("invalid algorithm")
	} else if payload.Header["typ"] != "JWT" {
		// Ensure the token's header has type JWT
		return "", errors.New("invalid type")
	} else if !verifyAudClaim(payload.Claims.(jwt.MapClaims)["aud"].([]interface{})) {
		// Ensure the token's audience matches your project
		return "", errors.New("invalid audience")
	} else if !strings.Contains(payload.Claims.(jwt.MapClaims)["iss"].(string),
		"https://firebaseappcheck.googleapis.com/"+projectNumber) {
		// Ensure the token is issued by App Check
		return "", errors.New("invalid issuer")
	}

	return payload.Claims.(jwt.MapClaims)["sub"].(string), nil
}
