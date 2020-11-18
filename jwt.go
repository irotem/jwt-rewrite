package jwt_middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"strings"
)

type Config struct {
	VerifySecret       string `json:"verify.secret,omitempty"`
	VerifyAuthHeader   string `json:"verify.authHeader,omitempty"`
	VerifyHeaderPrefix string `json:"verify.headerPrefix,omitempty"`
	VerifyHash         string `json:"verify.hash,omitempty"`
	SignSecret         string `json:"sign.secret,omitempty"`
	SignAuthHeader     string `json:"sign.authHeader,omitempty"`
	SignHeaderPrefix   string `json:"sign.headerPrefix,omitempty"`
	SignHash           string `json:"sign.hash,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type JWTHeader struct {
	secret       string
	authHeader   string
	headerPrefix string
	hash         string
}

type JWT struct {
	next   http.Handler
	name   string
	verify JWTHeader
	sign   JWTHeader
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	if len(config.VerifyHash) == 0 {
		config.VerifyHash = "HS256"
	}

	if len(config.SignHash) == 0 {
		config.SignHash = "HS256"
	}

	if len(config.VerifySecret) == 0 {
		config.VerifySecret = "00000000000000000000000000000000000000000000"
	}
	if len(config.VerifyAuthHeader) == 0 {
		config.VerifyAuthHeader = "Authorization"
	}
	if len(config.VerifyHeaderPrefix) == 0 {
		config.VerifyHeaderPrefix = "Bearer"
	}
	if len(config.SignSecret) == 0 {
		config.SignSecret = "11111111111111111111111111111111111111111111"
	}
	if len(config.SignAuthHeader) == 0 {
		config.SignAuthHeader = "Authorization"
	}
	if len(config.SignHeaderPrefix) == 0 {
		config.SignHeaderPrefix = "Bearer"
	}

	return &JWT{
		next: next,
		name: name,
		verify: JWTHeader{
			secret:       config.VerifySecret,
			authHeader:   config.VerifyAuthHeader,
			headerPrefix: config.VerifyHeaderPrefix,
			hash:         config.VerifyHash,
		},
		sign: JWTHeader{
			secret:       config.SignSecret,
			authHeader:   config.SignAuthHeader,
			headerPrefix: config.SignHeaderPrefix,
			hash:         config.SignHash,
		},
	}, nil
}

func (j *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	headerToken := req.Header.Get(j.verify.authHeader)

	if len(headerToken) == 0 {
		http.Error(res, "Request error", http.StatusBadRequest)
		return
	}

	token, preprocessError := preprocessJWT(headerToken, j.verify.headerPrefix)
	if preprocessError != nil {
		http.Error(res, "Request error", http.StatusBadRequest)
		return
	}

	verified, verificationError := verifyJWT(token, j.verify.secret, j.verify.hash)
	if verificationError != nil {
		http.Error(res, "Not allowed", http.StatusUnauthorized)
		return
	}

	if verified {
		// If true decode payload
		payload, decodeErr := decodeBase64(token.payload)
		if decodeErr != nil {
			http.Error(res, "Request error", http.StatusBadRequest)
			return
		}

		jwt := buildJWT(payload, j.sign)
		// Inject header as proxypayload or configured name
		req.Header.Del(j.sign.authHeader)
		req.Header.Add(j.verify.authHeader, j.verify.headerPrefix+" "+jwt)
		req.Header.Add("x-rewrite", "true")

		j.next.ServeHTTP(res, req)
	} else {
		http.Error(res, "Not allowed", http.StatusUnauthorized)
	}
}

// Token Deconstructed header token
type Token struct {
	header       string
	payload      string
	verification string
}

// verifyJWT Verifies jwt token with secret
func verifyJWT(token Token, secret string, jwtType string) (bool, error) {

	//mac := hmac.New(sha512.New, []byte(secret))
	var mac hash.Hash
	switch jwtType {
	case "HS512":
		mac = hmac.New(sha512.New, []byte(secret))
	case "HS256":
		mac = hmac.New(sha256.New, []byte(secret))
	default:
		return false, nil
	}

	message := token.header + "." + token.payload
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)

	decodedVerification, errDecode := base64.RawURLEncoding.DecodeString(token.verification)
	if errDecode != nil {
		fmt.Errorf("Could not decode verification")
	}

	if hmac.Equal(decodedVerification, expectedMAC) {
		return true, nil
	}
	return false, nil
	// TODO Add time check to jwt verification
}

// verifyJWT Verifies jwt token with secret
func buildJWT(payload string, sign JWTHeader) string {

	var mac hash.Hash
	switch sign.hash {
	case "HS512":
		mac = hmac.New(sha512.New, []byte(sign.secret))
	case "HS256":
		fallthrough
	default:
		mac = hmac.New(sha256.New, []byte(sign.secret))
	}

	header := "{\"alg\": \"" + sign.hash + "\",\"typ\": \"JWT\"\n}"
	message := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload))

	mac.Write([]byte(message))
	calculatedMAC := mac.Sum(nil)

	result := message + "." + base64.RawURLEncoding.EncodeToString(calculatedMAC)

	return result
	//decodedVerification, errDecode := base64.RawURLEncoding.DecodeString(token.verification)
	//if errDecode != nil {
	//	return false, errDecode
	//}

	//if hmac.Equal(decodedVerification, expectedMAC) {
	//	return true, nil
	//}
	//return false, nil

}

// preprocessJWT Takes the request header string, strips prefix and whitespaces and returns a Token
func preprocessJWT(reqHeader string, prefix string) (Token, error) {
	// fmt.Println("==> [processHeader] SplitAfter")
	// structuredHeader := strings.SplitAfter(reqHeader, "Bearer ")[1]
	cleanedString := strings.TrimPrefix(reqHeader, prefix)
	cleanedString = strings.TrimSpace(cleanedString)
	// fmt.Println("<== [processHeader] SplitAfter", cleanedString)

	var token Token

	tokenSplit := strings.Split(cleanedString, ".")

	if len(tokenSplit) != 3 {
		return token, fmt.Errorf("Invalid token")
	}

	token.header = tokenSplit[0]
	token.payload = tokenSplit[1]
	token.verification = tokenSplit[2]

	return token, nil
}

// decodeBase64 Decode base64 to string
func decodeBase64(baseString string) (string, error) {
	byte, decodeErr := base64.RawURLEncoding.DecodeString(baseString)
	if decodeErr != nil {
		return baseString, fmt.Errorf("Error decoding")
	}
	return string(byte), nil
}
