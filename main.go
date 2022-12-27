// Sample run-helloworld is a minimal Cloud Run service.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

var (
	bypassToken    = os.Getenv("BYPASS_TOKEN")
	protectorToken = os.Getenv("PROTECTOR_TOKEN")
	projectNumber  = os.Getenv("PROJECT_NUMBER")
	port           = os.Getenv("PORT")
	backend        = os.Getenv("BACKEND")
)

var (
	jwksURL  = "https://firebaseappcheck.googleapis.com/v1beta/jwks"
	jwksFunc *keyfunc.JWKS
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if projectNumber != "" {
		options := keyfunc.Options{
			Ctx: context.Background(),
			RefreshErrorHandler: func(err error) {
				log.Printf("there was an error with the jwt.Keyfunc\nError: %s", err.Error())
			},
			RefreshInterval: time.Hour * 6,
		}

		jwks, err := keyfunc.Get(jwksURL, options)
		if err != nil {
			log.Fatalf("failed to create JWKS from resource at the given URL. " + err.Error())
		}
		jwksFunc = jwks
	}
}

// NewProxy takes target host and creates a reverse proxy
func NewProxy(targetHost string) (*httputil.ReverseProxy, error) {
	url, err := url.Parse(targetHost)
	if err != nil {
		return nil, err
	}
	// overwrite the host header
	host := url.Hostname()

	proxy := httputil.NewSingleHostReverseProxy(url)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		modifyRequest(req, host)
	}
	proxy.ModifyResponse = modifyResponse

	proxy.ErrorHandler = errorHandler()
	return proxy, nil
}

func modifyResponse(resp *http.Response) error {
	if resp.Request.Method == "GET" {
		if resp.StatusCode < 400 {
			// on success, cache the response for 10 s
			resp.Header.Set("Vary", "X-Firebase-AppCheck, Authorization")
			resp.Header.Set("Cache-Control", "public, max-age=10, s-maxage=30")
		} else if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			// on 4xx, cache the response for ~ 1hr
			resp.Header.Set("Vary", "X-Firebase-AppCheck, Authorization")
			resp.Header.Set("Cache-Control", "public, max-age=3000, s-maxage=30")
		} else if resp.StatusCode >= 500 {
			// on 5xx, cache the response for 10s
			resp.Header.Set("Vary", "X-Firebase-AppCheck, Authorization")
			resp.Header.Set("Cache-Control", "public, max-age=10, s-maxage=30")
		}
		// other methods
	} else {
		if resp.StatusCode >= 400 {
			// on error, cache the response for 10s
			resp.Header.Set("Vary", "X-Firebase-AppCheck, Authorization")
			resp.Header.Set("Cache-Control", "public, max-age=10, s-maxage=30")
		} else {
			resp.Header.Set("Cache-Control", "no-cache")
		}
	}

	return nil
}

func modifyRequest(req *http.Request, host string) {
	req.Header.Set("X-Proxy", "protector")
	req.Header.Set("x-protector-token", protectorToken)
	req.Host = host
}

func errorHandler() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		http.Error(w, err.Error(), 500)
	}
}

// ProxyRequestHandler handles the http request using proxy
func ProxyRequestHandler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			recover()
		}()

		// allow cors requests
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		// check if the request is authorized
		if bypassToken != "" {
			reqBypassToken := r.Header.Get("X-Protector-Bypass")
			if reqBypassToken == bypassToken {
				proxy.ServeHTTP(w, r)
				return
			}
		}

		// check firebase appcheck header
		if projectNumber != "" {
			appCheckToken := r.Header.Get("X-Firebase-AppCheck")
			if appCheckToken == "" {
				http.Error(w, "Unauthorized", http.StatusForbidden)
				return
			} else if _, err := verifyToken(appCheckToken); err != nil {
				http.Error(w, "Unauthorized", http.StatusForbidden)
				return
			}
		}

		proxy.ServeHTTP(w, r)
	}
}

func verifyAudClaim(auds []interface{}) bool {
	for _, aud := range auds {
		if aud == "projects/"+projectNumber {
			return true
		}
	}
	return false
}

func verifyToken(token string) (string, error) {
	// Verify the signature on the App Check token
	// Ensure the token is not expired
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

func main() {
	// initialize a reverse proxy and pass the actual backend server url here
	proxy, err := NewProxy(backend)
	if err != nil {
		panic(err)
	}

	// handle all requests to your server using the proxy
	http.HandleFunc("/", ProxyRequestHandler(proxy))
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
