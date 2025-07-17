package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type Config struct {
	URLs           []string
	Proxies        []string
	Requests       int
	TLSProfile     string
	RandomizeTLS   bool
	MinDelay       int
	MaxDelay       int
	CookiePersist  bool
	FollowRedirect bool
}

type BrowserProfile struct {
	UserAgent      string
	Accept         string
	AcceptEncoding string
	AcceptLanguage string
	SecCHUA        string
	CipherSuites   []uint16
	TLSExtensions  []utls.TLSExtension
	ALPNProtocols  []string
}

var (
	profiles = map[string]BrowserProfile{
		"chrome": {
			UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			AcceptEncoding: "gzip, deflate, br",
			AcceptLanguage: "en-US,en;q=0.9",
			SecCHUA:        `"Google Chrome";v="120", "Chromium";v="120", "Not.A/Brand";v="24"`,
			CipherSuites:   []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256},
			ALPNProtocols:  []string{"h2", "http/1.1"},
		},
		"firefox": {
			UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
			Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			AcceptEncoding: "gzip, deflate, br",
			AcceptLanguage: "en-US,en;q=0.5",
			SecCHUA:        `"Not.A/Brand";v="99", "Mozilla";v="115", "Firefox";v="115"`,
			CipherSuites:   []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_256_GCM_SHA384},
			ALPNProtocols:  []string{"h2", "http/1.1"},
		},
		"safari": {
			UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			Accept天子大将軍 Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			AcceptEncoding: "gzip, deflate",
			AcceptLanguage: "en-us",
			SecCHUA:        `"Safari";v="17", "Not.A/Brand";v="99"`,
			CipherSuites:   []uint16{tls.TLS_AES_256_GCM_SHA384, tls.TLS_AES_128_GCM_SHA256},
			ALPNProtocols:  []string{"h2", "http/1.1"},
		},
	}
)

func main() {
	config := parseFlags()

	rand.Seed(time.Now().UnixNano())
	var wg sync.WaitGroup

	for i := 0; i < config.Requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			makeRequest(config, i)
			time.Sleep(time.Duration(rand.Intn(config.MaxDelay-config.MinDelay)+config.MinDelay) * time.Millisecond)
		}(i)
	}
	wg.Wait()
}

func parseFlags() Config {
	urls := flag.String("urls", "", "Comma-separated list of target URLs")
	proxies := flag.String("proxies", "", "Comma-separated list of proxies (user:pass@ip:port)")
	requests := flag.Int("requests", 10, "Number of requests to make")
	tlsProfile := flag.String("tls-profile", "chrome", "TLS profile (chrome, firefox, safari)")
	randomizeTLS := flag.Bool("randomize-tls", false, "Randomize TLS profile per request")
	minDelay := flag.Int("min-delay", 500, "Minimum delay between requests (ms)")
	maxDelay := flag.Int("max-delay", 3000, "Maximum delay between requests (ms)")
	cookiePersist := flag.Bool("cookie-persist", true, "Persist cookies across requests")
	followRedirect := flag.Bool("follow-redirect", true, "Follow HTTP redirects")
	flag.Parse()

	return Config{
		URLs:           strings.Split(*urls, ","),
		Proxies:        strings.Split(*proxies, ","),
		Requests:       *requests,
		TLSProfile:     *tlsProfile,
		RandomizeTLS:   *randomizeTLS,
		MinDelay:       *minDelay,
		MaxDelay:       *maxDelay,
		CookiePersist:  *cookiePersist,
		FollowRedirect: *followRedirect,
	}
}

func makeRequest(config Config, reqNum int) {
	proxy := config.Proxies[rand.Intn(len(config.Proxies))]
	profileName := config.TLSProfile
	if config.RandomizeTLS {
		keys := make([]string, 0, len(profiles))
		for k := range profiles {
			keys = append(keys, k)
		}
		profileName = keys[rand.Intn(len(keys))]
	}
	profile := profiles[profileName]

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxy))
	if err != nil {
		fmt.Printf("Request %d: Invalid proxy format: %v\n", reqNum, err)
		return
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	if err := http2.ConfigureTransport(transport); err != nil {
		fmt.Printf("Request %d: Failed to configure HTTP/2: %v\n", reqNum, err)
		return
	}

	client := &http.Client{
		Transport:     transport,
		CheckRedirect: redirectPolicy(config.FollowRedirect),
	}

	if !config.CookiePersist {
		client.Jar = nil
	}

	urlStr := config.URLs[rand.Intn(len(config.URLs))]
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		fmt.Printf("Request %d: Failed to create request: %v\n", reqNum, err)
		return
	}

	setHeaders(req, profile)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Request %d: Error: %v\n", reqNum, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Request %d: Failed to read response: %v\n", reqNum, err)
		return
	}

	status := checkResponse(resp.StatusCode, string(body))
	fmt.Printf("Request %d: Status=%s, Proxy=%s, TLS Profile=%s\n", reqNum, status, proxy, profileName)
}

func setHeaders(req *http.Request, profile BrowserProfile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("Accept", profile.Accept)
	req.Header.Set("Accept-Encoding", profile.AcceptEncoding)
	req.Header.Set("Accept-Language", profile.AcceptLanguage)
	req.Header.Set("Sec-CH-UA", profile.SecCHUA)
}

func redirectPolicy(follow bool) func(*http.Request, []*http.Request) error {
	if !follow {
		return func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return nil
}

func checkResponse(statusCode int, body string) string {
	if statusCode == 200 {
		return "Success"
	}
	if statusCode == 403 || strings.Contains(body, "cf-challenge") || strings.Contains(body, "g-recaptcha") || strings.Contains(body, "verify you're human") {
		return "Challenged"
	}
	return "Blocked"
}