# HTTPS Request Tool with TLS Fingerprint Spoofing

A Go-based CLI tool for making HTTPS requests with TLS fingerprint spoofing to bypass anti-bot protections (e.g., Cloudflare, Akamai). Features include proxy rotation, header mimicry, and challenge detection.

## Features
- TLS fingerprint spoofing (Chrome, Firefox, Safari)
- Proxy support with rotation (HTTP/SOCKS5)
- Configurable HTTPS requests
- Anti-bot evasion (header mimicry, cookie handling, redirects)
- Randomized delays for human-like behavior

## Installation
```bash
go get github.com/refraction-networking/utls
go build main.go