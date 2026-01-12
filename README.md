# Replit Proxy

A simple HTTP proxy server with a clean frontend interface.

## Features
- ✓ Load any website through the proxy
- ✓ Block local/private IP addresses
- ✓ Remove iframe-blocking headers for testing
- ✓ Debug endpoint showing recent requests
- ✓ Clean, responsive UI

## Setup

1. Files are already in place
2. Run `npm install` (Replit does this automatically)
3. Click **Run** or execute `npm start`
4. Open the provided URL in your browser

## Usage

1. Enter a URL (e.g., `example.com`)
2. Click **Load** or press Enter
3. The website loads in the iframe below
4. Check `/debug/recent` for request history

## Endpoints

- `/` - Main interface
- `/proxy? url=<ENCODED_URL>` - Proxy endpoint
- `/debug/recent` - Recent proxied requests (JSON)

## Security Notes

- ⚠️ Educational use only
- Blocks access to localhost and private IP ranges
- No authentication - anyone with access can use it
- No rate limiting - prone to abuse
- Do not deploy publicly without proper protections