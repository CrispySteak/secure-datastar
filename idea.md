# Secure Datastar Extension

## Overview
Provides nonce-based security for Datastar dynamic code execution, based on htmx secure-eval pattern.

## Features Implemented

### Core Security
- **Function Constructor Override**: Intercepts all dynamic code creation via `new Function()`
- **Nonce Validation**: Tests nonces by creating actual script elements to verify CSP compliance
- **Two-tier Nonce System**: Page nonce (from meta tag) + Server nonce (from response headers)

### Response Processing
- **Fetch Interception**: Captures server nonces from response headers (`HX-Nonce`, `Datastar-Nonce`, CSP headers)
- **SSE Stream Processing**: Real-time nonce transformation using TransformStream for Server-Sent Events
- **Regular Response Processing**: Transforms HTML responses before Datastar processes them

### Content Transformation
- **Expression Nonce Replacement**: Converts `/*nonce:server123*/` to `/*nonce:page456*/`
- **Script Tag Processing**: 
  - Replaces server nonces with page nonces in `<script nonce="...">` attributes
  - Removes unauthorized script tags without correct server nonce
  - Removes all script tags if no server nonce available
- **Duplicate Cleanup**: Removes duplicate nonce comments

### Security Patterns Detected
- `$[signal]` - Signal references
- `return (expression)` - Expression patterns  
- `ctx.el` - Runtime context
- `root` - Root signal access
- Parameters containing `el` and `$`

## Usage

### Basic Setup
```html
<meta name="csp-nonce" content="abc123">
<script src="secure-datastar.js"></script>
<script src="datastar.js"></script>
```

### Server Integration
```javascript
// Server sends nonce in header
response.setHeader('Datastar-Nonce', serverNonce);

// Or in CSP header
response.setHeader('Content-Security-Policy', `script-src 'nonce-${serverNonce}'`);
```

### Expression Usage
```html
<!-- Server generates with server nonce -->
<div data-text="/*nonce:server123*/$title.toUpperCase()"></div>

<!-- Gets transformed to page nonce -->
<div data-text="/*nonce:page456*/$title.toUpperCase()"></div>
```

## API

```javascript
window.datastartSecure = {
  setServerNonce(nonce),
  getPageLoadNonce(),
  getServerNonce(), 
  transformResponseContent(text),
  validateNonce(nonce)
}
```

## Security Model
1. **Page Load**: Extract nonce from `<meta name="csp-nonce">` or `window.datastartNonce`
2. **Server Response**: Extract nonce from response headers
3. **Content Transform**: Replace server nonces with page nonces
4. **Expression Execution**: Only allow expressions with valid nonce comments
5. **Script Sanitization**: Remove unauthorized script tags from responses

## Comparison to htmx secure-eval
- ✅ Nonce-based expression validation
- ✅ Server nonce extraction from headers
- ✅ Response content transformation
- ✅ Script tag nonce replacement and removal
- ✅ SSE stream processing (htmx doesn't have this)
- ❌ DOM attribute validation (not implemented)
- ❌ XPath-based attribute detection (not implemented)
- ❌ Cross-origin protection (not implemented)
- ❌ Ignore mechanism (not implemented)