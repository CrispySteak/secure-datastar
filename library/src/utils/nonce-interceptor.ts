// Nonce interceptor for Datastar responses
let pageLoadNonce: string | null = null
let currentServerNonce: string | null = null

// Initialize page load nonce from secure sources
export function initPageLoadNonce(): void {
  pageLoadNonce = 
    document.querySelector('meta[name="csp-nonce"]')?.getAttribute('content') ||
    (window as any).datastartNonce ||
    null
}

// Extract and set server nonce from response headers
export function extractAndSetServerNonce(response: Response): string | null {
  const nonce = response.headers.get('HX-Nonce') ||
                response.headers.get('Datastar-Nonce') ||
                extractNonceFromCSP(response.headers.get('content-security-policy'))
  
  currentServerNonce = nonce
  return nonce
}

function extractNonceFromCSP(csp: string | null): string | null {
  if (!csp) return null
  const match = csp.match(/(?:default|script)-src[^;]*'nonce-([^']*)'/i)
  return match?.[1] || null
}

// Transform response content to use page load nonce
export function transformResponseContent(text: string, serverNonce?: string | null): string {
  if (!pageLoadNonce) return text
  
  const nonce = serverNonce || currentServerNonce
  if (!nonce || nonce === pageLoadNonce) return text
  
  // Replace server nonce with page nonce in expressions
  text = text.replaceAll(`/*nonce:${nonce}*/`, `/*nonce:${pageLoadNonce}*/`)
  
  // Replace server nonce with page nonce in script tags
  const scriptNonceRegex = new RegExp(
    `(<script[^>]*\\s)nonce="${nonce.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"([^>]*>)`, 
    'gi'
  )
  text = text.replace(scriptNonceRegex, `$1nonce="${pageLoadNonce}"$2`)
  
  return text
}



// Get current page load nonce
export function getPageLoadNonce(): string | null {
  return pageLoadNonce
}

// Initialize on module load
initPageLoadNonce()