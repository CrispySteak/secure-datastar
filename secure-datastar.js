/**
 * Secure Datastar Extension
 * Provides nonce-based security for Datastar dynamic code execution
 * Based on htmx secure-eval pattern
 */
(function() {
  'use strict';
  
  let evalCounter = 0;
  let currentServerNonce = null;
  
  // Get page load nonce - only from secure sources
  function getPageLoadNonce() {
    // Only trust meta tag or manually set nonce, never script nonce attributes
    return document.querySelector('meta[name="csp-nonce"]')?.getAttribute('content') ||
           window.datastartNonce ||
           null;
  }
  
  // Test if a nonce is valid by attempting to create a script with it
  function validateNonce(nonce) {
    if (!nonce) return false;
    
    try {
      const testScript = document.createElement('script');
      testScript.nonce = nonce;
      testScript.textContent = 'window.datastartNonceTest = true;';
      
      document.head.appendChild(testScript);
      const isValid = window.datastartNonceTest === true;
      
      delete window.datastartNonceTest;
      document.head.removeChild(testScript);
      
      return isValid;
    } catch (e) {
      return false;
    }
  }
  
  // Server nonce management
  function setServerNonce(nonce) {
    currentServerNonce = nonce;
  }
  
  function getServerNonce() {
    return currentServerNonce;
  }
  
  // Execute code with page nonce for CSP compliance
  function executeWithPageNonce(code, args = [], values = []) {
    const pageNonce = getPageLoadNonce();
    if (!pageNonce) {
      throw new Error('No page nonce available for secure execution');
    }
    
    // Validate nonce is actually working
    if (!validateNonce(pageNonce)) {
      throw new Error('Invalid or spoofed page nonce detected');
    }
    
    const script = document.createElement('script');
    script.nonce = pageNonce;
    const funcVar = 'datastar_eval_func_' + (++evalCounter);
    
    // Fix: Handle both expression and statement code
    let wrappedCode;
    if (code.trim().startsWith('return ')) {
      // Already a return statement
      wrappedCode = `window.${funcVar} = function(${args.join(',')}) { ${code} }`;
    } else {
      // Wrap as return expression
      wrappedCode = `window.${funcVar} = function(${args.join(',')}) { return (${code}); }`;
    }
    
    script.textContent = wrappedCode;
    document.head.appendChild(script);
    
    try {
      if (typeof window[funcVar] !== 'function') {
        throw new Error(`Failed to create function: ${funcVar}`);
      }
      const result = window[funcVar](...values);
      return result;
    } finally {
      delete window[funcVar];
      document.head.removeChild(script);
    }
  }
  
  // Override Function constructor to intercept Datastar usage
  const originalFunction = window.Function;
  window.Function = function(...args) {
    const code = args[args.length - 1];
    const params = args.slice(0, -1);
    
    if (code && typeof code === 'string') {
      // Detect Datastar code patterns
      const isDatastarCode = 
        code.includes('$[') ||                                    // Signal references
        code.includes('return (') ||                              // jsStrToObject pattern
        (params.includes('el') && params.includes('$')) ||        // Expression pattern
        code.includes('ctx.el') ||                                // Runtime context
        code.includes('root');                                    // Root signal access
      
      if (isDatastarCode) {
        const pageNonce = getPageLoadNonce();
        const serverNonce = getServerNonce();
        
        let hasValidNonce = false;
        let cleanCode = code;
        
        // Check for server nonce first, then page nonce
        if (serverNonce) {
          const serverNonceComment = `/*nonce:${serverNonce}*/`;
          if (code.includes(serverNonceComment)) {
            cleanCode = code.replaceAll(serverNonceComment, '');
            hasValidNonce = true;
          }
        }
        
        if (!hasValidNonce && pageNonce) {
          const pageNonceComment = `/*nonce:${pageNonce}*/`;
          if (code.includes(pageNonceComment)) {
            cleanCode = code.replaceAll(pageNonceComment, '');
            hasValidNonce = true;
          }
        }
        
        if (!hasValidNonce) {
          throw new Error('Unsafe Datastar expression blocked - missing valid nonce');
        }
        
        return function(...values) {
          return executeWithPageNonce(cleanCode, params, values);
        };
      }
    }
    
    // Allow other Function constructor calls
    return originalFunction.apply(this, args);
  };
  
  // Copy static properties to maintain Function constructor behavior
  Object.setPrototypeOf(window.Function, originalFunction);
  Object.defineProperty(window.Function, 'prototype', {
    value: originalFunction.prototype,
    writable: false
  });
  
  // Intercept fetch requests to extract server nonces
  function interceptDatastarResponses() {
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
      const response = await originalFetch.apply(this, args);
      
      // Check if this is a Datastar request
      const isDatastarRequest = 
        args[1]?.headers?.['Datastar-Request'] ||
        response.headers.get('content-type')?.includes('text/event-stream') ||
        response.headers.get('content-type')?.includes('text/html');
      
      if (isDatastarRequest) {
        // Extract server nonce from various headers
        let serverNonce = response.headers.get('HX-Nonce') || 
                         response.headers.get('Datastar-Nonce');
        
        // Fallback: extract from CSP header
        if (!serverNonce) {
          const csp = response.headers.get('content-security-policy');
          if (csp) {
            const cspMatch = csp.match(/(?:default|script)-src[^;]*'nonce-([^']*)'/i);
            if (cspMatch) {
              serverNonce = cspMatch[1];
            }
          }
        }
        
        if (serverNonce) {
          setServerNonce(serverNonce);
        }
        
        // Transform response content
        if (response.headers.get('content-type')?.includes('text/event-stream')) {
          // Transform SSE chunks
          const transformStream = new TransformStream({
            transform(chunk, controller) {
              const text = new TextDecoder().decode(chunk);
              const transformed = transformResponseContent(text);
              controller.enqueue(new TextEncoder().encode(transformed));
            }
          });
          
          const transformedBody = response.body.pipeThrough(transformStream);
          Object.defineProperty(response, 'body', { value: transformedBody });
        } else {
          // Transform regular responses
          const originalText = response.text.bind(response);
          response.text = async function() {
            const text = await originalText();
            return transformResponseContent(text);
          };
        }
      }
      
      return response;
    };
  }
  
  // Transform response content to normalize nonces
  function transformResponseContent(text) {
    const pageNonce = getPageLoadNonce();
    const serverNonce = getServerNonce();
    
    if (pageNonce && serverNonce && serverNonce !== pageNonce) {
      // Replace server nonce with page nonce in expressions
      text = text.replaceAll(`/*nonce:${serverNonce}*/`, `/*nonce:${pageNonce}*/`);
      
      // Clean up any duplicate nonces
      const duplicatePattern = new RegExp(`/\\*nonce:${pageNonce.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\*/\\s*/\\*nonce:${pageNonce.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\*/`, 'g');
      text = text.replace(duplicatePattern, `/*nonce:${pageNonce}*/`);
    }
    
    // Handle script tag nonce replacement and removal
    if (serverNonce) {
      if (pageNonce) {
        // Replace server nonce with page nonce in script tags
        const scriptNonceRegex = new RegExp(`(<script[^>]*\s)nonce="${serverNonce.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"([^>]*>)`, 'gi');
        text = text.replace(scriptNonceRegex, `$1nonce="${pageNonce}"$2`);
      }
      
      // Remove script tags without correct server nonce
      const scriptRegex = new RegExp(`<script(\\s(?!nonce="${serverNonce.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}")[^>]*>|>).*?<\/script(\\s[^>]*>|>)`, 'gis');
      text = text.replace(scriptRegex, '');
    } else {
      // Remove all script tags if no server nonce
      text = text.replace(/<script(\s[^>]*>|>).*?<\/script(\s[^>]*>|>)/gis, '');
    }
    
    return text;
  }
  
  // Initialize fetch interception
  interceptDatastarResponses();
  
  // Expose API for manual control
  window.datastartSecure = {
    setServerNonce,
    getPageLoadNonce,
    getServerNonce,
    transformResponseContent,
    validateNonce
  };
  
  // Log initialization
  console.log('Secure Datastar initialized', {
    pageNonce: getPageLoadNonce() ? 'present' : 'missing',
    version: '1.0.0'
  });
  
})();