let evalCounter = 0

// Core utility functions
function getPageLoadNonce() {
  return htmx.config.inlineScriptNonce
}

function executeWithPageNonce(code, paramName, param, thisArg) {
  const pageNonce = getPageLoadNonce()
  if (!pageNonce) {
    throw new Error('No page nonce available for secure execution')
  }

  const script = document.createElement('script')
  script.nonce = pageNonce

  const funcVar = 'htmx_eval_func_' + (++evalCounter)

  const wrappedCode = `window.${funcVar} = function(${paramName || ''}) { ${code} }`

  script.textContent = wrappedCode
  document.head.appendChild(script)

  const result = window[funcVar].call(thisArg, param)

  delete window[funcVar]
  document.head.removeChild(script)

  return result
}

function isEvalAttribute(attrName) {
  return attrName.startsWith('hx-on:') || attrName.startsWith('data-hx-on:') ||
         attrName.startsWith('hx-on-') || attrName.startsWith('data-hx-on-') ||
         ['hx-trigger', 'data-hx-trigger', 'hx-vars', 'data-hx-vars', 'hx-vals', 'data-hx-vals'].includes(attrName)
}

function validateElementAttributes(elt, pageNonce) {
  Array.from(elt.attributes || []).forEach(attr => {
    if (isEvalAttribute(attr.name)) {
      if (attr.value.includes('/*nonce:') && !attr.value.includes(`/*nonce:${pageNonce}*/`)) {
        elt.removeAttribute(attr.name)
      }
    }
  })
}

function validateScriptTags(rootElt) {
  Array.from(rootElt.querySelectorAll('script')).forEach(script => {
    if (script.nonce !== htmx.config.inlineScriptNonce) {
      script.remove()
    }
  })
}

function validatePageLoadNonces(rootElt) {
  const pageNonce = getPageLoadNonce()
  if (!pageNonce) return

  // Collect all nodes first to avoid DOM mutation issues
  const nodesToProcess = [rootElt]

  // Use XPath to find hx-on:* attributes and collect nodes
  const HX_ON_QUERY = new XPathEvaluator()
    .createExpression('.//*[@*[ starts-with(name(), "hx-on:") or starts-with(name(), "data-hx-on:") or' +
      ' starts-with(name(), "hx-on-") or starts-with(name(), "data-hx-on-") ]]')

  const iter = HX_ON_QUERY.evaluate(rootElt)
  let node = null
  while (node = iter.iterateNext()) {
    nodesToProcess.push(node)
  }

  // Also collect static eval selector nodes
  const evalSelectors = '[hx-trigger], [data-hx-trigger], [hx-vars], [data-hx-vars], [hx-vals], [data-hx-vals]'
  rootElt.querySelectorAll(evalSelectors).forEach(elt => {
    nodesToProcess.push(elt)
  })

  // Process all collected nodes
  nodesToProcess.forEach(elt => {
    validateElementAttributes(elt, pageNonce)
  })
}

htmx.defineExtension('secure-eval', {
  init: function(apiRef) {
    // Override Function constructor to intercept htmx usage
    const originalFunction = window.Function
    window.Function = function(...args) {
      const code = args[args.length - 1]
      const params = args.slice(0, -1)
      
      if (code && typeof code === 'string') {
        // Detect htmx code patterns
        const isHtmxCode = 
          code.includes('event') ||                                 // Event handlers
          code.includes('return (') ||                              // Expression evaluation
          (params.includes('event') && params.length === 1) ||     // Event handler pattern
          code.includes('window.') ||                               // Window references
          (params.length === 0 && code.includes('return')) ||      // Simple return expressions
          code.includes('this.') ||                                 // Context references
          (params.includes('el') && code.includes('.'))             // Element property access
        
        if (isHtmxCode) {
          const pageNonce = getPageLoadNonce()
          
          let hasValidNonce = false
          let cleanCode = code
          
          if (pageNonce) {
            const pageNonceComment = `/*nonce:${pageNonce}*/`
            if (code.includes(pageNonceComment)) {
              cleanCode = code.replaceAll(pageNonceComment, '')
              hasValidNonce = true
            }
          }
          
          if (!hasValidNonce) {
            throw new Error('Unsafe htmx expression blocked - missing valid nonce')
          }
          
          return function(...values) {
            return executeWithPageNonce(cleanCode, params.join(','), values[0], this)
          }
        }
      }
      
      // Allow other Function constructor calls
      return originalFunction.apply(this, args)
    }
    
    // Copy static properties to maintain Function constructor behavior
    Object.setPrototypeOf(window.Function, originalFunction)
    Object.defineProperty(window.Function, 'prototype', {
      value: originalFunction.prototype,
      writable: false
    })
  },

  transformResponse: function(text, xhr, elt) {
    htmx.config.refreshOnHistoryMiss = true

    let serverNonce = xhr.getResponseHeader('HX-Nonce')
    if (!serverNonce) {
      const csp = xhr.getResponseHeader('content-security-policy')
      if (csp) {
        const cspMatch = csp.match(/(default|script)-src[^;]*'nonce-([^']*)'/i)
        if (cspMatch) {
          serverNonce = cspMatch[2]
        }
      }
    }

    if (window.location.hostname) {
      const responseURL = new URL(xhr.responseURL)
      if (responseURL.hostname !== window.location.hostname) {
        serverNonce = null
      }
    }

    if (serverNonce) {
      const pageNonce = getPageLoadNonce()
      if (pageNonce) {
        // Only replace server nonce with page nonce, reject any existing page nonce
        text = text.replaceAll(`/*nonce:${pageNonce}*/`, '')
        text = text.replaceAll(`/*nonce:${serverNonce}*/`, `/*nonce:${pageNonce}*/`)
      }

      const scriptRegex = new RegExp(`<script(\\s(?!nonce="${serverNonce.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}")[^>]*>|>).*?<\/script(\\s[^>]*>|>)`, 'gis')
      text = text.replace(scriptRegex, '')
    } else {
      text = text.replace(/<script(\s[^>]*>|>).*?<\/script(\s[^>]*>|>)/gis, '')
    }

    return text.replace(/ignore:secure-eval/g, '')
  },

  onEvent: function(name, evt) {
    if (name === 'htmx:beforeProcessNode') {
      validatePageLoadNonces(evt.detail.elt)
      validateScriptTags(evt.detail.elt)
      Array.from(evt.detail.elt.querySelectorAll('[hx-ext*="ignore:secure-eval"], [data-hx-ext*="ignore:secure-eval"]')).forEach(elt => {
        elt.remove()
      })
    }
    return true
  }
})
