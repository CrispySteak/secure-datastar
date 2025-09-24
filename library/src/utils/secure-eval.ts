let globalEvalCounter = 0

export function secureEval(code: string, paramNames: string[] = [], paramValues: any[] = []): any {
  // Extract nonce from code
  const nonceMatch = code.match(/\/\*nonce:([^*]+)\*\//)
  const nonce = nonceMatch?.[1]
  const cleanCode = nonce ? code.replace(/\/\*nonce:[^*]+\*\//, '') : code
  
  const script = document.createElement('script')
  if (nonce) script.nonce = nonce
  
  const funcVar = 'datastar_eval_' + (++globalEvalCounter)
  
  if (paramNames.length > 0) {
    // Create function with parameters
    script.textContent = `window.${funcVar} = function(${paramNames.join(',')}) { ${cleanCode} }`
  } else {
    // Create simple evaluation function
    script.textContent = `window.${funcVar} = function() { return (${cleanCode}); }`
  }
  
  document.head.appendChild(script)
  
  try {
    const fn = (window as any)[funcVar]
    if (typeof fn !== 'function') {
      throw new Error(`Failed to create function: ${funcVar}`)
    }
    
    return fn(...paramValues)
  } finally {
    delete (window as any)[funcVar]
    document.head.removeChild(script)
  }
}