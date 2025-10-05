let globalEvalCounter = 0

export function secureEval(code: string, paramNames: string[] = [], paramValues: any[] = []): any {
  const script = document.createElement('script')
  
  const funcVar = 'datastar_eval_' + (++globalEvalCounter)
  
  if (paramNames.length > 0) {
    // Create function with parameters
    script.textContent = `window.${funcVar} = function(${paramNames.join(',')}) { ${code} }`
  } else {
    // Create simple evaluation function
    script.textContent = `window.${funcVar} = function() { return (${code}); }`
  }
  
  try {
    document.head.appendChild(script)
    
    const fn = (window as any)[funcVar]
    if (typeof fn !== 'function') {
      throw new Error(`Failed to create function: ${funcVar}`)
    }
    
    return fn(...paramValues)
  } catch (error) {
    console.warn('Secure eval failed (likely CSP violation):', {
      code,
      error: error instanceof Error ? error.message : String(error)
    })
    // Return undefined instead of crashing
    return undefined
  } finally {
    try {
      delete (window as any)[funcVar]
      if (script.parentNode) {
        document.head.removeChild(script)
      }
    } catch (cleanupError) {
      // Ignore cleanup errors
    }
  }
}