import type { Modifiers } from '../engine/types'
import { secureEval } from './secure-eval'

export const isBoolString = (str: string) => str.trim() === 'true'

export const kebab = (str: string) =>
  str
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .replace(/([a-z])([0-9]+)/gi, '$1-$2')
    .replace(/([0-9]+)([a-z])/gi, '$1-$2')
    .toLowerCase()

export const camel = (str: string) =>
  kebab(str).replace(/-./g, (x) => x[1].toUpperCase())

export const snake = (str: string) => kebab(str).replace(/-/g, '_')

export const pascal = (str: string) =>
  camel(str).replace(/(^.|(?<=\.).)/g, (x) => x[0].toUpperCase())

export const jsStrToObject = (raw: string) => {
  try {
    return JSON.parse(raw)
  } catch {
    // If JSON parsing fails, try to evaluate as a JavaScript object
    return secureEval(raw, [], [])
  }
}

const caseFns: Record<string, (s: string) => string> = { kebab, snake, pascal }

export function modifyCasing(str: string, mods: Modifiers) {
  for (const c of mods.get('case') || []) {
    const fn = caseFns[c]
    if (fn) str = fn(str)
  }
  return str
}
