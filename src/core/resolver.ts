/**
 * DSH Plugin Guard: Marketplace ID & Package Spec Resolver
 * Resolves DSH Marketplace identifiers (e.g., community `amlyczz--dsh-agy-link`)
 * to valid npm package names, GitHub targets, or direct URLs.
 * @module dsh-plugin-vetter/core/resolver
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import type { ResolvedSpecInfo } from './types.js'

export type { ResolvedSpecInfo }

const pExecFile = promisify(execFile)

interface CatalogEntry {
  id?: string
  name?: string
  owner?: string
  npm?: string
  url?: string
  github?: string
  version?: string
}

let catalogCache: { entries: CatalogEntry[]; timestamp: number } | null = null
const CATALOG_CACHE_TTL_MS = 60_000 // 1 minute cache for catalog files

export function clearCatalogCache(): void {
  catalogCache = null
}

/**
 * Discovers and loads plugin catalog entries from local DSH / dsh-m cache directories.
 */
export function loadLocalMarketCatalogs(): CatalogEntry[] {
  const now = Date.now()
  if (catalogCache && now - catalogCache.timestamp < CATALOG_CACHE_TTL_MS) {
    return catalogCache.entries
  }

  const entries: CatalogEntry[] = []
  const baseDshHome = process.env.DSH_HOME || join(homedir(), '.dsh')

  const candidateDirs = [
    join(baseDshHome, 'dshm', 'cache', 'desktop', 'host', 'awesome'),
    join(baseDshHome, 'dshm', 'cache', 'host', 'awesome'),
    join(baseDshHome, 'dshm', 'cache', 'desktop', 'host'),
    join(baseDshHome, 'dshm', 'cache', 'host'),
    join(baseDshHome, 'profiles', 'desktop', 'node_modules', 'dsh-m'),
    join(baseDshHome, 'profiles', 'web', 'node_modules', 'dsh-m'),
  ]

  for (const dir of candidateDirs) {
    if (!existsSync(dir)) continue

    try {
      const stats = statSync(dir)
      if (stats.isDirectory()) {
        const files = readdirSync(dir)
        // Sort files to prioritize latest catalog-*.json or registry.json
        const jsonFiles = files
          .filter(f => f.endsWith('.json'))
          .sort((a, b) => b.localeCompare(a))

        for (const file of jsonFiles) {
          const filePath = join(dir, file)
          try {
            const content = readFileSync(filePath, 'utf-8')
            const parsed = JSON.parse(content)

            if (Array.isArray(parsed)) {
              for (const item of parsed) {
                if (item && typeof item === 'object') entries.push(item)
              }
            } else if (parsed && typeof parsed === 'object') {
              if (Array.isArray(parsed.plugins)) {
                for (const item of parsed.plugins) {
                  if (item && typeof item === 'object') entries.push(item)
                }
              } else if (parsed.id && (parsed.name || parsed.npm)) {
                entries.push(parsed)
              }
            }
          } catch {
            // Ignore malformed individual json files
          }
        }
      }
    } catch {
      // Ignore directory read errors
    }
  }

  catalogCache = { entries, timestamp: now }
  return entries
}

/**
 * Fast-checks if a given npm package exists on the npm registry via registry HTTP HEAD or npm view.
 */
async function checkNpmPackageExists(pkgName: string): Promise<boolean> {
  // 1. Try global fetch HEAD (lightweight and fast)
  if (typeof fetch === 'function') {
    try {
      const encoded = pkgName.startsWith('@')
        ? `@${encodeURIComponent(pkgName.slice(1))}`
        : encodeURIComponent(pkgName)
      const res = await fetch(`https://registry.npmjs.org/${encoded}`, {
        method: 'HEAD',
        signal: AbortSignal.timeout(3000),
      })
      if (res.status === 200) return true
      if (res.status === 404) return false
    } catch {
      // Network or timeout, fallback to npm view
    }
  }

  // 2. Fallback to npm view
  try {
    const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm'
    await pExecFile(npmCmd, ['view', pkgName, 'name', '--json'], {
      windowsHide: true,
      shell: process.platform === 'win32',
      timeout: 5000,
    })
    return true
  } catch {
    return false
  }
}

/**
 * Resolves an install spec (which may be a marketplace ID like 'amlyczz--dsh-agy-link')
 * into a definitive, installable npm / git spec.
 */
export async function resolveInstallSpec(rawSpec: string): Promise<ResolvedSpecInfo> {
  const trimmed = rawSpec.trim()

  // 1. Fast path for URLs and git specs
  if (/^(?:https?|git|git\+https?|file):/i.test(trimmed)) {
    return {
      originalSpec: trimmed,
      resolvedSpec: trimmed,
      packageName: trimmed.split('/').pop()?.replace(/\.git$/, '') || trimmed,
      source: 'url',
      isMarketId: false,
    }
  }

  if (trimmed.startsWith('github:')) {
    const withoutPrefix = trimmed.slice(7)
    const [repoPart, tagPart] = withoutPrefix.split('#')
    const pkg = repoPart.split('/')[1] || repoPart
    return {
      originalSpec: trimmed,
      resolvedSpec: trimmed,
      packageName: pkg,
      version: tagPart?.replace(/^v/, ''),
      source: 'github',
      isMarketId: false,
    }
  }

  // 2. Parse base name and version from spec
  let baseName = trimmed
  let version: string | undefined

  // Match package@version (taking scoped packages @scope/pkg@1.0.0 into account)
  const lastAt = trimmed.lastIndexOf('@')
  if (lastAt > 0) {
    baseName = trimmed.slice(0, lastAt)
    version = trimmed.slice(lastAt + 1).trim()
  }

  // If baseName does NOT contain '--' and doesn't look like an owner--name market ID:
  // Usually this is a direct npm package (e.g. 'dsh-claude-style', '@deepseek-ai/dsh-web-app')
  const isMarketCandidate = baseName.includes('--')

  // 3. Look up in local DSH Marketplace catalogs
  const catalogs = loadLocalMarketCatalogs()
  const lowerBase = baseName.toLowerCase()

  for (const entry of catalogs) {
    const entryId = (entry.id || '').toLowerCase()
    const entryName = (entry.name || '').toLowerCase()
    const entryOwner = (entry.owner || '').toLowerCase()
    const entryNpm = (entry.npm || '').toLowerCase()
    const synthId = entryOwner && entryName ? `${entryOwner}--${entryName}` : ''

    const isMatch =
      (entryId && entryId === lowerBase) ||
      (synthId && synthId === lowerBase) ||
      (entryName && entryName === lowerBase) ||
      (entryNpm && entryNpm === lowerBase)

    if (isMatch) {
      if (entry.npm) {
        const targetVersion = version || entry.version
        return {
          originalSpec: trimmed,
          resolvedSpec: targetVersion ? `${entry.npm}@${targetVersion}` : entry.npm,
          packageName: entry.npm,
          version: targetVersion,
          source: 'npm',
          isMarketId: isMarketCandidate || entryId === lowerBase,
        }
      }

      if (entry.github) {
        const targetVersion = version || entry.version
        const repo = entry.github.replace(/^github\.com\//, '')
        const pkg = entry.name || repo.split('/')[1] || repo
        return {
          originalSpec: trimmed,
          resolvedSpec: targetVersion ? `github:${repo}#v${targetVersion}` : `github:${repo}`,
          packageName: pkg,
          version: targetVersion,
          source: 'github',
          isMarketId: true,
        }
      }

      if (entry.url && entry.url.includes('github.com/')) {
        const repo = entry.url.replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '')
        const pkg = entry.name || repo.split('/')[1] || repo
        const targetVersion = version || entry.version
        return {
          originalSpec: trimmed,
          resolvedSpec: targetVersion ? `github:${repo}#v${targetVersion}` : `github:${repo}`,
          packageName: pkg,
          version: targetVersion,
          source: 'github',
          isMarketId: true,
        }
      }
    }
  }

  // 4. Synthesized ID heuristic: owner--name (standard dsh-m community adapter convention)
  const synthMatch = /^([a-zA-Z0-9_-]+)--([a-zA-Z0-9_.-]+)$/.exec(baseName)
  if (synthMatch) {
    const owner = synthMatch[1]
    const name = synthMatch[2]

    // Candidate 1: name directly published on npm (e.g. 'dsh-agy-link')
    const cand1Exists = await checkNpmPackageExists(name)
    if (cand1Exists) {
      return {
        originalSpec: trimmed,
        resolvedSpec: version ? `${name}@${version}` : name,
        packageName: name,
        version,
        source: 'npm',
        isMarketId: true,
      }
    }

    // Candidate 2: scoped npm package @owner/name
    const scopedName = `@${owner}/${name}`
    const cand2Exists = await checkNpmPackageExists(scopedName)
    if (cand2Exists) {
      return {
        originalSpec: trimmed,
        resolvedSpec: version ? `${scopedName}@${version}` : scopedName,
        packageName: scopedName,
        version,
        source: 'npm',
        isMarketId: true,
      }
    }

    // Candidate 3: GitHub repository github:owner/name
    return {
      originalSpec: trimmed,
      resolvedSpec: version ? `github:${owner}/${name}#v${version}` : `github:${owner}/${name}`,
      packageName: name,
      version,
      source: 'github',
      isMarketId: true,
    }
  }

  // 5. Default fallback: treat as standard npm spec
  return {
    originalSpec: trimmed,
    resolvedSpec: trimmed,
    packageName: baseName,
    version,
    source: 'npm',
    isMarketId: false,
  }
}
