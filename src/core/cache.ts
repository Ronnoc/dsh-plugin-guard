/**
 * DSH Plugin Guard: Persistent Local Security Audit Cache
 * Content-addressed and multi-dimensional caching by:
 * 1. model (e.g. 'static', 'deepseek-chat', 'deepseek-reasoner')
 * 2. pluginGuardVersion (e.g. '0.1.0')
 * 3. plugin (spec or package name)
 * 4. tarballSha256 (plugin tarball content digest)
 *
 * Eliminates redundant tarball downloading, extraction, AST rule evaluation,
 * and high-cost LLM API token consumption for previously verified plugin versions.
 * @module dsh-plugin-guard/core/cache
 */

import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { GUARD_VERSION } from './constants.js'
import type {
  AuditCacheEntry,
  AuditCacheKey,
  AuditCacheStats,
  AuditReport,
} from './types.js'

/**
 * Computes a deterministic 64-char SHA-256 hash from the 4 composite dimensions:
 * model, pluginGuardVersion, plugin, and tarballSha256.
 */
export function computeAuditCacheKey(key: AuditCacheKey): string {
  const model = (key.model || 'static').trim().toLowerCase()
  const version = (key.pluginGuardVersion || GUARD_VERSION).trim()
  const plugin = (key.plugin || '').trim().toLowerCase()
  const sha256 = (key.tarballSha256 || '').trim().toLowerCase()

  const raw = `${model}:${version}:${plugin}:${sha256}`
  return createHash('sha256').update(raw).digest('hex')
}

export interface SpecIndexEntry {
  tarballSha256: string
  model: string
  pluginGuardVersion: string
  updatedAt: number
}

export interface AuditCacheManagerOptions {
  cacheDir?: string
  enabled?: boolean
  defaultModel?: string
}

export class AuditCacheManager {
  private cacheDir: string
  private auditsDir: string
  private specIndexPath: string
  private enabled: boolean
  private defaultModel: string

  constructor(options: AuditCacheManagerOptions = {}) {
    this.enabled = options.enabled ?? true
    this.defaultModel = options.defaultModel ?? 'static'

    const baseDir =
      options.cacheDir ||
      (process.env.DSH_CACHE_DIR
        ? join(process.env.DSH_CACHE_DIR, 'plugin-guard')
        : join(homedir(), '.dsh', 'cache', 'plugin-guard'))

    this.cacheDir = baseDir
    this.auditsDir = join(baseDir, 'audits')
    this.specIndexPath = join(baseDir, 'spec-index.json')
  }

  getCacheDir(): string {
    return this.cacheDir
  }

  isEnabled(): boolean {
    return this.enabled
  }

  private ensureDir(): void {
    if (!existsSync(this.auditsDir)) {
      mkdirSync(this.auditsDir, { recursive: true })
    }
  }

  private readSpecIndex(): Record<string, SpecIndexEntry> {
    try {
      if (existsSync(this.specIndexPath)) {
        const raw = readFileSync(this.specIndexPath, 'utf-8')
        return JSON.parse(raw) as Record<string, SpecIndexEntry>
      }
    } catch {
      // Degrade gracefully on read errors
    }
    return {}
  }

  private writeSpecIndex(index: Record<string, SpecIndexEntry>): void {
    try {
      this.ensureDir()
      writeFileSync(this.specIndexPath, JSON.stringify(index, null, 2), 'utf-8')
    } catch {
      // Best-effort write
    }
  }

  /**
   * Fast-path lookup by plugin spec (e.g. 'foo@1.0.0') before unpacking.
   */
  async findBySpec(
    spec: string,
    model: string = this.defaultModel,
    version: string = GUARD_VERSION,
  ): Promise<AuditReport | null> {
    if (!this.enabled) return null

    const index = this.readSpecIndex()
    const normSpec = spec.trim().toLowerCase()
    const record = index[normSpec]
    if (!record) return null

    // Ensure model and plugin-guard version match
    if (
      record.model.toLowerCase() !== model.toLowerCase() ||
      record.pluginGuardVersion !== version
    ) {
      return null
    }

    return this.get({
      plugin: spec,
      tarballSha256: record.tarballSha256,
      model,
      pluginGuardVersion: version,
    })
  }

  /**
   * Retrieves a cached report matching the exact 4 dimensions.
   */
  async get(key: AuditCacheKey): Promise<AuditReport | null> {
    if (!this.enabled) return null

    const cacheHash = computeAuditCacheKey(key)
    const filePath = join(this.auditsDir, `${cacheHash}.json`)

    if (!existsSync(filePath)) {
      return null
    }

    try {
      const raw = readFileSync(filePath, 'utf-8')
      const entry = JSON.parse(raw) as AuditCacheEntry

      // Strict validation of the 4 dimensions
      const normModel = (key.model || 'static').trim().toLowerCase()
      const normVersion = (key.pluginGuardVersion || GUARD_VERSION).trim()
      const normHash = (key.tarballSha256 || '').trim().toLowerCase()

      if (
        (entry.key.model || '').toLowerCase() !== normModel ||
        entry.key.pluginGuardVersion !== normVersion ||
        (entry.key.tarballSha256 || '').toLowerCase() !== normHash
      ) {
        return null
      }

      // Update hit counter and access time
      entry.metadata.hitCount = (entry.metadata.hitCount ?? 0) + 1
      entry.metadata.accessedAt = Date.now()

      try {
        writeFileSync(filePath, JSON.stringify(entry, null, 2), 'utf-8')
      } catch {
        // Non-blocking
      }

      // Return a report copy flagged as cached
      const reportCopy: AuditReport = {
        ...entry.report,
        cached: true,
        cacheKey: cacheHash,
        model: normModel,
        pluginGuardVersion: normVersion,
      }

      return reportCopy
    } catch {
      return null
    }
  }

  /**
   * Persists an audit report into local disk cache.
   */
  async set(
    key: AuditCacheKey,
    report: AuditReport,
    scanDurationMs?: number,
  ): Promise<string> {
    if (!this.enabled) return ''

    const cacheHash = computeAuditCacheKey(key)
    this.ensureDir()

    const filePath = join(this.auditsDir, `${cacheHash}.json`)
    const tempPath = join(this.auditsDir, `${cacheHash}.${Date.now()}.tmp`)

    const normModel = (key.model || 'static').trim().toLowerCase()
    const normVersion = (key.pluginGuardVersion || GUARD_VERSION).trim()

    const entry: AuditCacheEntry = {
      key: {
        model: normModel,
        pluginGuardVersion: normVersion,
        plugin: key.plugin.trim(),
        tarballSha256: key.tarballSha256.trim().toLowerCase(),
      },
      report: {
        ...report,
        model: normModel,
        pluginGuardVersion: normVersion,
        cacheKey: cacheHash,
      },
      metadata: {
        createdAt: Date.now(),
        accessedAt: Date.now(),
        hitCount: 0,
        scanDurationMs,
        cachedBy: `dsh-plugin-guard@${normVersion}`,
      },
    }

    try {
      const content = JSON.stringify(entry, null, 2)
      writeFileSync(tempPath, content, 'utf-8')
      try {
        if (existsSync(filePath)) {
          unlinkSync(filePath)
        }
      } catch {
        // ignore
      }
      writeFileSync(filePath, content, 'utf-8')
      try {
        unlinkSync(tempPath)
      } catch {
        // ignore
      }

      // Also update fast-lookup spec index
      const index = this.readSpecIndex()
      const normSpec = key.plugin.trim().toLowerCase()
      index[normSpec] = {
        tarballSha256: key.tarballSha256.trim().toLowerCase(),
        model: normModel,
        pluginGuardVersion: normVersion,
        updatedAt: Date.now(),
      }
      this.writeSpecIndex(index)

      return cacheHash
    } catch (err) {
      console.warn('[dsh-plugin-guard] Failed to write persistent audit cache:', err)
      return ''
    }
  }

  /**
   * Checks whether a cache entry exists.
   */
  async has(key: AuditCacheKey): Promise<boolean> {
    if (!this.enabled) return false
    const cacheHash = computeAuditCacheKey(key)
    return existsSync(join(this.auditsDir, `${cacheHash}.json`))
  }

  /**
   * Deletes a specific cache entry.
   */
  async delete(key: AuditCacheKey): Promise<boolean> {
    const cacheHash = computeAuditCacheKey(key)
    return this.deleteByHash(cacheHash)
  }

  /**
   * Deletes a specific cache entry by its cache hash.
   */
  async deleteByHash(hash: string): Promise<boolean> {
    const safeHash = hash.replace(/[^a-f0-9]/gi, '').toLowerCase()
    if (!safeHash) return false
    const filePath = join(this.auditsDir, `${safeHash}.json`)
    if (existsSync(filePath)) {
      try {
        unlinkSync(filePath)
        return true
      } catch {
        return false
      }
    }
    return false
  }

  /**
   * Clears all stored audit cache entries and the spec index.
   */
  async clear(): Promise<number> {
    let count = 0
    if (existsSync(this.auditsDir)) {
      try {
        const files = readdirSync(this.auditsDir)
        for (const file of files) {
          if (file.endsWith('.json')) {
            try {
              unlinkSync(join(this.auditsDir, file))
              count++
            } catch {
              // ignore
            }
          }
        }
      } catch {
        // ignore
      }
    }

    if (existsSync(this.specIndexPath)) {
      try {
        unlinkSync(this.specIndexPath)
      } catch {
        // ignore
      }
    }

    return count
  }

  /**
   * Lists all cached audit entries.
   */
  async list(): Promise<AuditCacheEntry[]> {
    if (!existsSync(this.auditsDir)) {
      return []
    }

    const entries: AuditCacheEntry[] = []
    try {
      const files = readdirSync(this.auditsDir)
      for (const file of files) {
        if (!file.endsWith('.json')) continue
        try {
          const raw = readFileSync(join(this.auditsDir, file), 'utf-8')
          const entry = JSON.parse(raw) as AuditCacheEntry
          const hashFromFilename = file.replace(/\.json$/, '')
          if (!entry.report.cacheKey) {
            entry.report.cacheKey = hashFromFilename
          }
          entries.push(entry)
        } catch {
          // ignore corrupted files
        }
      }
    } catch {
      // ignore
    }

    // Sort by createdAt descending (most recent first)
    entries.sort((a, b) => (b.metadata?.createdAt ?? 0) - (a.metadata?.createdAt ?? 0))

    return entries
  }

  /**
   * Computes aggregate cache statistics.
   */
  async getStats(): Promise<AuditCacheStats> {
    const entries = await this.list()
    let totalHits = 0
    for (const e of entries) {
      totalHits += e.metadata?.hitCount ?? 0
    }

    return {
      totalEntries: entries.length,
      totalHits,
      cacheDir: this.cacheDir,
    }
  }
}
