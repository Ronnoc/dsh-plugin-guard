import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  AuditCacheManager,
  computeAuditCacheKey,
} from '../src/core/cache.js'
import type { AuditCacheKey, AuditReport } from '../src/core/types.js'

describe('AuditCacheManager', () => {
  let testCacheDir: string
  let cacheManager: AuditCacheManager

  const mockReport: AuditReport = {
    spec: 'test-plugin@1.2.3',
    packageName: 'test-plugin',
    version: '1.2.3',
    tarballSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    verdict: 'SAFE',
    score: 100,
    findings: [],
    permissions: {
      network: [],
      filesystem: [],
      subprocesses: false,
      mcpTools: [],
    },
    stagedAt: Date.now(),
  }

  beforeEach(() => {
    testCacheDir = join(
      tmpdir(),
      'dsh-guard-cache-test',
      `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    )
    mkdirSync(testCacheDir, { recursive: true })
    cacheManager = new AuditCacheManager({
      cacheDir: testCacheDir,
      enabled: true,
      defaultModel: 'static',
    })
  })

  afterEach(() => {
    try {
      rmSync(testCacheDir, { recursive: true, force: true })
    } catch {
      // Best effort
    }
  })

  it('computes deterministic and unique SHA-256 cache keys across all 4 dimensions', () => {
    const baseKey: AuditCacheKey = {
      model: 'static',
      pluginGuardVersion: '0.1.0',
      plugin: 'my-plugin',
      tarballSha256: 'aaaa1111bbbb2222',
    }

    const keyHash1 = computeAuditCacheKey(baseKey)
    const keyHash2 = computeAuditCacheKey({ ...baseKey })
    expect(keyHash1).toBe(keyHash2)
    expect(keyHash1.length).toBe(64)

    // 1. Changing model alters key
    const modelKeyHash = computeAuditCacheKey({ ...baseKey, model: 'deepseek-chat' })
    expect(modelKeyHash).not.toBe(keyHash1)

    // 2. Changing pluginGuardVersion alters key
    const versionKeyHash = computeAuditCacheKey({
      ...baseKey,
      pluginGuardVersion: '0.2.0',
    })
    expect(versionKeyHash).not.toBe(keyHash1)

    // 3. Changing plugin alters key
    const pluginKeyHash = computeAuditCacheKey({
      ...baseKey,
      plugin: 'other-plugin',
    })
    expect(pluginKeyHash).not.toBe(keyHash1)

    // 4. Changing tarballSha256 alters key
    const hashKeyHash = computeAuditCacheKey({
      ...baseKey,
      tarballSha256: 'cccc3333dddd4444',
    })
    expect(hashKeyHash).not.toBe(keyHash1)
  })

  it('persists and retrieves audit report with cache hit metadata', async () => {
    const key: AuditCacheKey = {
      model: 'static',
      pluginGuardVersion: '0.1.0',
      plugin: 'test-plugin@1.2.3',
      tarballSha256: mockReport.tarballSha256,
    }

    expect(await cacheManager.get(key)).toBeNull()

    const savedHash = await cacheManager.set(key, mockReport, 150)
    expect(savedHash.length).toBe(64)
    expect(await cacheManager.has(key)).toBe(true)

    const retrieved = await cacheManager.get(key)
    expect(retrieved).not.toBeNull()
    expect(retrieved?.cached).toBe(true)
    expect(retrieved?.cacheKey).toBe(savedHash)
    expect(retrieved?.packageName).toBe('test-plugin')
    expect(retrieved?.score).toBe(100)

    // Verify stats & hit counter
    const stats = await cacheManager.getStats()
    expect(stats.totalEntries).toBe(1)
    expect(stats.totalHits).toBe(1)
  })

  it('isolates cache entries when model differs', async () => {
    const staticKey: AuditCacheKey = {
      model: 'static',
      pluginGuardVersion: '0.1.0',
      plugin: 'test-plugin@1.2.3',
      tarballSha256: mockReport.tarballSha256,
    }

    await cacheManager.set(staticKey, mockReport)

    // Hit with static
    expect(await cacheManager.get(staticKey)).not.toBeNull()

    // Miss with deepseek-chat
    const aiKey: AuditCacheKey = {
      ...staticKey,
      model: 'deepseek-chat',
    }
    expect(await cacheManager.get(aiKey)).toBeNull()

    // Miss with deepseek-reasoner
    const r1Key: AuditCacheKey = {
      ...staticKey,
      model: 'deepseek-reasoner',
    }
    expect(await cacheManager.get(r1Key)).toBeNull()
  })

  it('invalidates cache when plugin-guard version upgrades', async () => {
    const v1Key: AuditCacheKey = {
      model: 'static',
      pluginGuardVersion: '0.1.0',
      plugin: 'test-plugin@1.2.3',
      tarballSha256: mockReport.tarballSha256,
    }

    await cacheManager.set(v1Key, mockReport)
    expect(await cacheManager.get(v1Key)).not.toBeNull()

    const v2Key: AuditCacheKey = {
      ...v1Key,
      pluginGuardVersion: '0.2.0',
    }
    expect(await cacheManager.get(v2Key)).toBeNull()
  })

  it('invalidates cache when tarball content hash changes', async () => {
    const key1: AuditCacheKey = {
      model: 'static',
      pluginGuardVersion: '0.1.0',
      plugin: 'test-plugin@1.2.3',
      tarballSha256: '1111111111111111',
    }

    await cacheManager.set(key1, mockReport)
    expect(await cacheManager.get(key1)).not.toBeNull()

    const tamperedKey: AuditCacheKey = {
      ...key1,
      tarballSha256: '2222222222222222',
    }
    expect(await cacheManager.get(tamperedKey)).toBeNull()
  })

  it('supports fast-path lookup by spec and model', async () => {
    const key: AuditCacheKey = {
      model: 'static',
      pluginGuardVersion: '0.1.0',
      plugin: 'test-plugin@1.2.3',
      tarballSha256: mockReport.tarballSha256,
    }

    await cacheManager.set(key, mockReport)

    // Fast-path lookup
    const found = await cacheManager.findBySpec('test-plugin@1.2.3', 'static', '0.1.0')
    expect(found).not.toBeNull()
    expect(found?.cached).toBe(true)

    // Fast-path with different model returns null
    const diffModel = await cacheManager.findBySpec(
      'test-plugin@1.2.3',
      'deepseek-chat',
      '0.1.0',
    )
    expect(diffModel).toBeNull()
  })

  it('clears all cached entries and deletes single entry properly', async () => {
    const key1: AuditCacheKey = {
      model: 'static',
      pluginGuardVersion: '0.1.0',
      plugin: 'pkg-a@1.0.0',
      tarballSha256: 'hash-a',
    }
    const key2: AuditCacheKey = {
      model: 'static',
      pluginGuardVersion: '0.1.0',
      plugin: 'pkg-b@1.0.0',
      tarballSha256: 'hash-b',
    }

    await cacheManager.set(key1, mockReport)
    await cacheManager.set(key2, mockReport)

    expect((await cacheManager.list()).length).toBe(2)

    const deleted = await cacheManager.delete(key1)
    expect(deleted).toBe(true)
    expect(await cacheManager.has(key1)).toBe(false)
    expect(await cacheManager.has(key2)).toBe(true)

    const clearedCount = await cacheManager.clear()
    expect(clearedCount).toBe(1)
    expect((await cacheManager.list()).length).toBe(0)
  })

  it('handles corrupted JSON files gracefully without crashing', async () => {
    const auditsDir = join(testCacheDir, 'audits')
    mkdirSync(auditsDir, { recursive: true })
    writeFileSync(join(auditsDir, 'bad-file.json'), 'not valid json {{{', 'utf-8')

    const list = await cacheManager.list()
    expect(Array.isArray(list)).toBe(true)
    expect(list.length).toBe(0)
  })
})
