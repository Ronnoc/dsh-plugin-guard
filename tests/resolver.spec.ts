import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { resolveInstallSpec, loadLocalMarketCatalogs, clearCatalogCache } from '../src/core/resolver.js'
import { mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

describe('resolveInstallSpec', () => {
  let tempDshHome: string

  beforeEach(() => {
    clearCatalogCache()
    tempDshHome = join(tmpdir(), `dsh-resolver-test-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`)
    mkdirSync(join(tempDshHome, 'dshm', 'cache', 'host', 'awesome'), { recursive: true })
    process.env.DSH_HOME = tempDshHome
  })

  afterEach(() => {
    delete process.env.DSH_HOME
    clearCatalogCache()
    try {
      rmSync(tempDshHome, { recursive: true, force: true })
    } catch {}
  })

  it('keeps standard npm specs intact', async () => {
    const res = await resolveInstallSpec('dsh-ops@0.4.4')
    expect(res.packageName).toBe('dsh-ops')
    expect(res.version).toBe('0.4.4')
    expect(res.resolvedSpec).toBe('dsh-ops@0.4.4')
    expect(res.isMarketId).toBe(false)
  })

  it('keeps scoped npm specs intact', async () => {
    const res = await resolveInstallSpec('@deepseek-ai/dsh-web-app@1.2.0')
    expect(res.packageName).toBe('@deepseek-ai/dsh-web-app')
    expect(res.version).toBe('1.2.0')
    expect(res.resolvedSpec).toBe('@deepseek-ai/dsh-web-app@1.2.0')
    expect(res.isMarketId).toBe(false)
  })

  it('keeps github specs intact', async () => {
    const res = await resolveInstallSpec('github:amlyczz/dsh-agy-link#v0.4.96')
    expect(res.packageName).toBe('dsh-agy-link')
    expect(res.version).toBe('0.4.96')
    expect(res.source).toBe('github')
    expect(res.isMarketId).toBe(false)
  })

  it('resolves market ID amlyczz--dsh-agy-link to npm package from market catalog cache', async () => {
    // Seed mock market catalog in DSH_HOME
    const mockCatalog = [
      {
        name: 'dsh-agy-link',
        owner: 'amlyczz',
        npm: 'dsh-agy-link',
        url: 'https://github.com/amlyczz/dsh-agy-link',
        version: '0.4.96',
      },
    ]
    writeFileSync(
      join(tempDshHome, 'dshm', 'cache', 'host', 'awesome', 'catalog-2026.1029.test.json'),
      JSON.stringify(mockCatalog),
      'utf-8',
    )

    const res = await resolveInstallSpec('amlyczz--dsh-agy-link')
    expect(res.packageName).toBe('dsh-agy-link')
    expect(res.resolvedSpec).toBe('dsh-agy-link@0.4.96')
    expect(res.source).toBe('npm')
    expect(res.isMarketId).toBe(true)
  })

  it('resolves market ID with explicit version tag amlyczz--dsh-agy-link@0.4.96', async () => {
    const mockCatalog = [
      {
        name: 'dsh-agy-link',
        owner: 'amlyczz',
        npm: 'dsh-agy-link',
        url: 'https://github.com/amlyczz/dsh-agy-link',
      },
    ]
    writeFileSync(
      join(tempDshHome, 'dshm', 'cache', 'host', 'awesome', 'catalog-2026.1029.test.json'),
      JSON.stringify(mockCatalog),
      'utf-8',
    )

    const res = await resolveInstallSpec('amlyczz--dsh-agy-link@0.4.96')
    expect(res.packageName).toBe('dsh-agy-link')
    expect(res.resolvedSpec).toBe('dsh-agy-link@0.4.96')
    expect(res.isMarketId).toBe(true)
  })

  it('resolves github-only community market ID when npm is not provided in catalog', async () => {
    const mockCatalog = [
      {
        name: 'my-custom-theme',
        owner: 'cooldev',
        url: 'https://github.com/cooldev/my-custom-theme',
        version: '1.0.0',
      },
    ]
    writeFileSync(
      join(tempDshHome, 'dshm', 'cache', 'host', 'awesome', 'catalog-2026.1029.test.json'),
      JSON.stringify(mockCatalog),
      'utf-8',
    )

    const res = await resolveInstallSpec('cooldev--my-custom-theme')
    expect(res.packageName).toBe('my-custom-theme')
    expect(res.resolvedSpec).toBe('github:cooldev/my-custom-theme#v1.0.0')
    expect(res.source).toBe('github')
    expect(res.isMarketId).toBe(true)
  })
})
