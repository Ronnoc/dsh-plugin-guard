import { describe, it, expect, vi } from 'vitest'
import {
  formatAuditSummary,
  apply,
  name,
  inject,
} from '../src/client.js'
import type { AuditReport } from '../src/core/types.js'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

describe('client module', () => {
  it('has expected metadata', () => {
    expect(name).toBe('dsh-plugin-guard')
    expect(Array.isArray(inject)).toBe(true)
  })

  it('formats audit summary accurately', () => {
    const mockReport: AuditReport = {
      spec: 'test-pkg@1.0.0',
      packageName: 'test-pkg',
      version: '1.0.0',
      tarballSha256: 'abcdef1234567890abcdef1234567890',
      verdict: 'SAFE',
      score: 95,
      findings: [],
      permissions: { network: [], filesystem: [], subprocesses: false, mcpTools: [] },
      stagedAt: Date.now(),
    }

    const summary = formatAuditSummary(mockReport)
    expect(summary).toContain('test-pkg@1.0.0')
    expect(summary).toContain('95 / 100')
    expect(summary).toContain('未发现任何已知危险模式')
  })

  it('formats audit summary with findings', () => {
    const mockReport: AuditReport = {
      spec: 'bad-pkg@1.0.0',
      packageName: 'bad-pkg',
      version: '1.0.0',
      tarballSha256: 'abcdef1234567890abcdef1234567890',
      verdict: 'DANGEROUS',
      score: 10,
      findings: [
        {
          ruleId: 'SEC-CRED-001',
          category: 'credentials',
          severity: 'CRITICAL',
          title: 'Master Token Exfiltration',
          description: 'Accesses sensitive tokens',
          file: 'index.js',
          line: 42,
        },
      ],
      permissions: { network: [], filesystem: [], subprocesses: false, mcpTools: [] },
      stagedAt: Date.now(),
    }

    const summary = formatAuditSummary(mockReport)
    expect(summary).toContain('DANGEROUS')
    expect(summary).toContain('SEC-CRED-001')
    expect(summary).toContain('CRITICAL')
  })

  it('formats audit summary with cached indicator when served from local cache', () => {
    const cachedReport: AuditReport = {
      spec: 'cached-pkg@1.0.0',
      packageName: 'cached-pkg',
      version: '1.0.0',
      tarballSha256: 'abcdef1234567890abcdef1234567890',
      verdict: 'SAFE',
      score: 100,
      cached: true,
      findings: [],
      permissions: { network: [], filesystem: [], subprocesses: false, mcpTools: [] },
      stagedAt: Date.now(),
    }

    const summary = formatAuditSummary(cachedReport)
    expect(summary).toContain('命中本地持久化安全缓存')
    expect(summary).toContain('零重复消耗')
  })

  it('hooks ctx.remote.pluginManager.installBundle correctly when defined as getter (real DSH runtime)', async () => {
    const mockInstallBundle = vi.fn().mockImplementation((spec: string, opts: any) => Promise.resolve({ ok: true, spec, opts }))
    
    // Simulate DSH RemoteNamespaceService with getter-only property in strict mode
    const pm: any = {}
    Object.defineProperty(pm, 'installBundle', {
      configurable: true,
      enumerable: true,
      get: () => mockInstallBundle,
    })

    const ctx = {
      remote: {
        pluginManager: pm,
      },
    }

    // Mock fetch for audit and approve
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/audit')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              ok: true,
              report: {
                spec: 'clean-pkg@1.0.0',
                packageName: 'clean-pkg',
                version: '1.0.0',
                tarballSha256: '12345',
                verdict: 'SAFE',
                score: 100,
                findings: [],
                permissions: { network: [], filesystem: [], subprocesses: false, mcpTools: [] },
                stagedAt: Date.now(),
              },
            }),
        })
      }
      if (url.includes('/approve')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              ok: true,
              auditToken: 'test-token-123',
              report: {},
            }),
        })
      }
      return Promise.reject(new Error(`Unhandled URL: ${url}`))
    })

    vi.stubGlobal('fetch', fetchMock)

    // apply must not throw TypeError: Cannot set property ... which has only a getter
    expect(() => apply(ctx)).not.toThrow()

    // Verify it was wrapped
    expect((ctx.remote.pluginManager.installBundle as any).__guarded).toBe(true)

    // Execute installBundle
    const res = await ctx.remote.pluginManager.installBundle('clean-pkg@1.0.0', { selection: true })

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(mockInstallBundle).toHaveBeenCalledWith('clean-pkg@1.0.0', {
      selection: true,
      auditToken: 'test-token-123',
    })
    expect(res).toEqual({
      ok: true,
      spec: 'clean-pkg@1.0.0',
      opts: { selection: true, auditToken: 'test-token-123' },
    })

    vi.unstubAllGlobals()
  })

  it('hooks ctx.pluginManager.install correctly', async () => {
    const mockInstall = vi.fn().mockResolvedValue({ ok: true })
    const ctx = {
      pluginManager: {
        install: mockInstall,
      },
    }

    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/audit')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              ok: true,
              report: {
                spec: 'foo@1.0.0',
                packageName: 'foo',
                version: '1.0.0',
                tarballSha256: '999',
                verdict: 'SAFE',
                score: 100,
                findings: [],
                permissions: { network: [], filesystem: [], subprocesses: false, mcpTools: [] },
                stagedAt: Date.now(),
              },
            }),
        })
      }
      if (url.includes('/approve')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ ok: true, auditToken: 'tok-abc', report: {} }),
        })
      }
      return Promise.reject(new Error(`Unhandled URL: ${url}`))
    })

    vi.stubGlobal('fetch', fetchMock)

    apply(ctx)
    expect((ctx.pluginManager.install as any).__guarded).toBe(true)

    await ctx.pluginManager.install('foo@1.0.0')
    expect(mockInstall).toHaveBeenCalledWith('foo@1.0.0?auditToken=tok-abc')

    vi.unstubAllGlobals()
  })

  it('built lib/client.js contains valid ModuleLoader registration and no top-level import/export', () => {
    const clientJs = readFileSync(resolve('lib/client.js'), 'utf-8')

    // Must not contain ES import/export keywords outside quotes
    expect(clientJs).not.toMatch(/^import\s+/m)
    expect(clientJs).not.toMatch(/^export\s+/m)

    // Must contain ModuleLoader registration
    expect(clientJs).toContain('window.__ModuleLoader__.load')
    expect(clientJs).toContain('dsh-plugin-guard')

    // Simulate DSH module loader environment
    let registeredPayload: any = null
    const fakeWindow: any = {
      __ModuleLoader__: {
        load: (payload: any) => {
          registeredPayload = payload
        },
      },
    }

    const runner = new Function('window', clientJs)
    expect(() => runner(fakeWindow)).not.toThrow()
    expect(registeredPayload).not.toBeNull()
    expect(registeredPayload.id).toBe('dsh-plugin-guard')

    const moduleExports = registeredPayload.factory(() => ({}))
    expect(moduleExports.name).toBe('dsh-plugin-guard')
    expect(typeof moduleExports.apply).toBe('function')
  })
})
