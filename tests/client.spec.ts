import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  formatAuditSummary,
  apply,
  name,
  inject,
  patchFetch,
  clearRecentApprovals,
  showAgentReviewModal,
} from '../src/client.js'
import type { AuditReport } from '../src/core/types.js'
import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { execSync } from 'node:child_process'

describe('client module', () => {
  beforeEach(() => {
    clearRecentApprovals()
  })
  it('has expected metadata', () => {
    expect(name).toBe('dsh-plugin-vetter')
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

  it('renders review modal with z-index 2147483647 so it is never occluded by dsh-m overlay', () => {
    const mockReport: AuditReport = {
      spec: 'test-pkg@1.0.0',
      packageName: 'test-pkg',
      version: '1.0.0',
      tarballSha256: 'abcdef',
      verdict: 'SAFE',
      score: 95,
      findings: [],
      permissions: { network: [], filesystem: [], subprocesses: false, mcpTools: [] },
      stagedAt: Date.now(),
    }

    let createdCount = 0
    let modalRootElement: any = null

    const fakeDocument: any = {
      body: {
        appendChild: vi.fn(),
      },
      getElementById: vi.fn().mockReturnValue(null),
      createElement: vi.fn().mockImplementation((tag: string) => {
        createdCount++
        const el: any = {
          id: '',
          style: {},
          appendChild: vi.fn(),
          remove: vi.fn(),
          innerHTML: '',
        }
        if (createdCount === 1) {
          modalRootElement = el
        }
        return el
      }),
    }

    vi.stubGlobal('document', fakeDocument)

    showAgentReviewModal(mockReport)

    expect(modalRootElement).not.toBeNull()
    expect(modalRootElement.id).toBe('dsh-plugin-vetter-modal-root')
    expect(modalRootElement.style.zIndex).toBe('2147483647')
    expect(modalRootElement.style.webkitAppRegion).toBe('no-drag')
    expect(fakeDocument.body.appendChild).toHaveBeenCalledWith(modalRootElement)

    vi.unstubAllGlobals()
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
    const clientPath = resolve('lib/client.js')
    if (!existsSync(clientPath)) {
      execSync('node scripts/build-client.mjs', { stdio: 'pipe' })
    }
    const clientJs = readFileSync(clientPath, 'utf-8')

    // Must not contain ES import/export keywords outside quotes
    expect(clientJs).not.toMatch(/^import\s+/m)
    expect(clientJs).not.toMatch(/^export\s+/m)

    // Must contain ModuleLoader registration
    expect(clientJs).toContain('window.__ModuleLoader__.load')
    expect(clientJs).toContain('dsh-plugin-vetter')

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
    expect(registeredPayload.id).toBe('dsh-plugin-vetter')

    const moduleExports = registeredPayload.factory(() => ({}))
    expect(moduleExports.name).toBe('dsh-plugin-vetter')
    expect(typeof moduleExports.apply).toBe('function')
  })

  it('patchFetch intercepts /dshm install requests and attaches audit token on approval', async () => {
    let dshmReceivedBody: any = null
    const fetchMock = vi.fn().mockImplementation((url: string, opts?: any) => {
      if (url.includes('/api/plugin-vetter/audit')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              ok: true,
              report: {
                spec: 'dsh-claude-style@0.19.6',
                packageName: 'dsh-claude-style',
                version: '0.19.6',
                tarballSha256: 'sha256-mock',
                verdict: 'SAFE',
                score: 100,
                findings: [],
                permissions: { network: [], filesystem: [], subprocesses: false, mcpTools: [] },
              },
            }),
        })
      }
      if (url.includes('/api/plugin-vetter/approve')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              ok: true,
              auditToken: 'approved-token-xyz',
              report: {},
            }),
        })
      }
      if (url === '/dshm' || url.endsWith('/dshm')) {
        dshmReceivedBody = JSON.parse(opts.body)
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ ok: true, installed: true }),
        })
      }
      return Promise.reject(new Error(`Unhandled URL: ${url}`))
    })

    vi.stubGlobal('fetch', fetchMock)
    patchFetch()

    // Simulate dsh-m install request
    const res = await fetch('/dshm', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ method: 'install', id: 'dsh-claude-style', version: '0.19.6' }),
    })
    const data = await res.json()

    expect(data.ok).toBe(true)
    expect(dshmReceivedBody).toBeDefined()
    expect(dshmReceivedBody.auditToken).toBe('approved-token-xyz')
    expect(fetchMock.mock.calls[0][0]).toContain('/api/plugin-vetter/audit?spec=dsh-claude-style%400.19.6')
    expect(fetchMock.mock.calls[1][0]).toContain('/api/plugin-vetter/approve')

    vi.unstubAllGlobals()
  })

  it('patchFetch aborts /dshm install when user rejects dangerous warning', async () => {
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/plugin-vetter/audit')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              ok: true,
              report: {
                spec: 'dsh-claude-style@0.19.6',
                packageName: 'dsh-claude-style',
                version: '0.19.6',
                tarballSha256: 'sha256-mock',
                verdict: 'DANGEROUS',
                score: 20,
                findings: [
                  {
                    ruleId: 'SEC-SUBPROC-001',
                    category: 'subprocesses',
                    severity: 'HIGH',
                    title: 'Dangerous execution',
                    description: 'test',
                    file: 'lib/client.js',
                  },
                ],
                permissions: { network: [], filesystem: [], subprocesses: true, mcpTools: [] },
              },
            }),
        })
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
    })

    vi.stubGlobal('fetch', fetchMock)
    // User clicks Cancel on confirm dialog
    vi.stubGlobal('window', { confirm: () => false })
    patchFetch()

    await expect(
      fetch('/dshm', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ method: 'install', id: 'dsh-claude-style' }),
      }),
    ).rejects.toThrow(/\[dsh-plugin-vetter\] 用户中止了高危插件 dsh-claude-style 的安装/)

    vi.unstubAllGlobals()
  })

  it("registers settings.section and plugins.bundle.config slots in client apply", () => {
    const registered: any[] = []
    const mockCtx = {
      slots: {
        inject: (name: string, fn: any) => fn(),
        register: (options: any, comp: any) => {
          registered.push({ options, comp })
          return () => {}
        },
      },
    }
    apply(mockCtx as any)
    const settingsSlot = registered.find(r => r.options.name === "settings.section")
    const bundleSlot = registered.find(r => r.options.name === "plugins.bundle.config")
    const rowSlot = registered.find(r => r.options.name === "plugins.row.config")

    expect(settingsSlot).toBeDefined()
    expect(settingsSlot?.options.id).toBe("plugin-vetter")
    expect(bundleSlot).toBeDefined()
    expect(bundleSlot?.options.key).toBe("dsh-plugin-vetter")
    expect(rowSlot).toBeDefined()
    expect(rowSlot?.options.key).toBe("dsh-plugin-vetter#dsh-plugin-vetter")
  })
})
