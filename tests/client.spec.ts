import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  formatAuditSummary,
  fetchAuditReport,
  approvePackageInstall,
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
    expect(inject).toContain('remote')
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

  it('hooks ctx.remote.pluginManager.installBundle correctly', async () => {
    const mockInstallBundle = vi.fn().mockResolvedValue({ ok: true })
    const ctx = {
      remote: {
        pluginManager: {
          installBundle: mockInstallBundle,
        },
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

    apply(ctx)

    // Verify it was wrapped
    expect((ctx.remote.pluginManager.installBundle as any).__guarded).toBe(true)

    // Execute installBundle
    await ctx.remote.pluginManager.installBundle('clean-pkg@1.0.0', { selection: true })

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(mockInstallBundle).toHaveBeenCalledWith('clean-pkg@1.0.0', {
      selection: true,
      auditToken: 'test-token-123',
    })

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
