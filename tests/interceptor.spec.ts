import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { Config } from '../src/index.js'
import { GuardInterceptor } from '../src/host/interceptor.js'
import type { AuditReport } from '../src/core/types.js'

describe('GuardInterceptor', () => {
  let testCacheDir: string

  beforeEach(() => {
    testCacheDir = join(
      tmpdir(),
      'dsh-guard-interceptor-test',
      `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    )
    mkdirSync(testCacheDir, { recursive: true })
  })

  afterEach(() => {
    try {
      rmSync(testCacheDir, { recursive: true, force: true })
    } catch {
      // Best effort
    }
  })

  it('blocks install requests when auditToken is missing', () => {
    const interceptor = new GuardInterceptor({ scanOnInstall: true })
    const check = interceptor.validateInstallRequest('some-package@1.0.0')

    expect(check.allowed).toBe(false)
    expect(check.reason).toContain('缺少安全预审放行凭证')
  })

  it('allows install request when scanOnInstall is false', () => {
    const interceptor = new GuardInterceptor({ scanOnInstall: false })
    const check = interceptor.validateInstallRequest('some-package@1.0.0')

    expect(check.allowed).toBe(true)
  })

  it('allows install when a valid token is provided and consumed', async () => {
    const interceptor = new GuardInterceptor({ scanOnInstall: true, strictMode: false })
    // Simulate approval by using token manager inside interceptor directly or approving
    const token = (interceptor as unknown as { tokenManager: { generateToken: (s: string) => string } }).tokenManager.generateToken('clean-plugin@1.0.0')

    const check = interceptor.validateInstallRequest('clean-plugin@1.0.0', token)
    expect(check.allowed).toBe(true)

    // Replay must be rejected
    const replayCheck = interceptor.validateInstallRequest('clean-plugin@1.0.0', token)
    expect(replayCheck.allowed).toBe(false)
    expect(replayCheck.reason).toContain('禁止重放')
  })

  it('validates default config through Cordis Schemastery', () => {
    const parsed = Config({})
    expect(parsed.strictMode).toBe(true)
    expect(parsed.scanOnInstall).toBe(true)
    expect(parsed.enableCache).toBe(true)
    expect(parsed.model).toBe('static')
    expect(parsed.allowedDomains).toContain('registry.npmjs.org')
  })

  it('serves audit results from local persistent cache on fast-path', async () => {
    const interceptor = new GuardInterceptor({
      scanOnInstall: true,
      cacheDir: testCacheDir,
      enableCache: true,
      model: 'static',
    })

    const mockReport: AuditReport = {
      spec: 'cached-plugin@2.0.0',
      packageName: 'cached-plugin',
      version: '2.0.0',
      tarballSha256: 'deadbeef12345678',
      verdict: 'SAFE',
      score: 95,
      findings: [],
      permissions: {
        network: [],
        filesystem: [],
        subprocesses: false,
        mcpTools: [],
      },
      stagedAt: Date.now(),
    }

    // Seed cache manager
    await interceptor.getCacheManager().set(
      {
        model: 'static',
        pluginGuardVersion: '0.1.0',
        plugin: 'cached-plugin@2.0.0',
        tarballSha256: 'deadbeef12345678',
      },
      mockReport,
    )

    // Audit should hit local persistent cache immediately without downloading
    const result = await interceptor.audit('cached-plugin@2.0.0')
    expect(result.cached).toBe(true)
    expect(result.packageName).toBe('cached-plugin')
    expect(result.score).toBe(95)

    // Approving the cached report generates a valid single-use token
    const approval = await interceptor.approve('cached-plugin@2.0.0')
    expect(approval.auditToken).toBeDefined()
    expect(approval.report.cached).toBe(true)

    // Validate install succeeds with this token
    const installCheck = interceptor.validateInstallRequest(
      'cached-plugin@2.0.0',
      approval.auditToken,
    )
    expect(installCheck.allowed).toBe(true)
  })

  it('updates runtime configuration including cache settings', () => {
    const interceptor = new GuardInterceptor({
      enableCache: true,
      model: 'static',
    })

    expect(interceptor.getConfig().model).toBe('static')

    const updated = interceptor.updateConfig({
      model: 'deepseek-chat',
      enableCache: false,
    })

    expect(updated.model).toBe('deepseek-chat')
    expect(updated.enableCache).toBe(false)
    expect(interceptor.getCacheManager().isEnabled()).toBe(false)
  })
})
