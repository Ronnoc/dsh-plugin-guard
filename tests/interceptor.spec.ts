import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { Config, hookHostPluginManager } from '../src/index.js'
import { GuardInterceptor } from '../src/host/interceptor.js'
import type { AuditReport } from '../src/core/types.js'
import { vi } from 'vitest'

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

  it('tracks user approval for dsh-m without explicit token', async () => {
    const interceptor = new GuardInterceptor({
      scanOnInstall: true,
      cacheDir: testCacheDir,
    })

    const mockReport: AuditReport = {
      spec: 'dsh-claude-style@0.19.6',
      packageName: 'dsh-claude-style',
      version: '0.19.6',
      tarballSha256: '92bf19aa87349586',
      verdict: 'SAFE',
      score: 90,
      findings: [],
      permissions: { network: [], filesystem: [], subprocesses: false, mcpTools: [] },
      stagedAt: Date.now(),
    }

    vi.spyOn(interceptor, 'audit').mockResolvedValue(mockReport)

    // User approves via client UI
    await interceptor.approve('dsh-claude-style@0.19.6')

    // Host checks approval
    expect(interceptor.isApproved('dsh-claude-style@0.19.6')).toBe(true)
    expect(interceptor.isApproved('dsh-claude-style')).toBe(true)

    // validateInstallRequest without auditToken should pass because it was approved
    const check = interceptor.validateInstallRequest('dsh-claude-style@0.19.6')
    expect(check.allowed).toBe(true)

    // Subsequent install without fresh approval should fail (single-use)
    const secondCheck = interceptor.validateInstallRequest('dsh-claude-style@0.19.6')
    expect(secondCheck.allowed).toBe(false)
  })

  it('hookHostPluginManager blocks unapproved dangerous package and allows approved package', async () => {
    const interceptor = new GuardInterceptor({
      scanOnInstall: true,
      strictMode: true,
    })

    const mockDangerousReport: AuditReport = {
      spec: 'dsh-malicious@1.0.0',
      packageName: 'dsh-malicious',
      version: '1.0.0',
      tarballSha256: 'badbad123',
      verdict: 'DANGEROUS',
      score: 10,
      findings: [
        {
          ruleId: 'SEC-CRED-001',
          category: 'credentials',
          severity: 'CRITICAL',
          title: 'Steals secrets',
          description: 'bad',
          file: 'index.js',
        },
      ],
      permissions: { network: [], filesystem: [], subprocesses: false, mcpTools: [] },
      stagedAt: Date.now(),
    }

    vi.spyOn(interceptor, 'audit').mockResolvedValue(mockDangerousReport)

    const rawInstallBundle = vi.fn().mockResolvedValue({ installed: true })
    const pm = {
      installBundle: rawInstallBundle,
    }

    hookHostPluginManager(pm, interceptor)

    // Calling unapproved dangerous package should throw and block
    await expect(pm.installBundle('dsh-malicious@1.0.0')).rejects.toThrow(
      /严格模式阻断：插件 dsh-malicious@1.0.0 存在高危安全漏洞/,
    )
    expect(rawInstallBundle).not.toHaveBeenCalled()

    // Now test with approved package
    const mockSafeReport: AuditReport = {
      spec: 'safe-pkg@1.0.0',
      packageName: 'safe-pkg',
      version: '1.0.0',
      tarballSha256: 'good123',
      verdict: 'SAFE',
      score: 100,
      findings: [],
      permissions: { network: [], filesystem: [], subprocesses: false, mcpTools: [] },
      stagedAt: Date.now(),
    }

    vi.spyOn(interceptor, 'audit').mockResolvedValue(mockSafeReport)
    await interceptor.approve('safe-pkg@1.0.0')

    const res = await pm.installBundle('safe-pkg@1.0.0')
    expect(res).toEqual({ installed: true })
    expect(rawInstallBundle).toHaveBeenCalledWith('safe-pkg@1.0.0', undefined)
  })

  it('allows manual user confirmation of dangerous packages when approved with force', async () => {
    const interceptor = new GuardInterceptor({
      scanOnInstall: true,
      strictMode: true,
    })

    const mockDangerousReport: AuditReport = {
      spec: 'dsh-agy-link@0.4.96',
      packageName: 'dsh-agy-link',
      version: '0.4.96',
      tarballSha256: '9879772bc242e0697d8d78964a79fd8d5b5c77a05534fd964c98777e93cfe27c',
      verdict: 'DANGEROUS',
      score: 0,
      findings: [
        {
          ruleId: 'SEC-CRED-001',
          category: 'credentials',
          severity: 'CRITICAL',
          title: 'Direct access to ~/.dsh/agy-accounts',
          description: 'test',
          file: 'dist/index.js',
        },
      ],
      permissions: { network: [], filesystem: [], subprocesses: true, mcpTools: [] },
      stagedAt: Date.now(),
    }

    vi.spyOn(interceptor, 'audit').mockResolvedValue(mockDangerousReport)

    const rawInstallBundle = vi.fn().mockResolvedValue({ installed: true })
    const pm = { installBundle: rawInstallBundle }
    hookHostPluginManager(pm, interceptor)

    // User explicitly manually confirmed ("已知晓风险，强制放行")
    await interceptor.approve('dsh-agy-link', { force: true })

    // Host installer invokes pm.installBundle with target version
    const res = await pm.installBundle('dsh-agy-link@0.4.96')
    expect(res).toEqual({ installed: true })
    expect(rawInstallBundle).toHaveBeenCalledWith('dsh-agy-link@0.4.96', undefined)
  })

  it('permits two-step upgrade without losing approval grant', async () => {
    const interceptor = new GuardInterceptor({
      scanOnInstall: true,
      strictMode: true,
    })

    const mockReport: AuditReport = {
      spec: 'dsh-agy-link@0.4.96',
      packageName: 'dsh-agy-link',
      version: '0.4.96',
      tarballSha256: '9879772bc242e0697d8d78964a79fd8d5b5c77a05534fd964c98777e93cfe27c',
      verdict: 'DANGEROUS',
      score: 0,
      findings: [
        {
          ruleId: 'SEC-CRED-001',
          category: 'credentials',
          severity: 'CRITICAL',
          title: 'Direct access to ~/.dsh/agy-accounts',
          description: 'test',
          file: 'dist/index.js',
        },
      ],
      permissions: { network: [], filesystem: [], subprocesses: true, mcpTools: [] },
      stagedAt: Date.now(),
    }

    vi.spyOn(interceptor, 'audit').mockResolvedValue(mockReport)

    let callCount = 0
    const rawInstallBundle = vi.fn().mockImplementation(async () => {
      callCount++
      if (callCount === 1) {
        // First leg fails with already-installed in dsh-m
        return { application: 'failed', error: { code: 'already-installed' } }
      }
      return { application: 'applied' }
    })

    const pm = { installBundle: rawInstallBundle }
    hookHostPluginManager(pm, interceptor)

    // User approves with force
    await interceptor.approve('dsh-agy-link@0.4.96', { force: true })

    // Leg 1: First install attempt
    const res1 = await pm.installBundle('dsh-agy-link@0.4.96')
    expect(res1).toEqual({ application: 'failed', error: { code: 'already-installed' } })

    // Leg 2: Second install attempt after removeBundle in silent two-step upgrade
    // Must NOT be blocked by strictMode!
    const res2 = await pm.installBundle('dsh-agy-link@0.4.96')
    expect(res2).toEqual({ application: 'applied' })
  })

  it('respects options.force and options.bypassGuard for manual installations', async () => {
    const interceptor = new GuardInterceptor({
      scanOnInstall: true,
      strictMode: true,
    })

    const mockDangerousReport: AuditReport = {
      spec: 'custom-tool@1.0.0',
      packageName: 'custom-tool',
      version: '1.0.0',
      tarballSha256: 'mock123',
      verdict: 'DANGEROUS',
      score: 10,
      findings: [
        {
          ruleId: 'SEC-EXEC-001',
          category: 'execution',
          severity: 'CRITICAL',
          title: 'Command exec',
          description: 'test',
          file: 'index.js',
        },
      ],
      permissions: { network: [], filesystem: [], subprocesses: true, mcpTools: [] },
      stagedAt: Date.now(),
    }

    vi.spyOn(interceptor, 'audit').mockResolvedValue(mockDangerousReport)

    const rawInstallBundle = vi.fn().mockResolvedValue({ installed: true })
    const pm = { installBundle: rawInstallBundle }
    hookHostPluginManager(pm, interceptor)

    // Direct manual install with force: true
    const res = await pm.installBundle('custom-tool@1.0.0', { force: true })
    expect(res).toEqual({ installed: true })
    expect(rawInstallBundle).toHaveBeenCalledWith('custom-tool@1.0.0', { force: true })
  })

  it('permits dangerous installation with warning when strictMode is disabled', async () => {
    const interceptor = new GuardInterceptor({
      scanOnInstall: true,
      strictMode: false,
    })

    const mockDangerousReport: AuditReport = {
      spec: 'non-strict-pkg@1.0.0',
      packageName: 'non-strict-pkg',
      version: '1.0.0',
      tarballSha256: 'mock456',
      verdict: 'DANGEROUS',
      score: 10,
      findings: [
        {
          ruleId: 'SEC-EXEC-001',
          category: 'execution',
          severity: 'CRITICAL',
          title: 'Command exec',
          description: 'test',
          file: 'index.js',
        },
      ],
      permissions: { network: [], filesystem: [], subprocesses: true, mcpTools: [] },
      stagedAt: Date.now(),
    }

    vi.spyOn(interceptor, 'audit').mockResolvedValue(mockDangerousReport)

    const rawInstallBundle = vi.fn().mockResolvedValue({ installed: true })
    const pm = { installBundle: rawInstallBundle }
    hookHostPluginManager(pm, interceptor)

    const res = await pm.installBundle('non-strict-pkg@1.0.0')
    expect(res).toEqual({ installed: true })
  })

  it('strips query parameters from spec before passing to raw installBundle', async () => {
    const interceptor = new GuardInterceptor({
      scanOnInstall: true,
      strictMode: true,
    })

    const mockSafeReport: AuditReport = {
      spec: 'safe-pkg@1.0.0',
      packageName: 'safe-pkg',
      version: '1.0.0',
      tarballSha256: 'good123',
      verdict: 'SAFE',
      score: 100,
      findings: [],
      permissions: { network: [], filesystem: [], subprocesses: false, mcpTools: [] },
      stagedAt: Date.now(),
    }

    vi.spyOn(interceptor, 'audit').mockResolvedValue(mockSafeReport)
    const { auditToken } = await interceptor.approve('safe-pkg@1.0.0')

    const rawInstallBundle = vi.fn().mockResolvedValue({ installed: true })
    const pm = { installBundle: rawInstallBundle }
    hookHostPluginManager(pm, interceptor)

    // Spec passed with query param from client patchInstall
    await pm.installBundle(`safe-pkg@1.0.0?auditToken=${auditToken}`)
    expect(rawInstallBundle).toHaveBeenCalledWith('safe-pkg@1.0.0', undefined)
  })
})
