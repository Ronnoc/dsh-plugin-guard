/**
 * DSH Plugin Guard: Audit Session & Interception Coordinator
 * Coordinates staging, static security scanning, cached reports, and approval tokens.
 * @module dsh-plugin-vetter/host/interceptor
 */

import type { AuditOptions, AuditReport, GuardConfig } from '../core/types.js'
import { stageAndAuditPackage, type StageSession } from '../core/stager.js'
import { AuditCacheManager } from '../core/cache.js'
import { TokenManager } from './token.js'

interface StagedCacheEntry {
  session: StageSession
  expiresAt: number
}

interface ApprovedRecord {
  spec: string
  packageName: string
  version?: string
  tarballSha256: string
  approvedAt: number
  expiresAt: number
  force?: boolean
  usedCount?: number
  lastUsedAt?: number
}

export class GuardInterceptor {
  private config: GuardConfig
  private tokenManager: TokenManager
  private cacheManager: AuditCacheManager
  private cache = new Map<string, StagedCacheEntry>() // normalizedSpec -> StagedCacheEntry
  private approvals = new Map<string, ApprovedRecord>() // normalizedKey -> ApprovedRecord
  private installGrants = new Map<string, number>() // normalizedKey -> expiresAt
  private hostContext?: any
  private disposed = false

  constructor(config: GuardConfig = {}, hostContext?: any) {
    this.config = config
    this.hostContext = hostContext
    this.tokenManager = new TokenManager(
      config.tokenSecret,
      config.stagingTtlMs ?? 300_000,
    )
    this.cacheManager = new AuditCacheManager({
      cacheDir: config.cacheDir,
      enabled: config.enableCache ?? true,
      defaultModel: config.model ?? 'static',
    })
  }

  /**
   * Sets the host runtime context (providing ctx.llm and ctx.agentDefaultModel).
   */
  setHostContext(ctx: any): void {
    this.hostContext = ctx
  }

  /**
   * Returns whether this interceptor has been disposed/unplugged.
   */
  isDisposed(): boolean {
    return this.disposed
  }

  /**
   * Returns current active guard configuration.
   */
  getConfig(): GuardConfig {
    return {
      strictMode: this.config.strictMode ?? true,
      scanOnInstall: this.config.scanOnInstall ?? true,
      scanOnUpdate: this.config.scanOnUpdate ?? true,
      allowedDomains: this.config.allowedDomains ?? [
        'registry.npmjs.org',
        'github.com',
        'api.github.com',
        'dsh-market.com',
      ],
      stagingTtlMs: this.config.stagingTtlMs ?? 300_000,
      tokenSecret: this.config.tokenSecret,
      cacheDir: this.config.cacheDir ?? this.cacheManager.getCacheDir(),
      enableCache: this.config.enableCache ?? true,
      model: this.config.model ?? 'static',
    }
  }

  /**
   * Updates guard configuration in runtime and updates managers if needed.
   */
  updateConfig(patch: Partial<GuardConfig>): GuardConfig {
    this.config = {
      ...this.config,
      ...patch,
    }
    if (patch.tokenSecret !== undefined || patch.stagingTtlMs !== undefined) {
      this.tokenManager = new TokenManager(
        this.config.tokenSecret,
        this.config.stagingTtlMs ?? 300_000,
      )
    }
    if (
      patch.cacheDir !== undefined ||
      patch.enableCache !== undefined ||
      patch.model !== undefined
    ) {
      this.cacheManager = new AuditCacheManager({
        cacheDir: this.config.cacheDir,
        enabled: this.config.enableCache ?? true,
        defaultModel: this.config.model ?? 'static',
      })
    }
    return this.getConfig()
  }

  /**
   * Returns the underlying persistent audit cache manager.
   */
  getCacheManager(): AuditCacheManager {
    return this.cacheManager
  }

  private async sweepExpired(): Promise<void> {
    const now = Date.now()
    for (const [spec, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(spec)
        await entry.session.cleanup().catch(() => {})
      }
    }
  }

  /**
   * Run an audit on a given package spec (or retrieve cached result).
   * Checks fast-path local disk cache to bypass downloading and scanning entirely
   * when the plugin version has already been audited for the target model.
   */
  async audit(spec: string, options?: AuditOptions): Promise<AuditReport> {
    if (this.disposed) {
      throw new Error('[dsh-plugin-vetter] GuardInterceptor has been disposed / unplugged.')
    }
    await this.sweepExpired()
    const key = spec.trim().toLowerCase()
    const model = options?.model || this.config.model || 'static'

    // 1. In-memory session cache check
    if (!options?.forceRefresh) {
      const cached = this.cache.get(key)
      if (
        cached &&
        Date.now() < cached.expiresAt &&
        (cached.session.report.model || 'static') === model
      ) {
        return cached.session.report
      }
    }

    // Clean up previous in-memory session if any
    const prev = this.cache.get(key)
    if (prev) {
      this.cache.delete(key)
      await prev.session.cleanup().catch(() => {})
    }

    // 2. Fast-path: Check persistent local disk cache before downloading
    if (!options?.forceRefresh && !options?.noCache && this.cacheManager.isEnabled()) {
      const persisted = await this.cacheManager.findBySpec(spec, model)
      if (persisted) {
        // Create an in-memory session stub for token generation and verification
        const ttl = this.config.stagingTtlMs ?? 300_000
        const fakeSession: StageSession = {
          spec,
          stageDir: '',
          unpackedDir: '',
          tarballPath: '',
          tarballSha256: persisted.tarballSha256,
          report: persisted,
          cleanup: async () => {},
        }
        this.cache.set(key, {
          session: fakeSession,
          expiresAt: Date.now() + ttl,
        })
        return persisted
      }
    }

    // 3. Staging and auditing (with tarball sha256 cache check)
    const session = await stageAndAuditPackage(spec, this.config, {
      ...options,
      model,
      cacheManager: this.cacheManager,
      hostContext: options?.hostContext || this.hostContext,
    })

    const ttl = this.config.stagingTtlMs ?? 300_000
    this.cache.set(key, {
      session,
      expiresAt: Date.now() + ttl,
    })

    return session.report
  }

  /**
   * Approve a staged package and obtain a single-use authorization token.
   */
  async approve(
    spec: string,
    options: { force?: boolean; model?: string } = {},
  ): Promise<{
    auditToken: string
    report: AuditReport
  }> {
    if (this.disposed) {
      throw new Error('[dsh-plugin-vetter] GuardInterceptor has been disposed / unplugged.')
    }
    const report = await this.audit(spec, { model: options.model })

    // Strict mode check: cannot approve critical security risks unless explicit force is passed
    if (this.config.strictMode && report.verdict === 'DANGEROUS' && !options.force) {
      const criticalCount = report.findings.filter(f => f.severity === 'CRITICAL').length
      if (criticalCount > 0) {
        throw new Error(
          `[dsh-plugin-vetter] 严格模式 (strictMode) 已启用：拦截到 ${criticalCount} 项 CRITICAL 高危漏洞，禁止放行安装。`,
        )
      }
    }

    const ttl = this.config.stagingTtlMs ?? 300_000
    const token = this.tokenManager.generateToken(
      spec,
      report.tarballSha256,
      ttl,
      {
        originalSpec: report.originalSpec || spec,
        resolvedSpec: report.resolvedSpec,
        packageName: report.packageName,
        version: report.version,
      },
    )

    report.auditToken = token

    // Record approval in memory for host-level verification
    const cleanSpec = spec.split('?')[0].trim()
    const normSpec = cleanSpec.toLowerCase()
    const normPkg = (report.packageName || cleanSpec).trim().toLowerCase()
    const record: ApprovedRecord = {
      spec: cleanSpec,
      packageName: report.packageName,
      version: report.version,
      tarballSha256: report.tarballSha256,
      approvedAt: Date.now(),
      expiresAt: Date.now() + ttl,
      force: options.force,
    }

    this.approvals.set(normSpec, record)
    this.approvals.set(normPkg, record)
    if (report.version) {
      this.approvals.set(`${normPkg}@${report.version}`.toLowerCase(), record)
    }
    this.approvals.set(`${normPkg}@latest`.toLowerCase(), record)

    if (report.resolvedSpec) {
      this.approvals.set(report.resolvedSpec.split('?')[0].trim().toLowerCase(), record)
    }
    if (report.originalSpec) {
      this.approvals.set(report.originalSpec.split('?')[0].trim().toLowerCase(), record)
    }

    return { auditToken: token, report }
  }

  private getApprovalLookupKeys(rawSpec: string): string[] {
    const clean = rawSpec.split('?')[0].trim().toLowerCase()
    const keys = new Set<string>([clean])

    // Handle package@version
    const lastAt = clean.lastIndexOf('@')
    if (lastAt > 0) {
      const name = clean.slice(0, lastAt)
      keys.add(name)
      keys.add(`${name}@latest`)
    } else {
      keys.add(`${clean}@latest`)
    }
    return Array.from(keys)
  }

  /**
   * Check if a spec has a valid recent approval.
   */
  isApproved(spec: string): boolean {
    const now = Date.now()
    const keys = this.getApprovalLookupKeys(spec)
    for (const k of keys) {
      const app = this.approvals.get(k)
      if (app && now <= app.expiresAt) {
        return true
      }
    }
    return false
  }

  /**
   * Grant an active installation window for a spec (e.g. 60 seconds) so multi-step installs
   * (e.g. pnpm already-installed -> removeBundle -> re-install, or route gate -> host installBundle) succeed.
   */
  grantInstallWindow(rawSpec: string, durationMs = 60_000): void {
    const now = Date.now()
    const cleanLower = rawSpec.split('?')[0].trim().toLowerCase()
    this.installGrants.set(cleanLower, now + durationMs)
    const atIdx = cleanLower.lastIndexOf('@')
    if (atIdx > 0) {
      this.installGrants.set(cleanLower.slice(0, atIdx), now + durationMs)
    }
  }

  /**
   * Check if a spec has an active installation session grant.
   */
  hasInstallGrant(rawSpec: string): boolean {
    const now = Date.now()
    const cleanLower = rawSpec.split('?')[0].trim().toLowerCase()
    const exp = this.installGrants.get(cleanLower)
    if (exp && now <= exp) return true
    const atIdx = cleanLower.lastIndexOf('@')
    if (atIdx > 0) {
      const pkgExp = this.installGrants.get(cleanLower.slice(0, atIdx))
      if (pkgExp && now <= pkgExp) return true
    }
    return false
  }

  /**
   * Consume an approval (single-use).
   */
  consumeApproval(spec: string): boolean {
    const now = Date.now()
    const cleanSpec = spec.split('?')[0].trim()
    const keys = this.getApprovalLookupKeys(cleanSpec)
    for (const k of keys) {
      const app = this.approvals.get(k)
      if (app && now <= app.expiresAt) {
        // Delete all associated keys for single-use approval
        const relatedKeys = this.getApprovalLookupKeys(app.spec)
        relatedKeys.push(app.packageName.toLowerCase())
        if (app.version) {
          relatedKeys.push(`${app.packageName}@${app.version}`.toLowerCase())
        }
        relatedKeys.push(`${app.packageName}@latest`.toLowerCase())
        for (const rk of relatedKeys) {
          this.approvals.delete(rk)
        }
        return true
      }
    }
    return false
  }

  /**
   * Validates whether an incoming install request should be permitted.
   */
  validateInstallRequest(
    rawSpec: string,
    auditToken?: string,
    options?: { force?: boolean },
  ): { allowed: boolean; reason?: string } {
    const cleanSpec = rawSpec.split('?')[0].trim()

    // If interceptor is disposed, scanning is disabled, explicit force flag passed, or spec has active install grant, allow
    if (
      this.disposed ||
      this.config.scanOnInstall === false ||
      options?.force ||
      this.hasInstallGrant(cleanSpec)
    ) {
      return { allowed: true }
    }

    // 1. If explicit auditToken provided, validate via tokenManager
    if (auditToken) {
      const key = cleanSpec.toLowerCase()
      const cached = this.cache.get(key)
      const expectedSha256 = cached?.session.tarballSha256

      const result = this.tokenManager.consumeToken(auditToken, cleanSpec, expectedSha256)
      if (result.valid) {
        this.consumeApproval(cleanSpec)
        return { allowed: true }
      }
      return {
        allowed: false,
        reason: result.reason ?? '安全预审凭证无效或已失效',
      }
    }

    // 2. If no token provided, check if spec was recently approved in this session
    if (this.consumeApproval(cleanSpec)) {
      return { allowed: true }
    }

    return {
      allowed: false,
      reason: '缺少安全预审放行凭证 (auditToken)。在安装插件前必须通过安全预审并获得用户确认。',
    }
  }

  /**
   * Dispose all active stage folders.
   */
  async dispose(): Promise<void> {
    this.disposed = true
    for (const entry of this.cache.values()) {
      await entry.session.cleanup().catch(() => {})
    }
    this.cache.clear()
    this.approvals.clear()
    this.installGrants.clear()
  }
}
