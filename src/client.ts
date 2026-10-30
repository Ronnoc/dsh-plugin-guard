/**
 * DSH Plugin Guard: Client-side Interception & Pre-installation Audit Gate
 * Injected into the DSH browser UI to prompt users with security audit findings.
 * @module dsh-plugin-guard/client
 */

import type { AuditReport } from './core/types.js'
import { GUARD_API_PREFIX } from './host/routes.js'

export interface ClientContext {
  pluginManager?: {
    install(spec: string): Promise<unknown>
    update?(spec: string): Promise<unknown>
    [key: string]: unknown
  }
  [key: string]: unknown
}

/**
 * Request an audit report for a package from the host guard service.
 */
export async function fetchAuditReport(spec: string): Promise<AuditReport> {
  const url = `${GUARD_API_PREFIX}/audit?spec=${encodeURIComponent(spec)}`
  const resp = await fetch(url)
  if (!resp.ok) {
    const errorBody = await resp.json().catch(() => ({ error: resp.statusText }))
    throw new Error(errorBody.error || `Failed to fetch audit report (${resp.status})`)
  }
  const data = (await resp.json()) as { ok: boolean; report: AuditReport }
  return data.report
}

/**
 * Submit user approval to host and retrieve single-use authorization token.
 */
export async function approvePackageInstall(
  spec: string,
  options: { force?: boolean } = {},
): Promise<{ auditToken: string; report: AuditReport }> {
  const url = `${GUARD_API_PREFIX}/approve`
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ spec, force: options.force }),
  })
  if (!resp.ok) {
    const errorBody = await resp.json().catch(() => ({ error: resp.statusText }))
    throw new Error(errorBody.error || `Failed to approve package (${resp.status})`)
  }
  return (await resp.json()) as { auditToken: string; report: AuditReport }
}

/**
 * Format audit findings into a clean human-readable text summary for dialogs or console.
 */
export function formatAuditSummary(report: AuditReport): string {
  const lines: string[] = []
  lines.push(`【安全预审评估】${report.packageName}@${report.version}`)
  lines.push(`综合安全评分: ${report.score} / 100 (${report.verdict})`)
  lines.push(`SHA-256: ${report.tarballSha256.slice(0, 16)}...`)
  lines.push('')

  if (report.findings.length === 0) {
    lines.push('✅ 未发现任何已知危险模式或安全异常')
  } else {
    lines.push(`⚠️ 发现 ${report.findings.length} 项风险检查项:`)
    for (const f of report.findings) {
      lines.push(`  [${f.severity}] ${f.title} (${f.file}:${f.line ?? 1})`)
    }
  }

  return lines.join('\n')
}

/**
 * Mount the client-side decorator onto DSH pluginManager.
 */
export function apply(ctx: ClientContext): void {
  if (!ctx.pluginManager || typeof ctx.pluginManager.install !== 'function') {
    return
  }

  const originalInstall = ctx.pluginManager.install.bind(ctx.pluginManager)

  // Decorate ctx.pluginManager.install to inject security review gate
  ctx.pluginManager.install = async (spec: string): Promise<unknown> => {
    // 1. Fetch pre-install security audit from host
    const report = await fetchAuditReport(spec)

    // 2. If dangerous, check findings
    if (report.verdict === 'DANGEROUS') {
      const summary = formatAuditSummary(report)
      const shouldProceed = typeof window !== 'undefined' && typeof window.confirm === 'function'
        ? window.confirm(`${summary}\n\n检测到高危安全风险！是否强制放行安装？`)
        : false

      if (!shouldProceed) {
        throw new Error(`[dsh-plugin-guard] 用户中止了高危插件 ${spec} 的安装`)
      }

      // User confirmed force bypass
      const { auditToken } = await approvePackageInstall(spec, { force: true })
      return originalInstall(`${spec}?auditToken=${auditToken}`)
    }

    // 3. If caution, ask for confirmation
    if (report.verdict === 'CAUTION') {
      const summary = formatAuditSummary(report)
      const shouldProceed = typeof window !== 'undefined' && typeof window.confirm === 'function'
        ? window.confirm(`${summary}\n\n插件包含警告项，是否确认继续安装？`)
        : true

      if (!shouldProceed) {
        throw new Error(`[dsh-plugin-guard] 用户取消了 ${spec} 的安装`)
      }

      const { auditToken } = await approvePackageInstall(spec)
      return originalInstall(`${spec}?auditToken=${auditToken}`)
    }

    // 4. If SAFE, automatically obtain token and proceed
    const { auditToken } = await approvePackageInstall(spec)
    return originalInstall(`${spec}?auditToken=${auditToken}`)
  }
}

export default { apply }
