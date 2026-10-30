/**
 * DSH Plugin Guard: Client-side Interception & Pre-installation Audit Gate
 * Injected into the DSH browser UI to prompt users with security audit findings.
 * @module dsh-plugin-guard/client
 */

import type { AuditReport } from './core/types.js'
import { GUARD_API_PREFIX } from './core/constants.js'

export const name = 'dsh-plugin-guard'
export const inject: string[] = []

export interface RemotePluginManager {
  installBundle(spec: string, options?: unknown): Promise<unknown>
  [key: string]: unknown
}

export interface ClientContext {
  pluginManager?: {
    install(spec: string): Promise<unknown>
    update?(spec: string): Promise<unknown>
    [key: string]: unknown
  }
  remote?: {
    pluginManager?: RemotePluginManager
    [key: string]: unknown
  }
  'remote.pluginManager'?: RemotePluginManager
  inject?(deps: string[], callback: (ctx: ClientContext) => void): void
  [key: string]: unknown
}

/**
 * Request an audit report for a package from the host guard service.
 */
export async function fetchAuditReport(spec: string): Promise<AuditReport> {
  const url = `${GUARD_API_PREFIX}/audit?spec=${encodeURIComponent(spec)}`
  const resp = await fetch(url)
  if (!resp.ok) {
    const errorBody = (await resp.json().catch(() => ({ error: resp.statusText }))) as { error?: string }
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
    const errorBody = (await resp.json().catch(() => ({ error: resp.statusText }))) as { error?: string }
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
  lines.push(`SHA-256: ${report.tarballSha256 ? report.tarballSha256.slice(0, 16) + '...' : 'N/A'}`)
  lines.push('')

  if (!report.findings || report.findings.length === 0) {
    lines.push('✅ 未发现任何已知危险模式或安全异常')
  } else {
    lines.push(`⚠️ 发现 ${report.findings.length} 项风险检查项:`)
    for (const f of report.findings) {
      lines.push(`  [${f.severity}] ${f.title} (${f.ruleId} in ${f.file}:${f.line ?? 1})`)
    }
  }

  return lines.join('\n')
}

/**
 * Prompts user if package is dangerous or cautious, then requests approval token.
 */
async function auditAndConfirm(spec: string): Promise<string> {
  const report = await fetchAuditReport(spec)

  if (report.verdict === 'DANGEROUS') {
    const summary = formatAuditSummary(report)
    const shouldProceed = typeof window !== 'undefined' && typeof window.confirm === 'function'
      ? window.confirm(`${summary}\n\n检测到高危安全风险！是否强制放行安装？`)
      : false

    if (!shouldProceed) {
      throw new Error(`[dsh-plugin-guard] 用户中止了高危插件 ${spec} 的安装`)
    }

    const { auditToken } = await approvePackageInstall(spec, { force: true })
    return auditToken
  }

  if (report.verdict === 'CAUTION') {
    const summary = formatAuditSummary(report)
    const shouldProceed = typeof window !== 'undefined' && typeof window.confirm === 'function'
      ? window.confirm(`${summary}\n\n插件包含警告项，是否确认继续安装？`)
      : true

    if (!shouldProceed) {
      throw new Error(`[dsh-plugin-guard] 用户取消了 ${spec} 的安装`)
    }

    const { auditToken } = await approvePackageInstall(spec)
    return auditToken
  }

  // Safe verdict
  const { auditToken } = await approvePackageInstall(spec)
  return auditToken
}

/**
 * Safely patch installBundle on remote pluginManager (supporting getter-only descriptors).
 */
function patchInstallBundle(pm: any): boolean {
  if (!pm || pm.__pluginGuardInstallBundlePatched) return false

  const desc = Object.getOwnPropertyDescriptor(pm, 'installBundle')

  if (desc?.get) {
    const origGet = desc.get
    try {
      Object.defineProperty(pm, 'installBundle', {
        configurable: true,
        enumerable: true,
        get: function (this: any) {
          const rawFn = origGet.call(this)
          const guarded = async (spec: string, options?: any) => {
            const auditToken = await auditAndConfirm(spec)
            return rawFn(spec, {
              ...(typeof options === 'object' && options !== null ? options : {}),
              auditToken,
            })
          }
          ;(guarded as any).__guarded = true
          return guarded
        },
      })
      pm.__pluginGuardInstallBundlePatched = true
      return true
    } catch (err) {
      console.warn('[dsh-plugin-guard] Failed to define getter on pm.installBundle:', err)
      return false
    }
  }

  if (typeof pm.installBundle === 'function') {
    const rawFn = pm.installBundle.bind(pm)
    const guarded = async (spec: string, options?: any) => {
      const auditToken = await auditAndConfirm(spec)
      return rawFn(spec, {
        ...(typeof options === 'object' && options !== null ? options : {}),
        auditToken,
      })
    }
    ;(guarded as any).__guarded = true

    try {
      Object.defineProperty(pm, 'installBundle', {
        configurable: true,
        enumerable: true,
        writable: true,
        value: guarded,
      })
      pm.__pluginGuardInstallBundlePatched = true
      return true
    } catch {
      try {
        pm.installBundle = guarded
        pm.__pluginGuardInstallBundlePatched = true
        return true
      } catch (err) {
        console.warn('[dsh-plugin-guard] Failed to set pm.installBundle:', err)
        return false
      }
    }
  }

  return false
}

/**
 * Safely patch install on local pluginManager.
 */
function patchInstall(pm: any): boolean {
  if (!pm || pm.__pluginGuardInstallPatched) return false

  const desc = Object.getOwnPropertyDescriptor(pm, 'install')

  if (desc?.get) {
    const origGet = desc.get
    try {
      Object.defineProperty(pm, 'install', {
        configurable: true,
        enumerable: true,
        get: function (this: any) {
          const rawFn = origGet.call(this)
          const guarded = async (spec: string, ...args: any[]) => {
            const auditToken = await auditAndConfirm(spec)
            const decoratedSpec = spec.includes('?') ? `${spec}&auditToken=${auditToken}` : `${spec}?auditToken=${auditToken}`
            return rawFn(decoratedSpec, ...args)
          }
          ;(guarded as any).__guarded = true
          return guarded
        },
      })
      pm.__pluginGuardInstallPatched = true
      return true
    } catch (err) {
      console.warn('[dsh-plugin-guard] Failed to define getter on pm.install:', err)
      return false
    }
  }

  if (typeof pm.install === 'function') {
    const rawFn = pm.install.bind(pm)
    const guarded = async (spec: string, ...args: any[]) => {
      const auditToken = await auditAndConfirm(spec)
      const decoratedSpec = spec.includes('?') ? `${spec}&auditToken=${auditToken}` : `${spec}?auditToken=${auditToken}`
      return rawFn(decoratedSpec, ...args)
    }
    ;(guarded as any).__guarded = true

    try {
      Object.defineProperty(pm, 'install', {
        configurable: true,
        enumerable: true,
        writable: true,
        value: guarded,
      })
      pm.__pluginGuardInstallPatched = true
      return true
    } catch {
      try {
        pm.install = guarded
        pm.__pluginGuardInstallPatched = true
        return true
      } catch (err) {
        console.warn('[dsh-plugin-guard] Failed to set pm.install:', err)
        return false
      }
    }
  }

  return false
}

/**
 * Mount the client-side decorator onto DSH pluginManager and remote.pluginManager.
 */
export function apply(ctx: ClientContext): void {
  try {
    const hookAll = () => {
      if (ctx.remote?.pluginManager) {
        patchInstallBundle(ctx.remote.pluginManager)
      }
      if (ctx['remote.pluginManager']) {
        patchInstallBundle(ctx['remote.pluginManager'])
      }
      if (ctx.pluginManager) {
        patchInstall(ctx.pluginManager)
      }
    }

    hookAll()

    if (typeof ctx.inject === 'function') {
      try {
        ctx.inject(['remote'], () => {
          hookAll()
        })
      } catch {}

      try {
        ctx.inject(['remote.pluginManager'], () => {
          hookAll()
        })
      } catch {}
    }
  } catch (err) {
    console.error('[dsh-plugin-guard] Unexpected error in client apply:', err)
  }
}

export default { name, inject, apply, fetchAuditReport, approvePackageInstall, formatAuditSummary }
