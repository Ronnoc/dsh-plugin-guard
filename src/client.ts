/**
 * DSH Plugin Guard: Client-side Interception, Pre-installation Audit Gate & UI Settings
 * Injected into the DSH browser UI to prompt users with security audit findings and provide settings.
 * @module dsh-plugin-guard/client
 */

import React, { useState, useEffect, createElement as h } from 'react'
import type { AuditReport, GuardConfig, AuditCacheEntry, AuditCacheStats } from './core/types.js'
import { GUARD_API_PREFIX, LEGACY_GUARD_PREFIX } from './core/constants.js'

export const name = 'dsh-plugin-guard'
export const inject = ['slots', 'locale']

export interface RemotePluginManager {
  installBundle(spec: string, options?: unknown): Promise<unknown>
  [key: string]: unknown
}

export interface ClientContext {
  slots?: {
    inject(slotName: string, factory: () => unknown): unknown
    register(options: Record<string, unknown>, component: unknown): () => void
    entries?(slotName: string): unknown[]
    [key: string]: unknown
  }
  locale?: {
    bind?(ns: string): (key: string) => string
    register?(ns: string, lang: string, dict: Record<string, string>): () => void
    [key: string]: unknown
  }
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
export async function fetchAuditReport(
  spec: string,
  options?: { model?: string; forceRefresh?: boolean },
): Promise<AuditReport> {
  const params = new URLSearchParams({ spec })
  if (options?.model) params.set('model', options.model)
  if (options?.forceRefresh) params.set('forceRefresh', 'true')
  const url = `${GUARD_API_PREFIX}/audit?${params.toString()}`
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
  options: { force?: boolean; model?: string } = {},
): Promise<{ auditToken: string; report: AuditReport }> {
  const url = `${GUARD_API_PREFIX}/approve`
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ spec, force: options.force, model: options.model }),
  })
  if (!resp.ok) {
    const errorBody = (await resp.json().catch(() => ({ error: resp.statusText }))) as { error?: string }
    throw new Error(errorBody.error || `Failed to approve package (${resp.status})`)
  }
  return (await resp.json()) as { auditToken: string; report: AuditReport }
}

/**
 * Fetch current guard configuration from host.
 */
export async function fetchGuardConfig(): Promise<GuardConfig> {
  const resp = await fetch(`${GUARD_API_PREFIX}/config`)
  if (!resp.ok) {
    throw new Error(`Failed to load config: ${resp.statusText}`)
  }
  const data = (await resp.json()) as { ok: boolean; config: GuardConfig }
  return data.config
}

/**
 * Fetch audit persistent cache statistics and entries.
 */
export async function fetchCacheStats(): Promise<{
  ok: boolean
  stats: { totalEntries: number; totalHits: number; cacheDir: string }
  entries: AuditCacheEntry[]
}> {
  const resp = await fetch(`${GUARD_API_PREFIX}/cache`)
  if (!resp.ok) {
    throw new Error(`Failed to load cache stats: ${resp.statusText}`)
  }
  return resp.json()
}

/**
 * Clear all persistent audit cache, or delete a specific entry by hash.
 */
export async function clearAuditCache(hash?: string): Promise<{
  ok: boolean
  cleared?: number
  deleted?: boolean
}> {
  const url = hash
    ? `${GUARD_API_PREFIX}/cache?hash=${encodeURIComponent(hash)}`
    : `${GUARD_API_PREFIX}/cache`
  const resp = await fetch(url, { method: 'DELETE' })
  if (!resp.ok) {
    throw new Error(`Failed to clear cache: ${resp.statusText}`)
  }
  return resp.json()
}

/**
 * Save updated guard configuration to host.
 */
export async function saveGuardConfig(config: Partial<GuardConfig>): Promise<GuardConfig> {
  const resp = await fetch(`${GUARD_API_PREFIX}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  })
  if (!resp.ok) {
    const errData = (await resp.json().catch(() => ({ error: resp.statusText }))) as { error?: string }
    throw new Error(errData.error || `Failed to save config: ${resp.status}`)
  }
  const data = (await resp.json()) as { ok: boolean; config: GuardConfig }
  return data.config
}

/**
 * Format audit findings into a clean human-readable text summary for dialogs or console.
 */
export function formatAuditSummary(report: AuditReport): string {
  const lines: string[] = []
  lines.push(`【安全预审评估】${report.packageName}@${report.version}`)
  lines.push(`综合安全评分: ${report.score} / 100 (${report.verdict})`)
  lines.push(`SHA-256: ${report.tarballSha256 ? report.tarballSha256.slice(0, 16) + '...' : 'N/A'}`)
  if (report.cached) {
    lines.push('⚡ 命中本地持久化安全缓存 (零重复消耗)')
  }
  if (report.recommendation) {
    const recMap: Record<string, string> = {
      APPROVE: '🟢 推荐安装 (业务意图合理，未见恶意特征)',
      REVIEW_CAREFULLY: '🟡 建议复核 (包含敏感特权，请结合用途核验)',
      REJECT: '🔴 建议拦截 (检测到已知威胁或恶意行为)',
    }
    lines.push(`💡 Agent 建议: ${recMap[report.recommendation] || report.recommendation}`)
  }
  if (report.intentAnalysis) {
    lines.push(`📋 意图与行为契合度: ${report.intentAnalysis}`)
  }
  if (report.agentSummary) {
    lines.push(`🤖 审查综述: ${report.agentSummary}`)
  }
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

// Tracks in-flight audit promises to eliminate concurrent duplicate prompts
const inFlightAudits = new Map<string, Promise<string>>()
// Caches recently approved tokens (60 seconds) so chained calls (fetch -> installBundle) succeed without re-prompting
const recentApprovals = new Map<string, { token: string; expiresAt: number }>()

export function clearRecentApprovals(): void {
  recentApprovals.clear()
  inFlightAudits.clear()
}

function getRecentApproval(spec: string): string | undefined {
  const now = Date.now()
  const key = spec.trim().toLowerCase()
  const entry = recentApprovals.get(key)
  if (entry && entry.expiresAt > now) {
    return entry.token
  }
  recentApprovals.delete(key)
  return undefined
}

function recordRecentApproval(spec: string, token: string): void {
  const now = Date.now()
  const key = spec.trim().toLowerCase()
  recentApprovals.set(key, { token, expiresAt: now + 60_000 })
}

/**
 * Renders an in-page modern Agent Review modal in browser, or falls back to confirm in headless tests.
 */
export function showAgentReviewModal(report: AuditReport): Promise<boolean> {
  if (typeof document === 'undefined' || !document.body) {
    const summary = formatAuditSummary(report)
    const promptMsg = report.verdict === 'DANGEROUS'
      ? `${summary}\n\n检测到高危安全风险！是否强制放行安装？`
      : report.verdict === 'CAUTION'
      ? `${summary}\n\n插件包含警告项，是否确认继续安装？`
      : `${summary}\n\nAgent 审查通过，是否确认安装？`
    const shouldProceed = typeof window !== 'undefined' && typeof window.confirm === 'function'
      ? window.confirm(promptMsg)
      : true
    return Promise.resolve(shouldProceed)
  }

  return new Promise((resolve) => {
    const existing = document.getElementById('dsh-plugin-guard-modal-root')
    if (existing) existing.remove()

    const root = document.createElement('div')
    root.id = 'dsh-plugin-guard-modal-root'
    root.style.position = 'fixed'
    root.style.top = '0'
    root.style.left = '0'
    root.style.width = '100vw'
    root.style.height = '100vh'
    root.style.backgroundColor = 'rgba(15, 23, 42, 0.65)'
    root.style.backdropFilter = 'blur(6px)'
    root.style.zIndex = '999999'
    root.style.display = 'flex'
    root.style.alignItems = 'center'
    root.style.justifyContent = 'center'
    root.style.fontFamily = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif'
    root.style.padding = '20px'
    root.style.boxSizing = 'border-box'

    const card = document.createElement('div')
    card.style.background = '#ffffff'
    card.style.color = '#1e293b'
    card.style.width = '100%'
    card.style.maxWidth = '580px'
    card.style.borderRadius = '16px'
    card.style.boxShadow = '0 25px 50px -12px rgba(0, 0, 0, 0.25), 0 0 0 1px rgba(0, 0, 0, 0.05)'
    card.style.overflow = 'hidden'
    card.style.display = 'flex'
    card.style.flexDirection = 'column'

    const verdictColor =
      report.verdict === 'DANGEROUS'
        ? '#ef4444'
        : report.verdict === 'CAUTION'
        ? '#f59e0b'
        : '#10b981'

    const verdictBg =
      report.verdict === 'DANGEROUS'
        ? '#fef2f2'
        : report.verdict === 'CAUTION'
        ? '#fffbeb'
        : '#ecfdf5'

    const verdictBorder =
      report.verdict === 'DANGEROUS'
        ? '#fecaca'
        : report.verdict === 'CAUTION'
        ? '#fde68a'
        : '#a7f3d0'

    const header = document.createElement('div')
    header.style.padding = '20px 24px 16px'
    header.style.borderBottom = '1px solid #f1f5f9'
    header.style.display = 'flex'
    header.style.alignItems = 'center'
    header.style.justifyContent = 'space-between'

    header.innerHTML = `
      <div style="display: flex; align-items: center; gap: 10px;">
        <span style="font-size: 22px;">🛡️</span>
        <div>
          <h2 style="margin: 0; font-size: 17px; font-weight: 600; color: #0f172a;">DSH 插件安全审查</h2>
          <div style="font-size: 13px; color: #64748b; margin-top: 2px;">
            待审对象: <strong style="color: #334155;">${report.spec}</strong>
          </div>
        </div>
      </div>
      <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 4px;">
        <span style="font-size: 12px; font-weight: 600; padding: 4px 10px; border-radius: 9999px; background: ${verdictBg}; color: ${verdictColor}; border: 1px solid ${verdictBorder};">
          ${report.verdict} · ${report.score}/100
        </span>
        ${report.cached ? '<span style="font-size: 11px; color: #059669;">⚡ 命中本地审计缓存</span>' : ''}
      </div>
    `

    const body = document.createElement('div')
    body.style.padding = '20px 24px'
    body.style.maxHeight = '65vh'
    body.style.overflowY = 'auto'
    body.style.display = 'flex'
    body.style.flexDirection = 'column'
    body.style.gap = '14px'

    const recText = report.recommendation === 'REJECT'
      ? '🔴 Agent 建议：建议拦截 (检测到已知威胁或恶意行为)'
      : report.recommendation === 'REVIEW_CAREFULLY'
      ? '🟡 Agent 建议：仔细核验 (包含敏感特权，请结合用途判定)'
      : '🟢 Agent 建议：推荐安装 (业务意图合理，未见恶意特征)'

    const intentHtml = report.intentAnalysis
      ? `<div style="background: #f8fafc; border-radius: 10px; padding: 12px 14px; border: 1px solid #e2e8f0;">
          <div style="font-size: 12px; font-weight: 600; color: #475569; margin-bottom: 4px;">📋 功能意图与权限契合度分析:</div>
          <div style="font-size: 13px; color: #1e293b; line-height: 1.5;">${report.intentAnalysis}</div>
        </div>`
      : ''

    const summaryHtml = report.agentSummary
      ? `<div style="font-size: 13px; color: #334155; line-height: 1.5;">
          <strong>Agent 审查综述:</strong> ${report.agentSummary}
        </div>`
      : ''

    let findingsHtml = ''
    if (report.findings && report.findings.length > 0) {
      findingsHtml = `
        <div style="margin-top: 6px;">
          <div style="font-size: 12px; font-weight: 600; color: #64748b; margin-bottom: 6px;">检查项详情 (${report.findings.length} 条):</div>
          <div style="display: flex; flex-direction: column; gap: 6px;">
            ${report.findings.map(f => `
              <div style="font-size: 12px; background: #fff1f2; border: 1px solid #ffe4e6; border-radius: 8px; padding: 8px 12px; color: #9f1239;">
                <span style="font-weight: 600;">[${f.severity}] ${f.title}</span>
                <div style="margin-top: 2px; color: #4c0519; opacity: 0.85;">${f.description || ''}</div>
              </div>
            `).join('')}
          </div>
        </div>
      `
    } else {
      findingsHtml = `
        <div style="font-size: 12px; color: #059669; background: #ecfdf5; border: 1px solid #d1fae5; border-radius: 8px; padding: 8px 12px;">
          ✅ 未发现任何已知危险模式或代码投毒异常
        </div>
      `
    }

    body.innerHTML = `
      <div style="font-size: 13px; font-weight: 600; color: ${verdictColor}; background: ${verdictBg}; border: 1px solid ${verdictBorder}; border-radius: 10px; padding: 10px 14px;">
        ${recText}
      </div>
      ${intentHtml}
      ${summaryHtml}
      ${findingsHtml}
      <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">
        审查引擎: ${report.model ?? 'DSH Agent'} · 最终安装决策权由您掌控
      </div>
    `

    const footer = document.createElement('div')
    footer.style.padding = '14px 24px'
    footer.style.borderTop = '1px solid #f1f5f9'
    footer.style.background = '#f8fafc'
    footer.style.display = 'flex'
    footer.style.alignItems = 'center'
    footer.style.justifyContent = 'flex-end'
    footer.style.gap = '12px'

    const cancelBtn = document.createElement('button')
    cancelBtn.textContent = '拒绝 / 取消安装'
    cancelBtn.style.padding = '8px 16px'
    cancelBtn.style.fontSize = '13px'
    cancelBtn.style.fontWeight = '500'
    cancelBtn.style.borderRadius = '8px'
    cancelBtn.style.border = '1px solid #cbd5e1'
    cancelBtn.style.background = '#ffffff'
    cancelBtn.style.color = '#475569'
    cancelBtn.style.cursor = 'pointer'

    const approveBtn = document.createElement('button')
    approveBtn.textContent = report.verdict === 'DANGEROUS' ? '已知晓风险，强制放行' : '批准并继续安装'
    approveBtn.style.padding = '8px 18px'
    approveBtn.style.fontSize = '13px'
    approveBtn.style.fontWeight = '600'
    approveBtn.style.borderRadius = '8px'
    approveBtn.style.border = 'none'
    approveBtn.style.background = report.verdict === 'DANGEROUS' ? '#dc2626' : '#2563eb'
    approveBtn.style.color = '#ffffff'
    approveBtn.style.cursor = 'pointer'

    const cleanup = () => {
      root.remove()
    }

    cancelBtn.onclick = () => {
      cleanup()
      resolve(false)
    }

    approveBtn.onclick = () => {
      cleanup()
      resolve(true)
    }

    footer.appendChild(cancelBtn)
    footer.appendChild(approveBtn)

    card.appendChild(header)
    card.appendChild(body)
    card.appendChild(footer)
    root.appendChild(card)
    document.body.appendChild(root)
  })
}

/**
 * Prompts user with Agent review report, then requests approval token upon confirmation.
 * Deduplicates concurrent requests and reuses recent approvals to eliminate duplicate popups.
 */
export async function auditAndConfirm(spec: string): Promise<string> {
  const key = spec.trim().toLowerCase()

  // 1. Fast path: check if recently approved by human in this session
  const recentToken = getRecentApproval(spec)
  if (recentToken) {
    return recentToken
  }

  // 2. Concurrency lock: if this spec is currently being audited, reuse the in-flight promise
  const existing = inFlightAudits.get(key)
  if (existing) {
    return existing
  }

  const auditPromise = (async () => {
    try {
      const report = await fetchAuditReport(spec)

      // Present the Agent review report modal to user
      const shouldProceed = await showAgentReviewModal(report)

      if (!shouldProceed) {
        if (report.verdict === 'DANGEROUS') {
          throw new Error(`[dsh-plugin-guard] 用户中止了高危插件 ${spec} 的安装`)
        } else {
          throw new Error(`[dsh-plugin-guard] 用户取消了 ${spec} 的安装`)
        }
      }

      // User confirmed, now request signed approval token from host
      const isForce = report.verdict === 'DANGEROUS'
      const { auditToken } = await approvePackageInstall(spec, { force: isForce })

      recordRecentApproval(spec, auditToken)
      return auditToken
    } finally {
      inFlightAudits.delete(key)
    }
  })()

  inFlightAudits.set(key, auditPromise)
  return auditPromise
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

const S = {
  container: {
    maxWidth: '780px',
    padding: '4px 0 24px 0',
    color: 'var(--dsw-alias-label-primary, #ffffff)',
    fontFamily: 'var(--dsw-font-family, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif)',
    fontSize: '13px',
    lineHeight: 1.5,
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '14px 18px',
    background: 'var(--dsw-alias-bg-card, rgba(255, 255, 255, 0.04))',
    border: '1px solid var(--dsw-alias-border-l1, rgba(255, 255, 255, 0.1))',
    borderRadius: '8px',
    marginBottom: '16px',
  },
  title: {
    fontSize: '16px',
    fontWeight: 600,
    margin: 0,
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  desc: {
    color: 'var(--dsw-alias-label-tertiary, #999999)',
    fontSize: '12px',
    margin: '4px 0 0 0',
  },
  badgeSuccess: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
    padding: '3px 10px',
    borderRadius: '12px',
    fontSize: '12px',
    fontWeight: 500,
    background: 'rgba(16, 185, 129, 0.15)',
    color: '#10b981',
    border: '1px solid rgba(16, 185, 129, 0.3)',
  },
  card: {
    background: 'var(--dsw-alias-bg-card, rgba(255, 255, 255, 0.03))',
    border: '1px solid var(--dsw-alias-border-l1, rgba(255, 255, 255, 0.08))',
    borderRadius: '8px',
    padding: '16px 18px',
    marginBottom: '14px',
  },
  cardTitle: {
    fontSize: '14px',
    fontWeight: 600,
    margin: '0 0 12px 0',
    color: 'var(--dsw-alias-label-primary, #ffffff)',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  },
  row: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '10px 0',
    borderBottom: '1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.05))',
  },
  rowLast: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '10px 0 0 0',
  },
  label: {
    fontWeight: 500,
    fontSize: '13px',
  },
  sublabel: {
    fontSize: '12px',
    color: 'var(--dsw-alias-label-tertiary, #888888)',
    marginTop: '2px',
  },
  switch: {
    cursor: 'pointer',
    width: '18px',
    height: '18px',
    accentColor: '#10b981',
  },
  input: {
    background: 'var(--dsw-alias-control-bg-secondary, rgba(255, 255, 255, 0.06))',
    border: '1px solid var(--dsw-alias-border-l1, rgba(255, 255, 255, 0.15))',
    borderRadius: '6px',
    color: 'inherit',
    padding: '6px 10px',
    fontSize: '13px',
    outline: 'none',
  },
  btnPrimary: {
    background: '#10a37f',
    color: '#ffffff',
    border: 'none',
    borderRadius: '6px',
    padding: '7px 16px',
    fontSize: '13px',
    fontWeight: 500,
    cursor: 'pointer',
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
  },
  btnSecondary: {
    background: 'var(--dsw-alias-control-bg-secondary, rgba(255, 255, 255, 0.08))',
    color: 'var(--dsw-alias-label-primary, #ffffff)',
    border: '1px solid var(--dsw-alias-border-l1, rgba(255, 255, 255, 0.12))',
    borderRadius: '6px',
    padding: '7px 14px',
    fontSize: '13px',
    cursor: 'pointer',
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
  },
  tag: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
    background: 'rgba(255, 255, 255, 0.08)',
    border: '1px solid rgba(255, 255, 255, 0.12)',
    borderRadius: '4px',
    padding: '3px 8px',
    fontSize: '12px',
    marginRight: '6px',
    marginBottom: '6px',
    fontFamily: 'monospace',
  },
  tagDelete: {
    cursor: 'pointer',
    opacity: 0.7,
    fontWeight: 'bold',
  },
  toastSuccess: {
    padding: '10px 14px',
    borderRadius: '6px',
    fontSize: '13px',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '14px',
    background: 'rgba(16, 185, 129, 0.15)',
    border: '1px solid rgba(16, 185, 129, 0.3)',
    color: '#10b981',
  },
  toastError: {
    padding: '10px 14px',
    borderRadius: '6px',
    fontSize: '13px',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '14px',
    background: 'rgba(239, 68, 68, 0.15)',
    border: '1px solid rgba(239, 68, 68, 0.3)',
    color: '#ef4444',
  },
  btnDanger: {
    background: 'rgba(239, 68, 68, 0.12)',
    color: '#ef4444',
    border: '1px solid rgba(239, 68, 68, 0.25)',
    borderRadius: '6px',
    padding: '6px 12px',
    fontSize: '12px',
    cursor: 'pointer',
    display: 'inline-flex',
    alignItems: 'center',
    gap: '4px',
  },
  btnSmall: {
    background: 'var(--dsw-alias-control-bg-secondary, rgba(255, 255, 255, 0.08))',
    color: 'var(--dsw-alias-label-primary, #ffffff)',
    border: '1px solid var(--dsw-alias-border-l1, rgba(255, 255, 255, 0.12))',
    borderRadius: '4px',
    padding: '3px 8px',
    fontSize: '11px',
    cursor: 'pointer',
    display: 'inline-flex',
    alignItems: 'center',
    gap: '4px',
  },
  statGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
    gap: '10px',
    marginBottom: '14px',
  },
  statBox: {
    background: 'rgba(0, 0, 0, 0.2)',
    border: '1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.07))',
    borderRadius: '6px',
    padding: '10px 12px',
  },
  statVal: {
    fontSize: '16px',
    fontWeight: 700,
    color: '#ffffff',
    fontFamily: 'monospace',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  statLbl: {
    fontSize: '11px',
    color: 'var(--dsw-alias-label-tertiary, #888888)',
    marginTop: '2px',
  },
  historyItem: {
    background: 'rgba(0, 0, 0, 0.22)',
    border: '1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.08))',
    borderRadius: '6px',
    padding: '12px 14px',
    marginBottom: '10px',
  },
  tabBtn: {
    background: 'transparent',
    border: 'none',
    color: 'var(--dsw-alias-label-tertiary, #888888)',
    padding: '4px 10px',
    fontSize: '12px',
    cursor: 'pointer',
    borderRadius: '4px',
  },
  tabBtnActive: {
    background: 'var(--dsw-alias-control-bg-secondary, rgba(255, 255, 255, 0.12))',
    border: 'none',
    color: 'var(--dsw-alias-label-primary, #ffffff)',
    padding: '4px 10px',
    fontSize: '12px',
    cursor: 'pointer',
    borderRadius: '4px',
    fontWeight: 600,
  },
}

function formatTimestamp(ts?: number): string {
  if (!ts) return '未知时间'
  try {
    const d = new Date(ts)
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  } catch {
    return '未知时间'
  }
}

/**
 * Settings and Configuration Section UI Component
 */
export interface GuardSettingsProps { isModal?: boolean; [key: string]: unknown }

export const GuardSettingsSection: React.FC<GuardSettingsProps> = (props) => {
  const [config, setConfig] = useState<GuardConfig>({
    strictMode: true,
    scanOnInstall: true,
    scanOnUpdate: true,
    stagingTtlMs: 300000,
    allowedDomains: ['registry.npmjs.org', 'github.com', 'api.github.com', 'dsh-market.com'],
  })
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<{ text: string; type: 'success' | 'error' } | null>(null)
  const [newDomain, setNewDomain] = useState('')
  const [testSpec, setTestSpec] = useState('lodash@4.17.21')
  const [testing, setTesting] = useState(false)
  const [testReport, setTestReport] = useState<AuditReport | null>(null)
  const [testErr, setTestErr] = useState<string | null>(null)

  // Cache & history state
  const [cacheStats, setCacheStats] = useState<{ totalEntries: number; totalHits: number; cacheDir: string } | null>(null)
  const [cacheEntries, setCacheEntries] = useState<AuditCacheEntry[]>([])
  const [cacheLoading, setCacheLoading] = useState(false)
  const [historySearch, setHistorySearch] = useState('')
  const [historyFilter, setHistoryFilter] = useState<'ALL' | 'SAFE' | 'CAUTION' | 'DANGEROUS'>('ALL')
  const [expandedHashes, setExpandedHashes] = useState<Record<string, boolean>>({})
  const [reAuditingSpec, setReAuditingSpec] = useState<string | null>(null)

  const loadCacheHistory = () => {
    setCacheLoading(true)
    fetchCacheStats()
      .then((res) => {
        if (res && res.ok) {
          setCacheStats(res.stats)
          setCacheEntries(res.entries || [])
        }
      })
      .catch((err) => {
        console.warn('[dsh-plugin-guard] Failed to load cache history:', err)
      })
      .finally(() => {
        setCacheLoading(false)
      })
  }

  const reload = () => {
    setLoading(true)
    loadCacheHistory()
    fetchGuardConfig()
      .then((cfg) => {
        if (cfg) {
          setConfig(cfg)
          setLoading(false)
        }
      })
      .catch((err) => {
        setLoading(false)
        console.warn('[dsh-plugin-guard] Failed to load config:', err)
      })
  }

  useEffect(() => {
    reload()
  }, [])

  const handleClearAllCache = async () => {
    if (typeof window !== 'undefined' && typeof window.confirm === 'function') {
      const ok = window.confirm('确认清空所有本地持久化安全审计缓存与历史记录？所有已缓存的数据将被彻底清理。')
      if (!ok) return
    }
    try {
      const res = await clearAuditCache()
      setMsg({ text: `已成功清空本地安全审计缓存 (清理 ${res.cleared ?? 0} 条记录)`, type: 'success' })
      loadCacheHistory()
    } catch (err: any) {
      setMsg({ text: `清空缓存失败: ${err?.message || String(err)}`, type: 'error' })
    }
  }

  const handleDeleteEntry = async (hash: string, spec: string) => {
    if (typeof window !== 'undefined' && typeof window.confirm === 'function') {
      const ok = window.confirm(`确认删除 ${spec} 的本地预审缓存记录？`)
      if (!ok) return
    }
    try {
      await clearAuditCache(hash)
      setMsg({ text: `已成功删除 ${spec} 的本地预审缓存`, type: 'success' })
      loadCacheHistory()
    } catch (err: any) {
      setMsg({ text: `删除缓存失败: ${err?.message || String(err)}`, type: 'error' })
    }
  }

  const handleReAudit = async (spec: string) => {
    setReAuditingSpec(spec)
    try {
      await fetchAuditReport(spec, { forceRefresh: true })
      setMsg({ text: `已重新预审并刷新本地缓存: ${spec}`, type: 'success' })
      loadCacheHistory()
    } catch (err: any) {
      setMsg({ text: `重新预审失败: ${err?.message || String(err)}`, type: 'error' })
    } finally {
      setReAuditingSpec(null)
    }
  }

  const toggleExpand = (hash: string) => {
    setExpandedHashes((prev) => ({ ...prev, [hash]: !prev[hash] }))
  }

  const handleSave = async () => {
    setSaving(true)
    setMsg(null)
    try {
      const saved = await saveGuardConfig(config)
      setConfig(saved)
      setMsg({ text: '安全设置已保存并同步写入 cordis.patch.yml', type: 'success' })
      setTimeout(() => setMsg(null), 4000)
    } catch (err: any) {
      setMsg({ text: `保存失败: ${err?.message || String(err)}`, type: 'error' })
    } finally {
      setSaving(false)
    }
  }

  const handleAddDomain = () => {
    const trimmed = newDomain.trim().toLowerCase()
    if (!trimmed) return
    const cur = config.allowedDomains ?? []
    if (!cur.includes(trimmed)) {
      setConfig({ ...config, allowedDomains: [...cur, trimmed] })
    }
    setNewDomain('')
  }

  const handleRemoveDomain = (d: string) => {
    const cur = config.allowedDomains ?? []
    setConfig({ ...config, allowedDomains: cur.filter((x) => x !== d) })
  }

  const handleRunAuditTest = async () => {
    const spec = testSpec.trim()
    if (!spec) return
    setTesting(true)
    setTestReport(null)
    setTestErr(null)
    try {
      const rep = await fetchAuditReport(spec)
      setTestReport(rep)
      loadCacheHistory()
    } catch (err: any) {
      setTestErr(err?.message || String(err))
    } finally {
      setTesting(false)
    }
  }

  const countAll = cacheEntries.length
  const countSafe = cacheEntries.filter((e) => e.report.verdict === 'SAFE').length
  const countCaution = cacheEntries.filter((e) => e.report.verdict === 'CAUTION').length
  const countDangerous = cacheEntries.filter((e) => e.report.verdict === 'DANGEROUS').length

  const filteredEntries = cacheEntries.filter((item) => {
    const rep = item.report
    const spec = rep.spec || `${rep.packageName}@${rep.version}`
    if (historyFilter !== 'ALL' && rep.verdict !== historyFilter) {
      return false
    }
    if (historySearch) {
      const q = historySearch.toLowerCase()
      return (
        spec.toLowerCase().includes(q) ||
        (rep.packageName || '').toLowerCase().includes(q)
      )
    }
    return true
  })

  return h(
    'section',
    { style: S.container },
    // Header
    h(
      'div',
      { style: S.header },
      h(
        'div',
        null,
        h('h2', { style: S.title }, '🛡️ 插件安全防护 (Plugin Guard)'),
        h('p', { style: S.desc }, '为 DeepSeek Harness 提供插件安装前的供应链安全静态代码审计、权限探测与放行控制'),
      ),
      h(
        'div',
        { style: S.badgeSuccess },
        h('span', null, '● 拦截防护生效中'),
      ),
    ),

    // Toast Message
    msg
      ? h(
          'div',
          { style: msg.type === 'success' ? S.toastSuccess : S.toastError },
          msg.type === 'success' ? '✅ ' : '❌ ',
          msg.text,
        )
      : null,

    // Card 1: Core Protection Policies
    h(
      'div',
      { style: S.card },
      h('h3', { style: S.cardTitle }, '核心防护策略'),

      // strictMode
      h(
        'div',
        { style: S.row },
        h(
          'div',
          null,
          h('div', { style: S.label }, '严格模式 (strictMode)'),
          h('div', { style: S.sublabel }, '检测到 CRITICAL 级别致命漏洞时强行阻断安装，禁止任何放行'),
        ),
        h('input', {
          type: 'checkbox',
          style: S.switch,
          checked: Boolean(config.strictMode),
          onChange: (e: any) => setConfig({ ...config, strictMode: e.target.checked }),
        }),
      ),

      // scanOnInstall
      h(
        'div',
        { style: S.row },
        h(
          'div',
          null,
          h('div', { style: S.label }, '安装预审拦截 (scanOnInstall)'),
          h('div', { style: S.sublabel }, '在 DSH 客户端执行插件安装（npm / git / url / 市场）时自动拦截并执行安全审计'),
        ),
        h('input', {
          type: 'checkbox',
          style: S.switch,
          checked: Boolean(config.scanOnInstall),
          onChange: (e: any) => setConfig({ ...config, scanOnInstall: e.target.checked }),
        }),
      ),

      // scanOnUpdate
      h(
        'div',
        { style: S.rowLast },
        h(
          'div',
          null,
          h('div', { style: S.label }, '升级预审拦截 (scanOnUpdate)'),
          h('div', { style: S.sublabel }, '在插件执行版本升级时同步触发安全审计，防范供应链投毒'),
        ),
        h('input', {
          type: 'checkbox',
          style: S.switch,
          checked: Boolean(config.scanOnUpdate),
          onChange: (e: any) => setConfig({ ...config, scanOnUpdate: e.target.checked }),
        }),
      ),
    ),

    // Card 2: Allowed Network Domains
    h(
      'div',
      { style: S.card },
      h('h3', { style: S.cardTitle }, '网络外联白名单 (allowedDomains)'),
      h('div', { style: { ...S.sublabel, marginBottom: '10px' } }, '插件静态扫描中允许的合法外联域名，超出白名单的外联调用将触发安全警告'),
      h(
        'div',
        { style: { display: 'flex', flexWrap: 'wrap', marginBottom: '10px' } },
        (config.allowedDomains ?? []).map((dom) =>
          h(
            'span',
            { key: dom, style: S.tag },
            dom,
            h(
              'span',
              {
                style: S.tagDelete,
                onClick: () => handleRemoveDomain(dom),
                title: '移除域名',
              },
              ' ✕',
            ),
          ),
        ),
      ),
      h(
        'div',
        { style: { display: 'flex', gap: '8px', alignItems: 'center' } },
        h('input', {
          type: 'text',
          placeholder: '输入合规域名 (如 api.example.com)',
          style: { ...S.input, flex: 1 },
          value: newDomain,
          onChange: (e: any) => setNewDomain(e.target.value),
          onKeyDown: (e: any) => {
            if (e.key === 'Enter') handleAddDomain()
          },
        }),
        h(
          'button',
          {
            type: 'button',
            style: S.btnSecondary,
            onClick: handleAddDomain,
          },
          '+ 添加域名',
        ),
      ),
    ),

    // Card 3: Staging & Token Parameters
    h(
      'div',
      { style: S.card },
      h('h3', { style: S.cardTitle }, '沙箱与凭证参数'),
      h(
        'div',
        { style: S.rowLast },
        h(
          'div',
          null,
          h('div', { style: S.label }, '暂存区与放行凭证保留时长 (stagingTtlMs)'),
          h('div', { style: S.sublabel }, '安全预审放行 Token 与解压审计沙箱的存活保留周期（毫秒，默认 300,000 即 5 分钟）'),
        ),
        h(
          'div',
          { style: { display: 'flex', alignItems: 'center', gap: '8px' } },
          h('input', {
            type: 'number',
            style: { ...S.input, width: '110px', textAlign: 'right' },
            value: config.stagingTtlMs ?? 300000,
            step: 60000,
            min: 30000,
            onChange: (e: any) => setConfig({ ...config, stagingTtlMs: Number(e.target.value) || 300000 }),
          }),
          h('span', { style: { color: 'var(--dsw-alias-label-tertiary, #888)' } }, 'ms'),
        ),
      ),
    ),

    // Action buttons bar
    h(
      'div',
      { style: { display: 'flex', gap: '10px', marginBottom: '20px' } },
      h(
        'button',
        {
          type: 'button',
          style: S.btnPrimary,
          disabled: saving,
          onClick: handleSave,
        },
        saving ? '正在保存...' : '💾 保存设置',
      ),
      h(
        'button',
        {
          type: 'button',
          style: S.btnSecondary,
          disabled: loading,
          onClick: reload,
        },
        '🔄 重新读取',
      ),
    ),

    // Card 4: Interactive Security Sandbox Audit Tester
    h(
      'div',
      { style: S.card },
      h('h3', { style: S.cardTitle }, '🔍 在线安全预审沙箱测试 (Audit Sandbox Tester)'),
      h('div', { style: { ...S.sublabel, marginBottom: '10px' } }, '测试任意 npm 插件包的安全评分、危险代码模式与权限画像探测：'),
      h(
        'div',
        { style: { display: 'flex', gap: '8px', marginBottom: '12px' } },
        h('input', {
          type: 'text',
          placeholder: '输入插件包名及版本 (例如: lodash@4.17.21 或 dsh-m@0.11.1)',
          style: { ...S.input, flex: 1 },
          value: testSpec,
          onChange: (e: any) => setTestSpec(e.target.value),
          onKeyDown: (e: any) => {
            if (e.key === 'Enter') handleRunAuditTest()
          },
        }),
        h(
          'button',
          {
            type: 'button',
            style: S.btnSecondary,
            disabled: testing,
            onClick: handleRunAuditTest,
          },
          testing ? '正在预审...' : '⚡ 开始预审',
        ),
      ),

      // Test error
      testErr
        ? h(
            'div',
            { style: { ...S.toastError, marginBottom: 0 } },
            '预审测试失败: ',
            testErr,
          )
        : null,

      // Test result report
      testReport
        ? h(
            'div',
            {
              style: {
                background: 'rgba(0, 0, 0, 0.25)',
                border: '1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.1))',
                borderRadius: '6px',
                padding: '12px',
                fontSize: '12px',
              },
            },
            h(
              'div',
              { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' } },
              h(
                'span',
                { style: { fontWeight: 600, fontSize: '13px' } },
                `${testReport.packageName}@${testReport.version}`,
              ),
              h(
                'span',
                {
                  style: {
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontWeight: 600,
                    background:
                      testReport.verdict === 'SAFE'
                        ? 'rgba(16, 185, 129, 0.2)'
                        : testReport.verdict === 'CAUTION'
                          ? 'rgba(245, 158, 11, 0.2)'
                          : 'rgba(239, 68, 68, 0.2)',
                    color:
                      testReport.verdict === 'SAFE'
                        ? '#10b981'
                        : testReport.verdict === 'CAUTION'
                          ? '#f59e0b'
                          : '#ef4444',
                  },
                },
                `${testReport.score}分 (${testReport.verdict})`,
              ),
            ),
            h(
              'div',
              { style: { color: 'var(--dsw-alias-label-tertiary, #aaa)', marginBottom: '8px' } },
              `SHA-256: ${testReport.tarballSha256 || 'N/A'}`,
            ),
            // Permissions
            h(
              'div',
              { style: { marginBottom: '8px' } },
              h('div', { style: { fontWeight: 600, marginBottom: '4px' } }, '探测权限画像:'),
              h(
                'ul',
                { style: { margin: 0, paddingLeft: '18px', color: 'var(--dsw-alias-label-tertiary, #bbb)' } },
                h(
                  'li',
                  null,
                  `子进程执行: ${testReport.permissions?.subprocesses ? '⚠️ 存在本地命令执行' : '无'}`,
                ),
                h(
                  'li',
                  null,
                  `网络端点: ${testReport.permissions?.network?.length ? testReport.permissions.network.join(', ') : '无'}`,
                ),
                h(
                  'li',
                  null,
                  `文件访问: ${testReport.permissions?.filesystem?.length ? testReport.permissions.filesystem.join(', ') : '无'}`,
                ),
                h(
                  'li',
                  null,
                  `MCP 工具注册: ${testReport.permissions?.mcpTools?.length ? testReport.permissions.mcpTools.join(', ') : '无'}`,
                ),
              ),
            ),
            // Findings
            h(
              'div',
              null,
              h('div', { style: { fontWeight: 600, marginBottom: '4px' } }, `风险发现项 (${testReport.findings?.length ?? 0}):`),
              !testReport.findings || testReport.findings.length === 0
                ? h('div', { style: { color: '#10b981' } }, '✅ 未发现任何已知危险模式或安全异常')
                : h(
                    'ul',
                    { style: { margin: 0, paddingLeft: '18px', color: '#f59e0b' } },
                    testReport.findings.map((f, i) =>
                      h(
                        'li',
                        { key: i },
                        `[${f.severity}] ${f.title} (${f.ruleId} in ${f.file}:${f.line ?? 1})`,
                      ),
                    ),
                  ),
            ),
          )
        : null,
    ),

    // Card 5: Audit History & Persistent Local Cache
    h(
      'div',
      { style: S.card },
      h(
        'div',
        {
          style: {
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '12px',
            flexWrap: 'wrap',
            gap: '8px',
          },
        },
        h(
          'div',
          null,
          h('h3', { style: { ...S.cardTitle, margin: 0 } }, '📜 预审历史与本地缓存 (Audit History & Local Cache)'),
          h(
            'div',
            { style: S.sublabel },
            '查看已完成安全审计的插件历史记录、安全评分、权限画像与本地磁盘缓存明细，避免重复开销',
          ),
        ),
        h(
          'div',
          { style: { display: 'flex', gap: '8px' } },
          h(
            'button',
            {
              type: 'button',
              style: S.btnSecondary,
              disabled: cacheLoading,
              onClick: loadCacheHistory,
              title: '刷新历史记录列表',
            },
            cacheLoading ? '正在刷新...' : '🔄 刷新',
          ),
          h(
            'button',
            {
              type: 'button',
              style: S.btnDanger,
              disabled: cacheLoading || cacheEntries.length === 0,
              onClick: handleClearAllCache,
              title: '清空所有磁盘缓存',
            },
            '🗑️ 清空所有缓存',
          ),
        ),
      ),

      // Statistics grid
      h(
        'div',
        { style: S.statGrid },
        h(
          'div',
          { style: S.statBox },
          h('div', { style: S.statVal }, String(cacheStats?.totalEntries ?? cacheEntries.length)),
          h('div', { style: S.statLbl }, '已缓存插件历史数'),
        ),
        h(
          'div',
          { style: S.statBox },
          h('div', { style: { ...S.statVal, color: '#10b981' } }, String(cacheStats?.totalHits ?? 0)),
          h('div', { style: S.statLbl }, '⚡ 累计命中免重审次数'),
        ),
        h(
          'div',
          { style: S.statBox, title: cacheStats?.cacheDir || '~/.dsh/cache/plugin-guard' },
          h(
            'div',
            { style: { ...S.statVal, fontSize: '12px', fontWeight: 500 } },
            cacheStats?.cacheDir ? 'plugin-guard' : '~/.dsh/cache',
          ),
          h(
            'div',
            { style: S.statLbl },
            `本地目录: ${cacheStats?.cacheDir || '~/.dsh/cache/plugin-guard'}`,
          ),
        ),
      ),

      // Filter and search toolbar
      h(
        'div',
        {
          style: {
            display: 'flex',
            flexWrap: 'wrap',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: '8px',
            marginBottom: '12px',
          },
        },
        h(
          'div',
          {
            style: {
              display: 'flex',
              gap: '4px',
              background: 'rgba(0, 0, 0, 0.25)',
              padding: '3px',
              borderRadius: '6px',
            },
          },
          h(
            'button',
            {
              type: 'button',
              style: historyFilter === 'ALL' ? S.tabBtnActive : S.tabBtn,
              onClick: () => setHistoryFilter('ALL'),
            },
            `全部 (${countAll})`,
          ),
          h(
            'button',
            {
              type: 'button',
              style: historyFilter === 'SAFE' ? { ...S.tabBtnActive, color: '#10b981' } : S.tabBtn,
              onClick: () => setHistoryFilter('SAFE'),
            },
            `安全 (${countSafe})`,
          ),
          h(
            'button',
            {
              type: 'button',
              style: historyFilter === 'CAUTION' ? { ...S.tabBtnActive, color: '#f59e0b' } : S.tabBtn,
              onClick: () => setHistoryFilter('CAUTION'),
            },
            `警告 (${countCaution})`,
          ),
          h(
            'button',
            {
              type: 'button',
              style: historyFilter === 'DANGEROUS' ? { ...S.tabBtnActive, color: '#ef4444' } : S.tabBtn,
              onClick: () => setHistoryFilter('DANGEROUS'),
            },
            `高危 (${countDangerous})`,
          ),
        ),
        h('input', {
          type: 'text',
          placeholder: '搜索插件名或版本...',
          value: historySearch,
          style: { ...S.input, width: '200px', fontSize: '12px', padding: '4px 8px' },
          onChange: (e: any) => setHistorySearch(e.target.value),
        }),
      ),

      // List of entries
      cacheLoading && cacheEntries.length === 0
        ? h(
            'div',
            { style: { padding: '24px 0', textAlign: 'center', color: 'var(--dsw-alias-label-tertiary, #888)' } },
            '正在读取本地审计历史记录...',
          )
        : filteredEntries.length === 0
          ? h(
              'div',
              {
                style: {
                  padding: '24px 0',
                  textAlign: 'center',
                  color: 'var(--dsw-alias-label-tertiary, #888)',
                  background: 'rgba(0,0,0,0.15)',
                  borderRadius: '6px',
                },
              },
              cacheEntries.length === 0
                ? '暂无预审历史记录。在 DSH 安装、升级插件或在上方沙箱进行测试时，审计结果将自动留存。'
                : '没有匹配该筛选条件的审计记录。',
            )
          : h(
              'div',
              null,
              filteredEntries.map((item, idx) => {
                const rep = item.report
                const spec = rep.spec || `${rep.packageName}@${rep.version}`
                const hashKey = rep.cacheKey || item.key.tarballSha256 || `item-${idx}`
                const isExpanded = Boolean(expandedHashes[hashKey])
                const isReAuditing = reAuditingSpec === spec

                const verdictColor =
                  rep.verdict === 'SAFE'
                    ? '#10b981'
                    : rep.verdict === 'CAUTION'
                      ? '#f59e0b'
                      : '#ef4444'

                const verdictBg =
                  rep.verdict === 'SAFE'
                    ? 'rgba(16, 185, 129, 0.15)'
                    : rep.verdict === 'CAUTION'
                      ? 'rgba(245, 158, 11, 0.15)'
                      : 'rgba(239, 68, 68, 0.15)'

                return h(
                  'div',
                  {
                    key: hashKey,
                    style: {
                      ...S.historyItem,
                      borderLeft: `3px solid ${verdictColor}`,
                    },
                  },
                  // Summary Header Row
                  h(
                    'div',
                    {
                      style: {
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        flexWrap: 'wrap',
                        gap: '8px',
                      },
                    },
                    h(
                      'div',
                      { style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' } },
                      h('span', { style: { fontWeight: 600, fontSize: '13px' } }, `${rep.packageName}@${rep.version}`),
                      h(
                        'span',
                        {
                          style: {
                            padding: '2px 8px',
                            borderRadius: '4px',
                            fontSize: '11px',
                            fontWeight: 600,
                            background: verdictBg,
                            color: verdictColor,
                          },
                        },
                        `${rep.score}分 (${rep.verdict})`,
                      ),
                      h('span', { style: S.tag }, `模型: ${rep.model || item.key.model || 'static'}`),
                      h('span', { style: S.tag }, `⚡ 命中 ${item.metadata?.hitCount ?? 0} 次`),
                      h(
                        'span',
                        { style: { fontSize: '11px', color: 'var(--dsw-alias-label-tertiary, #888)' } },
                        formatTimestamp(item.metadata?.createdAt || rep.stagedAt),
                      ),
                    ),
                    h(
                      'div',
                      { style: { display: 'flex', alignItems: 'center', gap: '6px' } },
                      h(
                        'button',
                        {
                          type: 'button',
                          style: S.btnSmall,
                          onClick: () => toggleExpand(hashKey),
                        },
                        isExpanded ? '收起 ▴' : '详情 ▾',
                      ),
                      h(
                        'button',
                        {
                          type: 'button',
                          style: S.btnSmall,
                          disabled: isReAuditing,
                          onClick: () => handleReAudit(spec),
                          title: '强制刷新本地缓存并重新预审',
                        },
                        isReAuditing ? '预审中...' : '⚡ 重审',
                      ),
                      h(
                        'button',
                        {
                          type: 'button',
                          style: { ...S.btnSmall, color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.3)' },
                          onClick: () => handleDeleteEntry(hashKey, spec),
                          title: '删除此插件的本地缓存',
                        },
                        '🗑️',
                      ),
                    ),
                  ),

                  // Collapsible Detailed View
                  isExpanded
                    ? h(
                        'div',
                        {
                          style: {
                            marginTop: '12px',
                            paddingTop: '12px',
                            borderTop: '1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.08))',
                            fontSize: '12px',
                          },
                        },
                        // Digest & Staging info
                        h(
                          'div',
                          {
                            style: {
                              display: 'grid',
                              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                              gap: '6px',
                              marginBottom: '10px',
                              color: 'var(--dsw-alias-label-tertiary, #aaa)',
                            },
                          },
                          h('div', null, `Tarball SHA-256: ${rep.tarballSha256 ? rep.tarballSha256.slice(0, 18) + '...' : 'N/A'}`),
                          h('div', null, `缓存 Key: ${rep.cacheKey ? rep.cacheKey.slice(0, 18) + '...' : 'N/A'}`),
                          h('div', null, `扫描耗时: ${item.metadata?.scanDurationMs ? `${item.metadata.scanDurationMs}ms` : '即时'}`),
                          h('div', null, `最后访问: ${formatTimestamp(item.metadata?.accessedAt)}`),
                        ),

                        // Permissions Breakdown
                        h(
                          'div',
                          { style: { marginBottom: '10px' } },
                          h('div', { style: { fontWeight: 600, marginBottom: '4px' } }, '探测权限画像:'),
                          h(
                            'ul',
                            { style: { margin: 0, paddingLeft: '18px', color: 'var(--dsw-alias-label-tertiary, #bbb)' } },
                            h(
                              'li',
                              null,
                              `子进程执行: ${rep.permissions?.subprocesses ? '⚠️ 存在本地命令调用 (exec/spawn)' : '✅ 无本地进程调用'}`,
                            ),
                            h(
                              'li',
                              null,
                              `网络端点: ${rep.permissions?.network?.length ? rep.permissions.network.join(', ') : '✅ 无外部网络请求'}`,
                            ),
                            h(
                              'li',
                              null,
                              `文件系统: ${rep.permissions?.filesystem?.length ? rep.permissions.filesystem.join(', ') : '✅ 无高危敏感文件访问'}`,
                            ),
                            h(
                              'li',
                              null,
                              `MCP 工具: ${rep.permissions?.mcpTools?.length ? rep.permissions.mcpTools.join(', ') : '无 MCP 暴露'}`,
                            ),
                          ),
                        ),

                        // Findings Breakdown
                        h(
                          'div',
                          null,
                          h('div', { style: { fontWeight: 600, marginBottom: '4px' } }, `风险发现项 (${rep.findings?.length ?? 0}):`),
                          !rep.findings || rep.findings.length === 0
                            ? h('div', { style: { color: '#10b981' } }, '✅ 未发现任何已知危险模式或安全异常')
                            : h(
                                'ul',
                                { style: { margin: 0, paddingLeft: '18px', color: '#f59e0b' } },
                                rep.findings.map((f, i) =>
                                  h(
                                    'li',
                                    { key: i, style: { marginBottom: '4px' } },
                                    h(
                                      'span',
                                      {
                                        style: {
                                          padding: '1px 5px',
                                          borderRadius: '3px',
                                          fontSize: '10px',
                                          fontWeight: 600,
                                          marginRight: '6px',
                                          background:
                                            f.severity === 'CRITICAL'
                                              ? 'rgba(239, 68, 68, 0.25)'
                                              : f.severity === 'HIGH'
                                                ? 'rgba(239, 68, 68, 0.15)'
                                                : 'rgba(245, 158, 11, 0.15)',
                                          color:
                                            f.severity === 'CRITICAL' || f.severity === 'HIGH'
                                              ? '#ef4444'
                                              : '#f59e0b',
                                        },
                                      },
                                      f.severity,
                                    ),
                                    h('strong', null, `${f.title} `),
                                    h('span', { style: { color: 'var(--dsw-alias-label-tertiary, #888)' } }, `(${f.ruleId} in ${f.file}:${f.line ?? 1})`),
                                    f.description
                                      ? h('div', { style: { color: 'var(--dsw-alias-label-tertiary, #aaa)', marginTop: '2px' } }, f.description)
                                      : null,
                                  ),
                                ),
                              ),
                        ),
                      )
                    : null,
                )
              }),
            ),
    ),
  )
}

/**
 * Safely patch global fetch to intercept third-party market APIs (e.g. dsh-m /dshm and direct install endpoints).
 */
export function patchFetch(): boolean {
  if (typeof globalThis === 'undefined' || typeof globalThis.fetch !== 'function') return false
  if ((globalThis.fetch as any).__pluginGuardPatched) return false

  const origFetch = globalThis.fetch

  const guardedFetch: typeof fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    let urlStr = ''
    if (typeof input === 'string') {
      urlStr = input
    } else if (input instanceof URL) {
      urlStr = input.toString()
    } else if (input && typeof (input as any).url === 'string') {
      urlStr = (input as any).url
    }

    const method = (init?.method || (input && (input as any).method) || 'GET').toUpperCase()

    // 1. Intercept /dshm install and upgrade calls from dsh-m marketplace
    const isDshm = urlStr === '/dshm' || urlStr.endsWith('/dshm') || urlStr.includes('/dshm?')
    if (isDshm && method === 'POST' && typeof init?.body === 'string') {
      try {
        const bodyObj = JSON.parse(init.body)
        if (bodyObj && typeof bodyObj === 'object') {
          const action = bodyObj.method
          let targetSpec: string | undefined

          if (action === 'install' && typeof bodyObj.id === 'string') {
            targetSpec = typeof bodyObj.version === 'string' && bodyObj.version
              ? `${bodyObj.id}@${bodyObj.version}`
              : bodyObj.id
          } else if (action === 'upgrade' && typeof bodyObj.pkg === 'string') {
            targetSpec = bodyObj.pkg
          } else if (action === 'self-upgrade') {
            targetSpec = 'dsh-m'
          }

          if (targetSpec) {
            console.log(`[dsh-plugin-guard] 拦截到市场 ${action} 请求: ${targetSpec}，执行安全预审...`)
            const auditToken = await auditAndConfirm(targetSpec)

            // Attach auditToken to headers and body
            const headers = new Headers(init.headers || {})
            headers.set('x-audit-token', auditToken)
            bodyObj.auditToken = auditToken

            const newInit: RequestInit = {
              ...init,
              headers,
              body: JSON.stringify(bodyObj),
            }
            return origFetch(input, newInit)
          }
        }
      } catch (err) {
        // If auditAndConfirm threw an error (user cancelled or refused), abort fetch!
        if (err instanceof Error && err.message.includes('[dsh-plugin-guard]')) {
          console.warn('[dsh-plugin-guard] 插件安装已被用户或安全策略拦截:', err.message)
          throw err
        }
        // If other error, rethrow
        throw err
      }
    }

    // 2. Intercept direct /api/plugin-manager/install or /gateway/install
    const isDirectInstall =
      urlStr.includes('/api/plugin-manager/install') ||
      urlStr.includes('/gateway/install') ||
      urlStr.includes('/api/plugins/install')

    if (isDirectInstall && method === 'POST' && typeof init?.body === 'string') {
      try {
        const bodyObj = JSON.parse(init.body)
        const spec = typeof bodyObj?.spec === 'string' ? bodyObj.spec : undefined
        if (spec && !bodyObj.auditToken) {
          const auditToken = await auditAndConfirm(spec)
          const headers = new Headers(init.headers || {})
          headers.set('x-audit-token', auditToken)
          bodyObj.auditToken = auditToken
          return origFetch(input, {
            ...init,
            headers,
            body: JSON.stringify(bodyObj),
          })
        }
      } catch (err) {
        if (err instanceof Error && err.message.includes('[dsh-plugin-guard]')) {
          throw err
        }
      }
    }

    return origFetch(input, init)
  }

  ;(guardedFetch as any).__pluginGuardPatched = true

  try {
    globalThis.fetch = guardedFetch
    if (typeof window !== 'undefined') {
      window.fetch = guardedFetch
    }
    return true
  } catch (err) {
    console.warn('[dsh-plugin-guard] Failed to hook globalThis.fetch:', err)
    return false
  }
}

/**
 * Mount the client-side decorator and slots onto DSH context.
 */
export function apply(ctx: ClientContext): void {
  try {
    patchFetch()

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

    // Register UI slots
    const registerSlots = (slots: any) => {
      if (!slots || typeof slots.inject !== 'function') return

      // 1. DSH Main Settings Left Sidebar entry
      slots.inject('settings.section', () => {
        return slots.register(
          {
            name: 'settings.section',
            id: 'plugin-guard',
            order: 25,
            label: () => '安全防御',
            locale: 'dsh-plugin-guard',
          },
          GuardSettingsSection,
        )
      })

      // 2. DSH Plugin Manager bundle card configuration section
      slots.inject('plugins.bundle.config', () => {
        return slots.register(
          {
            name: 'plugins.bundle.config',
            key: 'dsh-plugin-guard',
            locale: 'dsh-plugin-guard',
          },
          (ownerProps: any) => {
            if (ownerProps?.view === 'summary') return null
            return h(GuardSettingsSection, { isModal: false })
          },
        )
      })

      // 3. DSH Plugin Manager row config
      slots.inject('plugins.row.config', () => {
        return slots.register(
          {
            name: 'plugins.row.config',
            key: 'dsh-plugin-guard#dsh-plugin-guard',
            locale: 'dsh-plugin-guard',
          },
          (ownerProps: any) => {
            if (ownerProps?.view === 'summary') return null
            return h(GuardSettingsSection, { isModal: false })
          },
        )
      })
    }

    if (ctx.slots) {
      registerSlots(ctx.slots)
    }

    if (typeof ctx.inject === 'function') {
      try {
        ctx.inject(['slots'], (c: any) => {
          registerSlots(c?.slots || ctx.slots)
        })
      } catch {}
    }
  } catch (err) {
    console.error('[dsh-plugin-guard] Unexpected error in client apply:', err)
  }
}

export default {
  name,
  inject,
  apply,
  GuardSettingsSection,
  fetchAuditReport,
  approvePackageInstall,
  fetchGuardConfig,
  saveGuardConfig,
  fetchCacheStats,
  clearAuditCache,
  formatAuditSummary,
}
