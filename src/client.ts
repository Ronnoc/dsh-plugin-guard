/**
 * DSH Plugin Guard: Client-side Interception, Pre-installation Audit Gate & UI Settings
 * Injected into the DSH browser UI to prompt users with security audit findings and provide settings.
 * @module dsh-plugin-guard/client
 */

import React, { useState, useEffect, createElement as h } from 'react'
import type { AuditReport, GuardConfig } from './core/types.js'
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
  entries: unknown[]
}> {
  const resp = await fetch(`${GUARD_API_PREFIX}/cache`)
  if (!resp.ok) {
    throw new Error(`Failed to load cache stats: ${resp.statusText}`)
  }
  return resp.json()
}

/**
 * Clear all persistent audit cache.
 */
export async function clearAuditCache(): Promise<{ ok: boolean; cleared: number }> {
  const resp = await fetch(`${GUARD_API_PREFIX}/cache`, { method: 'DELETE' })
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

  const reload = () => {
    setLoading(true)
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
    } catch (err: any) {
      setTestErr(err?.message || String(err))
    } finally {
      setTesting(false)
    }
  }

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
  )
}

/**
 * Mount the client-side decorator and slots onto DSH context.
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
  formatAuditSummary,
}
