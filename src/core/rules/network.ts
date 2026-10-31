/**
 * Rule: Network Outbound & Exfiltration Guard
 * Inspects all hardcoded external network endpoints, WebSockets, and known C2 vectors.
 * @module dsh-plugin-vetter/core/rules/network
 */

import type { AuditFinding, GuardRule, RuleContext } from '../types.js'

const DEFAULT_ALLOWED_DOMAINS = [
  'registry.npmjs.org',
  'github.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'dsh-market.com',
  'api.deepseek.com',
  'localhost',
  '127.0.0.1',
]

// Common C2 exfiltration channels
const SUSPICIOUS_C2_HOSTS = [
  /discord(?:app)?\.com\/api\/webhooks/i,
  /api\.telegram\.org\/bot/i,
  /pastebin\.com\/raw/i,
  /webhook\.site/i,
  /requestbin\./i,
  /ngrok(?:-free)?\.app/i,
  /pipedream\.net/i,
  /oastify\.com/i,
  /burpcollaborator\.net/i,
]

const URL_REGEX = /https?:\/\/([a-zA-Z0-9.-]+(?::[0-9]+)?)(?:\/[^\s"'>]*)?/g

export const networkRule: GuardRule = {
  id: 'SEC-NET-001',
  name: 'Outbound Network & C2 Detection',
  category: 'network',
  description: 'Audits all declared or hardcoded outbound HTTP/WebSocket endpoints for unauthorized telemetry or exfiltration.',

  run(ctx: RuleContext): AuditFinding[] {
    const findings: AuditFinding[] = []
    const allowed = new Set([
      ...DEFAULT_ALLOWED_DOMAINS,
      ...(ctx.config.allowedDomains ?? []),
    ])

    for (const file of ctx.files) {
      if (file.relPath.endsWith('.md') || file.relPath.endsWith('.json')) {
        continue
      }

      const lines = file.content.split('\n')

      for (let i = 0; i < lines.length; i++) {
        const lineContent = lines[i]

        // Check for raw C2 vectors first
        for (const c2Pattern of SUSPICIOUS_C2_HOSTS) {
          if (c2Pattern.test(lineContent)) {
            findings.push({
              ruleId: this.id,
              category: this.category,
              severity: 'CRITICAL',
              title: '疑似 C2 外联 / Webhook 数据泄露通道',
              description: `在文件 ${file.relPath} 第 ${i + 1} 行检测到已知的公网 Webhook/C2 接收端。`,
              file: file.relPath,
              line: i + 1,
              codeSnippet: lineContent.trim().slice(0, 160),
            })
          }
        }

        // Check general URLs
        let match: RegExpExecArray | null
        URL_REGEX.lastIndex = 0
        while ((match = URL_REGEX.exec(lineContent)) !== null) {
          const fullUrl = match[0]
          const host = match[1].toLowerCase().split(':')[0]

          if (!allowed.has(host) && !host.endsWith('.github.io')) {
            findings.push({
              ruleId: this.id,
              category: this.category,
              severity: 'MEDIUM',
              title: `发现未报备的外部网络请求: ${host}`,
              description: `插件包含对未经白名单授权的外联域名 (${fullUrl}) 的硬编码网络请求。`,
              file: file.relPath,
              line: i + 1,
              codeSnippet: lineContent.trim().slice(0, 160),
            })
          }
        }

        // Check for raw socket usage
        if (/\brequire\(['"](?:net|dgram)['"]\)|import\s+.*\s+from\s+['"](?:net|dgram)['"]/.test(lineContent)) {
          findings.push({
            ruleId: this.id,
            category: this.category,
            severity: 'HIGH',
            title: '直接使用低级网络 Socket (net/dgram)',
            description: `文件 ${file.relPath} 第 ${i + 1} 行引入了底层网络 Socket 模块，可能绕过标准 HTTP 代理与审计。`,
            file: file.relPath,
            line: i + 1,
            codeSnippet: lineContent.trim().slice(0, 160),
          })
        }
      }
    }

    return findings
  },
}
