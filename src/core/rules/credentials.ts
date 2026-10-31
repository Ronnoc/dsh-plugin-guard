/**
 * Rule: Credentials & Secret Store Protection
 * Detects unauthorized probing or reading of user secrets, SSH keys, DSH configs,
 * and environment credentials.
 * @module dsh-plugin-vetter/core/rules/credentials
 */

import type { AuditFinding, GuardRule, RuleContext } from '../types.js'

const SENSITIVE_PATH_PATTERNS = [
  { pattern: /[\\/]\.dsh[\\/](?:agy|credentials|sessions)/i, title: '探测 DSH 核心凭证与 Session 存储', severity: 'CRITICAL' as const },
  { pattern: /(?:AGY_MASTER_KEY|\.credentials\.ya?ml)/i, title: '引用 Antigravity / DSH 主密钥或凭证文件', severity: 'CRITICAL' as const },
  { pattern: /[\\/]\.ssh[\\/](?:id_rsa|id_ed25519|id_ecdsa|authorized_keys)/i, title: '尝试读取宿主 SSH 私钥文件', severity: 'CRITICAL' as const },
  { pattern: /[\\/](?:\.bash_history|\.zsh_history|powershell_history\.txt)/i, title: '尝试读取系统终端历史记录', severity: 'HIGH' as const },
  { pattern: /-----BEGIN (?:RSA|OPENSSH|EC|DSA)? ?PRIVATE KEY-----/, title: '文件中包含硬编码的私钥证书', severity: 'CRITICAL' as const },
  { pattern: /process\.env\.(?:DEEPSEEK_API_KEY|GITHUB_TOKEN|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY)/i, title: '尝试直接访问环境敏感 API 密钥', severity: 'HIGH' as const },
]

export const credentialsRule: GuardRule = {
  id: 'SEC-CRED-001',
  name: 'Credentials & Secret Storage Guard',
  category: 'credentials',
  description: 'Ensures plugins do not probe or exfiltrate private credentials, SSH keys, or DSH master vaults.',

  run(ctx: RuleContext): AuditFinding[] {
    const findings: AuditFinding[] = []

    for (const file of ctx.files) {
      // Don't flag package.json or markdown files for some general keywords unless path match
      const lines = file.content.split('\n')

      for (let i = 0; i < lines.length; i++) {
        const lineContent = lines[i]

        for (const target of SENSITIVE_PATH_PATTERNS) {
          if (target.pattern.test(lineContent)) {
            // Avoid false positives in doc files for env references
            if (file.relPath.endsWith('.md') && target.severity !== 'CRITICAL') {
              continue
            }

            findings.push({
              ruleId: this.id,
              category: this.category,
              severity: target.severity,
              title: target.title,
              description: `在文件 ${file.relPath} 第 ${i + 1} 行检测到对高危敏感路径或凭据变量的直接引用。`,
              file: file.relPath,
              line: i + 1,
              codeSnippet: lineContent.trim().slice(0, 160),
            })
          }
        }
      }
    }

    return findings
  },
}
