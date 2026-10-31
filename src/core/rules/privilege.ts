/**
 * Rule: DSH Sandbox & Privilege Escalation Guard
 * Audits attempts to tamper with DSH confirmation gates, bypass sandbox policies,
 * or forge approval timestamps.
 * @module dsh-plugin-vetter/core/rules/privilege
 */

import type { AuditFinding, GuardRule, RuleContext } from '../types.js'

export const privilegeRule: GuardRule = {
  id: 'SEC-PRIV-001',
  name: 'Privilege Escalation & Gate Bypass Guard',
  category: 'privilege',
  description: 'Detects unauthorized elevation to danger-full-access, TOCTOU confirmation forging, and sandbox tampering.',

  run(ctx: RuleContext): AuditFinding[] {
    const findings: AuditFinding[] = []

    for (const file of ctx.files) {
      if (file.relPath.endsWith('.md')) continue

      const lines = file.content.split('\n')

      for (let i = 0; i < lines.length; i++) {
        const lineContent = lines[i]

        // 1. Direct forgery of permissionConfirmedAt
        if (/permissionConfirmedAt\s*=\s*(?:Date\.now\(\)|[0-9]+|now)/.test(lineContent)) {
          findings.push({
            ruleId: this.id,
            category: this.category,
            severity: 'CRITICAL',
            title: '疑似伪造特权确认时间戳 (permissionConfirmedAt)',
            description: `文件 ${file.relPath} 第 ${i + 1} 行检测到显式赋值 permissionConfirmedAt，可能绕过人类确认直接提权。`,
            file: file.relPath,
            line: i + 1,
            codeSnippet: lineContent.trim().slice(0, 160),
          })
        }

        // 2. Overriding DSH_PERMISSION_MODE in process
        if (/process\.env\.(?:DSH_PERMISSION_MODE|DSH_TOOLS_MODE)\s*=\s*['"]danger-full-access['"]/.test(lineContent)) {
          findings.push({
            ruleId: this.id,
            category: this.category,
            severity: 'CRITICAL',
            title: '在运行时强制改写进程权限模式为 danger-full-access',
            description: `文件 ${file.relPath} 第 ${i + 1} 行尝试直接改写 DSH 权限环境变量，击穿沙箱安全防护。`,
            file: file.relPath,
            line: i + 1,
            codeSnippet: lineContent.trim().slice(0, 160),
          })
        }

        // 3. Modifying cordis.patch.yml directly from code
        if (/cordis\.patch\.ya?ml/i.test(lineContent) && /(?:writeFileSync|appendFileSync|writeFile)/.test(lineContent)) {
          findings.push({
            ruleId: this.id,
            category: this.category,
            severity: 'HIGH',
            title: '代码中尝试直接修改主配置 cordis.patch.yml',
            description: `文件 ${file.relPath} 第 ${i + 1} 行包含对 cordis.patch.yml 的直接写操作，可能持久化注入恶意补丁。`,
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
