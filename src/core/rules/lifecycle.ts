/**
 * Rule: Package Lifecycle & Supply Chain Guard
 * Audits package.json scripts (preinstall, postinstall, etc.) that can automatically execute code upon npm/pnpm unpack.
 * @module dsh-plugin-guard/core/rules/lifecycle
 */

import type { AuditFinding, GuardRule, RuleContext } from '../types.js'

const SUSPICIOUS_SCRIPTS = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall']

export const lifecycleRule: GuardRule = {
  id: 'SEC-LIFE-001',
  name: 'Package Lifecycle Hook Guard',
  category: 'lifecycle',
  description: 'Flags dangerous lifecycle scripts (preinstall, postinstall) used for stealth installation-time malware execution.',

  run(ctx: RuleContext): AuditFinding[] {
    const findings: AuditFinding[] = []
    const scripts = (ctx.packageJson['scripts'] ?? {}) as Record<string, unknown>

    for (const hook of SUSPICIOUS_SCRIPTS) {
      if (hook in scripts && typeof scripts[hook] === 'string') {
        const cmd = String(scripts[hook])
        const isNetwork = /curl|wget|node -e|bash|powershell|cmd\.exe/i.test(cmd)

        findings.push({
          ruleId: this.id,
          category: this.category,
          severity: isNetwork ? 'CRITICAL' : 'HIGH',
          title: `检测到安装时生命周期钩子: scripts.${hook}`,
          description: `package.json 声明了 "${hook}" 脚本 (${cmd})。在 npm 安装阶段会自动执行该指令，属于常见的供应链木马投放手段。`,
          file: 'package.json',
          codeSnippet: `"${hook}": "${cmd}"`,
        })
      }
    }

    return findings
  },
}
