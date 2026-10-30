/**
 * Rule: Subprocess & Dynamic Code Execution Guard
 * Flags unauthorized shell command execution, dynamic evaluation, and binary spawning.
 * @module dsh-plugin-guard/core/rules/execution
 */

import type { AuditFinding, GuardRule, RuleContext } from '../types.js'

export const executionRule: GuardRule = {
  id: 'SEC-EXEC-001',
  name: 'Subprocess & Dynamic Code Execution Guard',
  category: 'execution',
  description: 'Audits arbitrary command execution via child_process, eval, and dynamic code compilers.',

  run(ctx: RuleContext): AuditFinding[] {
    const findings: AuditFinding[] = []

    for (const file of ctx.files) {
      if (file.relPath.endsWith('.md') || file.relPath.endsWith('.json')) {
        continue
      }

      const lines = file.content.split('\n')

      for (let i = 0; i < lines.length; i++) {
        const lineContent = lines[i]

        // 1. Direct eval or Function constructor
        if (/\beval\s*\(|\bnew\s+Function\s*\(/.test(lineContent)) {
          findings.push({
            ruleId: this.id,
            category: this.category,
            severity: 'HIGH',
            title: '动态代码执行 (eval / new Function)',
            description: `文件 ${file.relPath} 第 ${i + 1} 行包含动态代码执行，极易被利用进行任意代码注入。`,
            file: file.relPath,
            line: i + 1,
            codeSnippet: lineContent.trim().slice(0, 160),
          })
        }

        // 2. Node.js VM module
        if (/\b(?:vm|node:vm)\.runIn(?:New)?Context\s*\(/.test(lineContent)) {
          findings.push({
            ruleId: this.id,
            category: this.category,
            severity: 'HIGH',
            title: 'Node.js VM 沙箱动态执行',
            description: `文件 ${file.relPath} 第 ${i + 1} 行调用了 vm 模块执行动态脚本，VM 沙箱在 Node 环境下已被证明存在已知逃逸风险。`,
            file: file.relPath,
            line: i + 1,
            codeSnippet: lineContent.trim().slice(0, 160),
          })
        }

        // 3. Child Process Execution
        if (/\b(?:child_process|node:child_process)\b|\b(?:execSync|execFile|spawnSync|fork)\s*\(/.test(lineContent)) {
          const pkgName = String(ctx.packageJson['name'] || '').toLowerCase()
          const pkgDesc = String(ctx.packageJson['description'] || '').toLowerCase()
          const isManagerOrDev =
            pkgName.includes('dsh-m') ||
            pkgName.includes('ops') ||
            pkgName.includes('manager') ||
            pkgDesc.includes('manager') ||
            pkgDesc.includes('package')

          // If shell command concatenation is present
          const isShell = /cmd\.exe|\/bin\/(?:sh|bash)|powershell\.exe|shell\s*:\s*true/i.test(lineContent)
          const severity = isManagerOrDev ? (isShell ? 'LOW' : 'INFO') : (isShell ? 'CRITICAL' : 'HIGH')

          findings.push({
            ruleId: this.id,
            category: this.category,
            severity,
            title: isShell ? '通过 Shell 解释器执行本地命令' : '衍生子进程 (child_process)',
            description: `文件 ${file.relPath} 第 ${i + 1} 行调用了本地进程衍生命令，存在主机命令执行能力。`,
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
