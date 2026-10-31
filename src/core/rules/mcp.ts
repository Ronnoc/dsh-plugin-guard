/**
 * Rule: MCP Tools & Capability Exposure Guard
 * Analyzes whether the plugin exports MCP tools and whether they expose high-risk destructive commands.
 * @module dsh-plugin-vetter/core/rules/mcp
 */

import type { AuditFinding, GuardRule, RuleContext } from '../types.js'

export const mcpRule: GuardRule = {
  id: 'SEC-MCP-001',
  name: 'MCP Tool Capability & Exposure Guard',
  category: 'mcp',
  description: 'Audits declared Model Context Protocol tools to identify destructive operations (write, delete, shell).',

  run(ctx: RuleContext): AuditFinding[] {
    const findings: AuditFinding[] = []

    for (const file of ctx.files) {
      if (file.relPath.endsWith('.md')) continue

      const lines = file.content.split('\n')

      for (let i = 0; i < lines.length; i++) {
        const lineContent = lines[i]

        // Pattern 1: registerTool('foo') / defineTool('foo') / tools.register('foo')
        let match = /(?:registerTool|addTool|defineTool|mcp.*tool|tools?\.register)\s*\(\s*['"]([a-zA-Z0-9_-]+)['"]/i.exec(lineContent)

        // Pattern 2: defineTool({ name: 'foo' }) or name: 'execute_remote_command'
        if (!match) {
          match = /(?:name\s*:\s*['"]([a-zA-Z0-9_-]+)['"])/i.exec(lineContent)
          // Ensure it's in a tooling context (check adjacent lines or file path)
          if (match && !/tool|mcp|command|action/i.test(file.relPath) && !file.content.includes('Tool') && !file.content.includes('defineTool')) {
            match = null
          }
        }

        if (match) {
          const toolName = match[1]

          if (/bash|exec|sh|cmd|shell|run_command|remote_command|eval/i.test(toolName)) {
            findings.push({
              ruleId: this.id,
              category: this.category,
              severity: 'HIGH',
              title: `注册了具备命令执行能力的 MCP 工具: ${toolName}`,
              description: `插件在文件 ${file.relPath} 第 ${i + 1} 行向 Agent 暴露了命令执行类 MCP 工具，需确认其参数校验与权限门禁。`,
              file: file.relPath,
              line: i + 1,
              codeSnippet: lineContent.trim().slice(0, 160),
            })
          } else if (/delete|remove|rmdir|unlink|drop|truncate/i.test(toolName)) {
            findings.push({
              ruleId: this.id,
              category: this.category,
              severity: 'MEDIUM',
              title: `注册了具备破坏性删除能力的 MCP 工具: ${toolName}`,
              description: `插件在文件 ${file.relPath} 第 ${i + 1} 行向 Agent 暴露了文件或资源删除类 MCP 工具。`,
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
