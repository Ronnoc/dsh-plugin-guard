import { describe, expect, it } from 'vitest'
import { evaluateVerdict, extractPermissions } from '../src/core/scanner.js'
import type { AuditFinding, FileEntry } from '../src/core/types.js'

describe('Scanner Engine & Verdict Evaluation', () => {
  it('assigns SAFE verdict and 100 score when no findings exist', () => {
    const findings: AuditFinding[] = []
    const result = evaluateVerdict(findings)
    expect(result.score).toBe(100)
    expect(result.verdict).toBe('SAFE')
  })

  it('assigns CAUTION verdict when finding has HIGH severity', () => {
    const findings: AuditFinding[] = [
      {
        ruleId: 'SEC-EXEC-001',
        category: 'execution',
        severity: 'HIGH',
        title: 'Child process execution detected',
        description: '...',
        file: 'index.js',
      },
    ]
    const result = evaluateVerdict(findings)
    expect(result.score).toBe(80)
    expect(result.verdict).toBe('CAUTION')
  })

  it('assigns DANGEROUS verdict when finding has CRITICAL severity', () => {
    const findings: AuditFinding[] = [
      {
        ruleId: 'SEC-CRED-001',
        category: 'credentials',
        severity: 'CRITICAL',
        title: 'Unauthorized SSH key access',
        description: '...',
        file: 'stealer.js',
      },
    ]
    const result = evaluateVerdict(findings)
    expect(result.score).toBe(60)
    expect(result.verdict).toBe('DANGEROUS')
  })

  it('extracts requested permissions correctly', () => {
    const files: FileEntry[] = []
    const findings: AuditFinding[] = [
      {
        ruleId: 'SEC-NET-001',
        category: 'network',
        severity: 'MEDIUM',
        title: '发现未报备的外部网络请求: api.analytics.io',
        description: '',
        file: 'telemetry.js',
      },
      {
        ruleId: 'SEC-EXEC-001',
        category: 'execution',
        severity: 'HIGH',
        title: '使用 child_process 派生子进程',
        description: '',
        file: 'exec.js',
      },
      {
        ruleId: 'SEC-MCP-001',
        category: 'mcp',
        severity: 'MEDIUM',
        title: '发现声明的 MCP 工具: system_command_runner',
        description: '',
        file: 'tools.js',
      },
    ]

    const permissions = extractPermissions(files, findings)
    expect(permissions.network).toContain('api.analytics.io')
    expect(permissions.subprocesses).toBe(true)
    expect(permissions.mcpTools).toContain('system_command_runner')
  })
})
