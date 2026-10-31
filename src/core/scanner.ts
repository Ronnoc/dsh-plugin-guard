/**
 * DSH Plugin Guard: Core Audit Scanner Engine
 * Runs static rules over unpacked package sources and computes safety score and verdict.
 * @module dsh-plugin-vetter/core/scanner
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import type {
  AuditFinding,
  AuditReport,
  AuditVerdict,
  FileEntry,
  GuardConfig,
  GuardRule,
  RequestedPermissions,
  RuleContext,
} from './types.js'

import { credentialsRule } from './rules/credentials.js'
import { networkRule } from './rules/network.js'
import { executionRule } from './rules/execution.js'
import { privilegeRule } from './rules/privilege.js'
import { lifecycleRule } from './rules/lifecycle.js'
import { mcpRule } from './rules/mcp.js'

export const DEFAULT_RULES: GuardRule[] = [
  credentialsRule,
  networkRule,
  executionRule,
  privilegeRule,
  lifecycleRule,
  mcpRule,
]

const MAX_SCAN_BYTES = 5 * 1024 * 1024 // 5 MB per file limit
const TEXT_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
  '.json', '.yml', '.yaml', '.html', '.css',
  '.sh', '.bash', '.ps1', '.cmd', '.bat',
])

/**
 * Recursively walk the unpacked directory and collect all scanable text files.
 */
export function collectSourceFiles(dir: string, baseDir: string = dir): FileEntry[] {
  const entries: FileEntry[] = []

  let list: string[]
  try {
    list = readdirSync(dir)
  } catch {
    return entries
  }

  for (const item of list) {
    if (item === '.git' || item === 'node_modules') continue

    const fullPath = join(dir, item)
    try {
      const stat = statSync(fullPath)
      if (stat.isDirectory()) {
        entries.push(...collectSourceFiles(fullPath, baseDir))
      } else if (stat.isFile()) {
        const ext = item.slice(item.lastIndexOf('.')).toLowerCase()
        if (TEXT_EXTENSIONS.has(ext) || item.toLowerCase().includes('license') || item.toLowerCase().includes('readme')) {
          if (stat.size <= MAX_SCAN_BYTES) {
            const content = readFileSync(fullPath, 'utf-8')
            entries.push({
              relPath: relative(baseDir, fullPath).replace(/\\/g, '/'),
              absPath: fullPath,
              content,
            })
          }
        }
      }
    } catch {
      // Skip unreadable files
    }
  }

  return entries
}

/**
 * Evaluate score and verdict based on accumulated findings.
 */
export function evaluateVerdict(findings: AuditFinding[]): { verdict: AuditVerdict; score: number } {
  let score = 100
  let hasCritical = false
  let hasHigh = false

  for (const f of findings) {
    switch (f.severity) {
      case 'CRITICAL':
        score -= 40
        hasCritical = true
        break
      case 'HIGH':
        score -= 20
        hasHigh = true
        break
      case 'MEDIUM':
        score -= 10
        break
      case 'LOW':
        score -= 5
        break
    }
  }

  score = Math.max(0, Math.min(100, score))

  let verdict: AuditVerdict = 'SAFE'
  if (hasCritical || score <= 40) {
    verdict = 'DANGEROUS'
  } else if (hasHigh || score < 85) {
    verdict = 'CAUTION'
  }

  return { verdict, score }
}

/**
 * Extract declared permissions and capabilities from findings and files.
 */
export function extractPermissions(files: FileEntry[], findings: AuditFinding[]): RequestedPermissions {
  const networkHosts = new Set<string>()
  const sensitivePaths = new Set<string>()
  const mcpTools = new Set<string>()
  let subprocesses = false

  for (const f of findings) {
    if (f.category === 'network' && f.title.includes('外部网络请求:')) {
      const host = f.title.replace('发现未报备的外部网络请求:', '').trim()
      if (host) networkHosts.add(host)
    }
    if (f.category === 'credentials') {
      sensitivePaths.add(f.title)
    }
    if (f.category === 'execution') {
      subprocesses = true
    }
    if (f.category === 'mcp' && f.title.includes('MCP 工具:')) {
      const tool = f.title.split(':').pop()?.trim()
      if (tool) mcpTools.add(tool)
    }
  }

  return {
    network: Array.from(networkHosts),
    filesystem: Array.from(sensitivePaths),
    subprocesses,
    mcpTools: Array.from(mcpTools),
  }
}

/**
 * Run a full audit scan across an unpacked directory.
 */
export function auditPackageDirectory(
  spec: string,
  stageDir: string,
  tarballSha256: string,
  config: GuardConfig = {},
  rules: GuardRule[] = DEFAULT_RULES,
): AuditReport {
  const files = collectSourceFiles(stageDir)

  // Find package.json
  const pkgFile = files.find(f => f.relPath === 'package.json')
  let packageJson: Record<string, unknown> = {}
  if (pkgFile) {
    try {
      packageJson = JSON.parse(pkgFile.content)
    } catch {
      // Ignored
    }
  }

  const packageName = String(packageJson['name'] ?? spec.split('@')[0])
  const version = String(packageJson['version'] ?? 'unknown')

  const ctx: RuleContext = {
    packageJson,
    files,
    config,
  }

  const findings: AuditFinding[] = []
  for (const rule of rules) {
    try {
      const results = rule.run(ctx)
      findings.push(...results)
    } catch (err) {
      console.error(`[dsh-plugin-vetter] Error executing rule ${rule.id}:`, err)
    }
  }

  const { verdict, score } = evaluateVerdict(findings)
  const permissions = extractPermissions(files, findings)

  return {
    spec,
    packageName,
    version,
    tarballSha256,
    verdict,
    score,
    findings,
    permissions,
    stagedAt: Date.now(),
  }
}
