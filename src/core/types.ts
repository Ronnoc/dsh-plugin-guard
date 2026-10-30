/**
 * DSH Plugin Guard: Types & Schema Definitions
 * @module dsh-plugin-guard/core/types
 */

export type AuditSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export type AuditVerdict = 'SAFE' | 'CAUTION' | 'DANGEROUS'

export type RuleCategory =
  | 'credentials'
  | 'network'
  | 'execution'
  | 'privilege'
  | 'mcp'
  | 'lifecycle'

export interface AuditFinding {
  /** Unique rule identifier, e.g. 'SEC-CRED-001' */
  ruleId: string
  /** Broad vulnerability category */
  category: RuleCategory
  /** Severity level */
  severity: AuditSeverity
  /** Short human-readable title */
  title: string
  /** Detailed description of why this is a risk */
  description: string
  /** File path relative to package root */
  file: string
  /** Line number if detectable */
  line?: number
  /** Code snippet surrounding the detection */
  codeSnippet?: string
}

export interface RequestedPermissions {
  /** External endpoints/domains discovered in package */
  network: string[]
  /** Sensitive filesystem paths touched */
  filesystem: string[]
  /** Whether native subprocess spawning was found */
  subprocesses: boolean
  /** MCP tools exported by this plugin */
  mcpTools: string[]
}

export interface AuditReport {
  /** The requested install spec (e.g. 'foo@1.0.0') */
  spec: string
  /** Package name declared in package.json */
  packageName: string
  /** Package version */
  version: string
  /** SHA-256 digest of the downloaded tarball */
  tarballSha256: string
  /** Overall risk assessment verdict */
  verdict: AuditVerdict
  /** Security score from 0 (malicious) to 100 (clean) */
  score: number
  /** Individual security findings */
  findings: AuditFinding[]
  /** Extracted permissions declared or inferred */
  permissions: RequestedPermissions
  /** Timestamp when staged (epoch ms) */
  stagedAt: number
  /** Ephemeral single-use approval token if deemed eligible */
  auditToken?: string
  /** Error message if staging or scanning encountered an issue */
  error?: string
  /** Model or engine identifier used for this audit */
  model?: string
  /** Version of dsh-plugin-guard that conducted this audit */
  pluginGuardVersion?: string
  /** Whether this report was served from local persistent cache */
  cached?: boolean
  /** Unique composite cache key hash if cached */
  cacheKey?: string
  /** Agent concise summary / review rationale */
  agentSummary?: string
  /** Agent review of intent alignment (how code matches declared plugin purpose) */
  intentAnalysis?: string
  /** Agent explicit recommendation: 'APPROVE' | 'REVIEW_CAREFULLY' | 'REJECT' */
  recommendation?: 'APPROVE' | 'REVIEW_CAREFULLY' | 'REJECT'
  /** Standards evaluated by the Agent */
  evaluatedStandards?: string[]
}

export interface GuardConfig {
  /** If true, CRITICAL severity findings block installation completely */
  strictMode?: boolean
  /** Whether to intercept install operations */
  scanOnInstall?: boolean
  /** Whether to intercept update operations */
  scanOnUpdate?: boolean
  /** Explicit domain allowlist for network requests */
  allowedDomains?: string[]
  /** Staging folder time-to-live in ms */
  stagingTtlMs?: number
  /** Secret key used to sign and verify approval tokens */
  tokenSecret?: string
  /** Directory for persistent audit cache. Defaults to ~/.dsh/cache/plugin-guard */
  cacheDir?: string
  /** Whether persistent local disk caching is enabled (default: true) */
  enableCache?: boolean
  /** Default audit model identifier (default: 'static') */
  model?: string
}

export interface AuditCacheKey {
  /** AI Model or security engine identifier, e.g. 'static', 'deepseek-chat', 'deepseek-reasoner' */
  model: string
  /** Version of dsh-plugin-guard that performed the audit, e.g. '0.1.0' */
  pluginGuardVersion: string
  /** Plugin package name or spec, e.g. 'dsh-plugin-foo' or 'dsh-plugin-foo@1.0.0' */
  plugin: string
  /** SHA-256 digest of the pristine tarball */
  tarballSha256: string
}

export interface AuditCacheEntry {
  key: AuditCacheKey
  report: AuditReport
  metadata: {
    createdAt: number
    accessedAt: number
    hitCount: number
    scanDurationMs?: number
    cachedBy: string
  }
}

export interface AuditCacheStats {
  totalEntries: number
  totalHits: number
  cacheDir: string
}

export interface AuditOptions {
  /** Model or engine identifier to evaluate against (defaults to config.model or 'static') */
  model?: string
  /** Bypass and refresh local persistent cache */
  forceRefresh?: boolean
  /** Skip checking or writing to persistent cache */
  noCache?: boolean
  /** Host context offering ctx.llm and ctx.agentDefaultModel */
  hostContext?: any
}

export interface FileEntry {
  /** Relative path from package root (e.g. 'src/index.ts') */
  relPath: string
  /** Absolute path on disk in temporary staging */
  absPath: string
  /** File contents as string */
  content: string
}

export interface RuleContext {
  /** Package.json object of the scanned package */
  packageJson: Record<string, unknown>
  /** All text files extracted from the package */
  files: FileEntry[]
  /** Guard runtime configuration */
  config: GuardConfig
}

export interface GuardRule {
  id: string
  name: string
  category: RuleCategory
  description: string
  run(ctx: RuleContext): AuditFinding[]
}
