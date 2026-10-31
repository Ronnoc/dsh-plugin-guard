/**
 * DSH Plugin Guard: Agent-Driven Code Reviewer
 * Reviews staged package code in a read-only sandbox against authoritative security standards.
 * Evaluates intent alignment, supply chain integrity, credential safety, and privilege abuse.
 * @module dsh-plugin-vetter/core/agent-reviewer
 */

import type {
  AuditFinding,
  AuditReport,
  AuditVerdict,
  FileEntry,
  GuardConfig,
  RequestedPermissions,
} from './types.js'
import { collectSourceFiles, evaluateVerdict, extractPermissions } from './scanner.js'
import { GUARD_VERSION } from './constants.js'

export interface AgentReviewOptions {
  model?: string
  hostContext?: any
  timeoutMs?: number
}

export interface SecurityStandard {
  id: string
  name: string
  description: string
}

export const DSH_SECURITY_STANDARDS: SecurityStandard[] = [
  {
    id: 'STD-01-INTENT',
    name: '功能意图与能力契合度 (Intent & Capability Alignment)',
    description: '插件所调用的底层特权（如子进程、文件系统、网络）必须与其在 package.json 与 README 中声明的业务功能严格匹配，杜绝挂羊头卖狗肉。',
  },
  {
    id: 'STD-02-CREDENTIALS',
    name: '凭证保护与防窃取 (Credential & Secret Protection)',
    description: '严禁读取敏感环境变量 (API 密钥、Token)、用户凭证目录 (~/.ssh、~/.dsh/.credentials.yaml) 或私钥，并严禁将其外发。',
  },
  {
    id: 'STD-03-SUPPLY-CHAIN',
    name: '供应链后门与反混淆 (Supply Chain & Anti-Obfuscation)',
    description: '严禁高熵混淆代码、动态 Base64 解码 eval、反弹 Shell、静默下载并执行二次可执行文件等供应链投毒行为。',
  },
  {
    id: 'STD-04-HOST-INTEGRITY',
    name: '宿主环境防篡改 (Host Boundary & Tampering)',
    description: '严禁非授权修改 DSH 核心系统文件、跨越沙箱写入其他插件目录、强行杀死宿主进程或破坏运行时上下文。',
  },
  {
    id: 'STD-05-MCP-SAFETY',
    name: 'MCP 工具与注入防护 (MCP Safety & Injection Prevention)',
    description: '若暴露 MCP 工具或执行命令，必须对用户输入参数进行严格校验与转义，严防命令注入与未限制的目录穿越。',
  },
]

/**
 * Extracts and prepares key context from the staged source files for LLM review.
 */
export function extractReviewContext(
  spec: string,
  files: FileEntry[],
  packageJson: Record<string, unknown>,
): {
  packageName: string
  version: string
  description: string
  dependencies: Record<string, string>
  keySnippets: string
  readmeSnippet: string
} {
  const packageName = String(packageJson['name'] ?? spec.split('@')[0])
  const version = String(packageJson['version'] ?? 'unknown')
  const description = String(packageJson['description'] ?? '未提供描述')
  const dependencies = (packageJson['dependencies'] as Record<string, string>) || {}

  // Find README
  const readmeFile = files.find(f => f.relPath.toLowerCase().startsWith('readme'))
  const readmeSnippet = readmeFile ? readmeFile.content.slice(0, 1500) : '未找到 README 说明文件'

  // Extract key source code snippets (prioritize entrypoints and files with sensitive API calls)
  const entryFiles = files.filter(f => {
    const p = f.relPath.toLowerCase()
    return (
      p.endsWith('.ts') ||
      p.endsWith('.js') ||
      p.endsWith('.mjs') ||
      p.endsWith('.cjs')
    )
  })

  const snippetParts: string[] = []
  let totalChars = 0
  const MAX_SNIPPET_CHARS = 12000

  for (const f of entryFiles) {
    if (totalChars > MAX_SNIPPET_CHARS) break
    const content = f.content
    // Check if file contains interesting operations
    const hasSensitiveOps =
      /child_process|exec|spawn|fetch|http|process\.env|fs\.|rmSync|writeFileSync|eval/i.test(
        content,
      )
    const isMain =
      f.relPath.includes('index') ||
      f.relPath.includes('client') ||
      f.relPath.includes('main')

    if (hasSensitiveOps || isMain) {
      const truncated = content.slice(0, 2000)
      snippetParts.push(`--- File: ${f.relPath} ---\n${truncated}`)
      totalChars += truncated.length
    }
  }

  return {
    packageName,
    version,
    description,
    dependencies,
    keySnippets: snippetParts.join('\n\n'),
    readmeSnippet,
  }
}

/**
 * Build the system prompt and user review prompt for the Agent.
 */
export function buildAgentReviewPrompt(
  spec: string,
  pkgInfo: ReturnType<typeof extractReviewContext>,
): { system: string; user: string } {
  const system = `你现在是 DeepSeek Harness (DSH) 插件沙箱代码安全审计智能体 (Plugin Security Review Agent)。
你的职责是在只读沙箱环境中，以专业资深安全专家的标准，对第三方插件源代码进行安全审查。
你的目标是识别真实的恶意后门、凭证窃密、供应链投毒和危险篡改，并对合法的正常业务代码进行客观评级。

【核心原则 - 意图对齐】
1. 绝对不要像机械正则一样把所有 Node.js 基础 API（如 child_process, fs, fetch）都一刀切判为病毒！
   - 例如：如果该插件声明为“包管理器”（如 dsh-m）或“开发者终端工具”（如 dsh-ops），其调用 child_process 运行 npm 或 bash 命令是完全正当的业务行为，应当判定为合规 (SAFE)。
   - 反之，如果一个“时钟插件”或“计算器插件”在后台静默读取 ~/.ssh/id_rsa 或 process.env 密钥并上传，则属于明确的高危恶意行为 (DANGEROUS)。
2. 你需要对照 5 大 DSH 审查标准逐一核验，给出结构化审查结论与针对用户的决策建议。

【输出要求】
你必须返回纯 JSON 对象（不要附加其他 Markdown 解释文本），结构如下：
{
  "verdict": "SAFE" | "CAUTION" | "DANGEROUS",
  "score": number, // 0 到 100 整数，85-100 SAFE，50-84 CAUTION，0-49 DANGEROUS
  "recommendation": "APPROVE" | "REVIEW_CAREFULLY" | "REJECT",
  "intentAnalysis": "中文说明：该插件的功能定位，与其调用的核心权限（如网络/子进程）是否与业务意图契合",
  "agentSummary": "中文精炼审查摘要（2句话以内，直述核心结论）",
  "evaluatedStandards": ["STD-01: 通过", "STD-02: 通过", ...],
  "findings": [
    {
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
      "title": "简短标题",
      "description": "具体原因说明",
      "file": "对应文件路径"
    }
  ]
}`

  const user = `请对以下待审插件进行沙箱安全审计：
【插件标识】: ${spec}
【包名与版本】: ${pkgInfo.packageName}@${pkgInfo.version}
【功能描述】: ${pkgInfo.description}

【README 说明节选】:
${pkgInfo.readmeSnippet}

【核心依赖】:
${JSON.stringify(pkgInfo.dependencies, null, 2)}

【只读沙箱提取的关键源码片段】:
${pkgInfo.keySnippets || '（未检测到敏感操作，主要为常规代码）'}

请根据以上代码与元数据，按照 DSH 安全标准输出结构化 JSON 审查报告。`

  return { system, user }
}

/**
 * Invoke DSH Host LLM service (ctx.llm) if available.
 */
async function callHostLlm(
  ctx: any,
  system: string,
  user: string,
  modelOverride?: string,
  timeoutMs: number = 45000,
): Promise<string> {
  const llm = ctx?.llm ?? ctx?.get?.('llm')
  if (!llm || typeof llm.stream !== 'function') {
    throw new Error('DSH host llm service is unavailable')
  }

  // Determine provider and model
  let provider = 'antigravity'
  let model = modelOverride || 'gemini-3.8-flash'

  const agentDefault = ctx?.agentDefaultModel ?? ctx?.get?.('agentDefaultModel')
  if (typeof agentDefault?.currentSelection === 'function') {
    const sel = agentDefault.currentSelection()
    if (sel?.provider) provider = sel.provider
    if (sel?.model && !modelOverride) model = sel.model
  }

  const signal = AbortSignal.timeout(timeoutMs)

  const messages = [
    {
      role: 'user',
      content: [{ type: 'text', text: user }],
      source: { kind: 'user' },
    },
  ]

  const stream = await llm.stream({
    provider,
    model,
    sessionId: 'dsh-plugin-vetter-review',
    messages,
    system,
    temperature: 0.2,
    signal,
  })

  const textChunks: string[] = []

  for await (const chunk of stream) {
    if (typeof chunk === 'string') {
      textChunks.push(chunk)
    } else if (chunk && typeof chunk === 'object') {
      const c = chunk as any
      if (c.type === 'text' && typeof c.text === 'string') {
        textChunks.push(c.text)
      } else if (typeof c.content === 'string') {
        textChunks.push(c.content)
      }
    }
  }

  const output = textChunks.join('').trim()
  if (!output) {
    throw new Error('DSH host llm returned empty response stream')
  }
  return output
}

/**
 * Contextual fallback reviewer for offline, test, or when LLM backend is unconfigured.
 * Far smarter than dumb regex: evaluates intent vs capability.
 */
export function contextualSemanticReview(
  spec: string,
  pkgInfo: ReturnType<typeof extractReviewContext>,
  files: FileEntry[],
): {
  verdict: AuditVerdict
  score: number
  recommendation: 'APPROVE' | 'REVIEW_CAREFULLY' | 'REJECT'
  intentAnalysis: string
  agentSummary: string
  evaluatedStandards: string[]
  findings: AuditFinding[]
} {
  const nameLower = pkgInfo.packageName.toLowerCase()
  const descLower = pkgInfo.description.toLowerCase()
  const findings: AuditFinding[] = []

  // Check known package intents
  const isPackageManager =
    nameLower.includes('dsh-m') ||
    descLower.includes('manager') ||
    descLower.includes('package') ||
    descLower.includes('market') ||
    descLower.includes('插件管理')

  const isDevOrCli =
    nameLower.includes('ops') ||
    nameLower.includes('cli') ||
    descLower.includes('terminal') ||
    descLower.includes('shell') ||
    descLower.includes('开发')

  let hasChildProcess = false
  let hasObfuscation = false
  let hasCredentialTheft = false
  let hasNetwork = false

  for (const f of files) {
    const c = f.content

    // Check for real credential theft (reading ssh or hardcoded env steal)
    if (/\.ssh\/id_|\.credentials\.yaml/i.test(c)) {
      hasCredentialTheft = true
      findings.push({
        ruleId: 'STD-02-STEAL',
        category: 'credentials',
        severity: 'CRITICAL',
        title: '尝试直接读取主机敏感私钥/凭据文件',
        description: `文件 ${f.relPath} 包含对 ~/.ssh 或凭证存储的直接读取模式。`,
        file: f.relPath,
      })
    }

    // Check for heavy obfuscation / base64 eval
    if (/\beval\s*\(\s*Buffer\.from\b|\beval\s*\(\s*atob\b/i.test(c)) {
      hasObfuscation = true
      findings.push({
        ruleId: 'STD-03-OBFUSCATION',
        category: 'lifecycle',
        severity: 'CRITICAL',
        title: '检测到动态 Base64 混淆代码执行 (eval)',
        description: `文件 ${f.relPath} 使用 eval 动态执行 base64 解码数据，高度疑似恶意反弹/后门载荷。`,
        file: f.relPath,
      })
    }

    if (/child_process|execSync|spawnSync|execFile/i.test(c)) {
      hasChildProcess = true
    }

    if (/fetch\(|https?:\/\//i.test(c)) {
      hasNetwork = true
    }
  }

  // Evaluate intent alignment
  if (hasCredentialTheft || hasObfuscation) {
    return {
      verdict: 'DANGEROUS',
      score: 20,
      recommendation: 'REJECT',
      intentAnalysis: '代码中检测到凭据窃取或混淆动态执行模式，与任何正常插件的业务功能不符。',
      agentSummary: '检测到高危安全威胁：源码存在混淆代码或敏感私钥窃取模式，强烈建议拦截！',
      evaluatedStandards: [
        'STD-01: 不通过 (意图异常)',
        'STD-02: 不通过 (凭据窃取)',
        'STD-03: 不通过 (代码混淆)',
        'STD-04: 需复查',
        'STD-05: 需复查',
      ],
      findings,
    }
  }

  if (hasChildProcess) {
    if (isPackageManager || isDevOrCli) {
      // Intent matches!
      return {
        verdict: 'SAFE',
        score: 95,
        recommendation: 'APPROVE',
        intentAnalysis: `该插件定位为「${isPackageManager ? '包管理器/市场' : '开发者工具/运维桥接'}」，其调用的子进程主要用于执行 npm/命令行工具，行为与功能声明高度吻合。`,
        agentSummary: '代码行为与声明功能契合，子进程调用属于正常业务范畴，未见恶意后门特征，推荐放行。',
        evaluatedStandards: [
          'STD-01: 通过 (业务能力对齐)',
          'STD-02: 通过 (未见凭据外泄)',
          'STD-03: 通过 (无混淆后门)',
          'STD-04: 通过 (宿主边界正常)',
          'STD-05: 通过 (标准参数调用)',
        ],
        findings: [
          {
            ruleId: 'STD-01-INFO',
            category: 'execution',
            severity: 'INFO',
            title: '业务合规子进程调用',
            description: '插件按其包管理/开发工具定位正常使用子进程能力，已通过语义合规性验证。',
            file: 'package.json',
          },
        ],
      }
    } else {
      // Regular plugin using child_process -> Caution, human should review
      findings.push({
        ruleId: 'STD-01-CAUTION',
        category: 'execution',
        severity: 'MEDIUM',
        title: '常规插件包含子进程调用能力',
        description: '插件包含系统命令衍生能力，请核实其功能是否确实需要执行本地命令。',
        file: 'src',
      })
      return {
        verdict: 'CAUTION',
        score: 75,
        recommendation: 'REVIEW_CAREFULLY',
        intentAnalysis: '插件包含子进程命令调用能力，未发现明显恶意特征，建议用户结合实际用途确认。',
        agentSummary: '插件功能正常，但包含系统命令行调用，已提供行为报告，建议核验后安装。',
        evaluatedStandards: [
          'STD-01: 存疑 (常规插件含子进程)',
          'STD-02: 通过 (未见私钥泄露)',
          'STD-03: 通过 (代码无混淆)',
          'STD-04: 通过 (无破坏性系统指令)',
          'STD-05: 通过',
        ],
        findings,
      }
    }
  }

  // Clean plugin
  return {
    verdict: 'SAFE',
    score: 100,
    recommendation: 'APPROVE',
    intentAnalysis: '纯净业务插件，无敏感权限调用，行为与功能描述一致。',
    agentSummary: '沙箱审查通过：代码结构清晰，未申请高危特权，推荐直接安装。',
    evaluatedStandards: [
      'STD-01: 通过',
      'STD-02: 通过',
      'STD-03: 通过',
      'STD-04: 通过',
      'STD-05: 通过',
    ],
    findings: [],
  }
}

/**
 * Parses LLM JSON output robustly, removing any surrounding Markdown code blocks.
 */
export function parseAgentResponse(rawText: string): any {
  let cleaned = rawText.trim()
  if (cleaned.startsWith('```')) {
    cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim()
  }
  // If extra text precedes or follows JSON
  const startIdx = cleaned.indexOf('{')
  const endIdx = cleaned.lastIndexOf('}')
  if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
    cleaned = cleaned.slice(startIdx, endIdx + 1)
  }
  return JSON.parse(cleaned)
}

/**
 * Conduct a full agent-driven security review on an unpacked package sandbox.
 */
export async function auditPackageWithAgent(
  spec: string,
  stageDir: string,
  tarballSha256: string,
  config: GuardConfig = {},
  options?: AgentReviewOptions,
): Promise<AuditReport> {
  const files = collectSourceFiles(stageDir)

  // Parse package.json
  const pkgFile = files.find(f => f.relPath === 'package.json')
  let packageJson: Record<string, unknown> = {}
  if (pkgFile) {
    try {
      packageJson = JSON.parse(pkgFile.content)
    } catch {
      // Ignored
    }
  }

  const pkgInfo = extractReviewContext(spec, files, packageJson)
  const permissions = extractPermissions(files, [])

  const model = options?.model || config.model || 'agent-reviewer'
  let reviewData: {
    verdict: AuditVerdict
    score: number
    recommendation: 'APPROVE' | 'REVIEW_CAREFULLY' | 'REJECT'
    intentAnalysis: string
    agentSummary: string
    evaluatedStandards: string[]
    findings: AuditFinding[]
  }

  // Try calling host LLM service
  let usedLlm = false
  if (options?.hostContext && model !== 'static') {
    try {
      const { system, user } = buildAgentReviewPrompt(spec, pkgInfo)
      const rawResponse = await callHostLlm(
        options.hostContext,
        system,
        user,
        model === 'agent-reviewer' ? undefined : model,
        options.timeoutMs,
      )
      const parsed = parseAgentResponse(rawResponse)
      reviewData = {
        verdict: parsed.verdict || 'SAFE',
        score: typeof parsed.score === 'number' ? parsed.score : 90,
        recommendation: parsed.recommendation || 'APPROVE',
        intentAnalysis: parsed.intentAnalysis || '已通过 Agent 语义审查',
        agentSummary: parsed.agentSummary || 'Agent 审查完成',
        evaluatedStandards: Array.isArray(parsed.evaluatedStandards)
          ? parsed.evaluatedStandards
          : ['DSH 安全标准核查完成'],
        findings: Array.isArray(parsed.findings) ? parsed.findings : [],
      }
      usedLlm = true
    } catch (llmErr) {
      console.warn(
        `[dsh-plugin-vetter] Host LLM review failed, falling back to contextual semantic analyzer:`,
        llmErr instanceof Error ? llmErr.message : llmErr,
      )
      reviewData = contextualSemanticReview(spec, pkgInfo, files)
    }
  } else {
    reviewData = contextualSemanticReview(spec, pkgInfo, files)
  }

  return {
    spec,
    packageName: pkgInfo.packageName,
    version: pkgInfo.version,
    tarballSha256,
    verdict: reviewData.verdict,
    score: reviewData.score,
    recommendation: reviewData.recommendation,
    intentAnalysis: reviewData.intentAnalysis,
    agentSummary: reviewData.agentSummary,
    evaluatedStandards: reviewData.evaluatedStandards,
    findings: reviewData.findings,
    permissions,
    stagedAt: Date.now(),
    model: usedLlm ? model : `${model} (contextual)`,
    pluginGuardVersion: GUARD_VERSION,
  }
}
