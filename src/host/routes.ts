import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { GUARD_API_PREFIX, LEGACY_GUARD_PREFIX } from '../core/constants.js'

export { GUARD_API_PREFIX, LEGACY_GUARD_PREFIX }
import type { GuardConfig } from '../core/types.js'
import type { GuardInterceptor } from './interceptor.js'

/**
 * DSH Plugin Guard: Host HTTP Route Handlers & Interception Middleware
 * Intercepts /api/plugin-manager/install and exposes /api/plugin-guard audit APIs.
 * @module dsh-plugin-guard/host/routes
 */

export const INTERCEPT_INSTALL_PATHS = new Set([
  '/api/plugin-manager/install',
  '/gateway/install',
  '/api/plugins/install',
])

function writeJson(
  res: ServerResponse,
  statusCode: number,
  data: Record<string, unknown>,
): void {
  const payload = Buffer.from(JSON.stringify(data), 'utf-8')
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': payload.length,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, DELETE',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-audit-token',
  })
  res.end(payload)
}

function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0

    req.on('data', (chunk: Buffer) => {
      chunks.push(chunk)
      size += chunk.length
      if (size > 1024 * 1024) {
        reject(new Error('Payload too large'))
      }
    })

    req.on('end', () => {
      try {
        const bodyStr = Buffer.concat(chunks).toString('utf-8')
        if (!bodyStr.trim()) {
          resolve({})
          return
        }
        resolve(JSON.parse(bodyStr) as Record<string, unknown>)
      } catch (err) {
        reject(err)
      }
    })

    req.on('error', reject)
  })
}

export interface GuardRouteOptions {
  interceptor: GuardInterceptor
}

function syncPatchFile(config: GuardConfig): void {
  try {
    const candidatePaths = [
      join(homedir(), '.dsh', 'profiles', 'desktop', 'cordis.patch.yml'),
      process.env.DSH_HOME ? join(process.env.DSH_HOME, 'profiles', 'desktop', 'cordis.patch.yml') : '',
    ].filter(Boolean)

    for (const patchPath of candidatePaths) {
      if (existsSync(patchPath)) {
        const content = readFileSync(patchPath, 'utf-8')
        const blockRegex = /- id: (["']?)dsh-plugin-guard\1[\s\S]*?(?=\n- id:|\n- insert:|$)/
        const newBlock = `- id: dsh-plugin-guard
  name: "dsh-plugin-guard"
  config:
    strictMode: ${config.strictMode ?? true}
    scanOnInstall: ${config.scanOnInstall ?? true}
    scanOnUpdate: ${config.scanOnUpdate ?? true}
    enableCache: ${config.enableCache ?? true}
    model: "${config.model ?? 'static'}"
    stagingTtlMs: ${config.stagingTtlMs ?? 300000}
    allowedDomains:
${(config.allowedDomains ?? ['registry.npmjs.org', 'github.com', 'api.github.com', 'dsh-market.com']).map((d) => `      - "${d}"`).join('\n')}`

        if (content.includes('id: dsh-plugin-guard') && blockRegex.test(content)) {
          writeFileSync(patchPath, content.replace(blockRegex, newBlock), 'utf-8')
        } else {
          const appendBlock = `\n${newBlock}\n`
          writeFileSync(patchPath, content.trimEnd() + '\n' + appendBlock, 'utf-8')
        }
        break
      }
    }
  } catch (err) {
    console.warn('[dsh-plugin-guard] Failed to sync config to cordis.patch.yml:', err)
  }
}

/**
 * Handles incoming HTTP requests for plugin guard and intercepts plugin installations.
 * Returns true if request was handled, false if caller should continue next route.
 */
export async function handleGuardRequest(
  req: IncomingMessage,
  res: ServerResponse,
  options: GuardRouteOptions,
): Promise<boolean> {
  const { interceptor } = options
  const rawUrl = req.url ?? '/'
  const parsed = new URL(rawUrl, 'http://localhost')
  const pathname = parsed.pathname

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    writeJson(res, 204, {})
    return true
  }

  // 1. Audit Endpoint: GET or POST /api/plugin-guard/audit or /gateway/guard/audit
  if (pathname === `${GUARD_API_PREFIX}/audit` || pathname === `${LEGACY_GUARD_PREFIX}/audit`) {
    let spec: string | undefined
    let model: string | undefined
    let forceRefresh = false
    let noCache = false

    if (req.method === 'GET') {
      spec = parsed.searchParams.get('spec') ?? undefined
      model = parsed.searchParams.get('model') ?? undefined
      forceRefresh =
        parsed.searchParams.get('forceRefresh') === 'true' ||
        parsed.searchParams.get('nocache') === 'true'
      noCache = parsed.searchParams.get('noCache') === 'true'
    } else if (req.method === 'POST') {
      const body = (await readJsonBody(req).catch(() => null)) as Record<string, unknown> | null
      spec = typeof body?.['spec'] === 'string' ? body['spec'] : undefined
      model = typeof body?.['model'] === 'string' ? body['model'] : undefined
      forceRefresh = Boolean(body?.['forceRefresh'] || body?.['nocache'])
      noCache = Boolean(body?.['noCache'])
    }

    if (!spec || !spec.trim()) {
      writeJson(res, 400, { error: '缺少 spec 参数 (例如: foo@1.0.0)' })
      return true
    }

    try {
      const report = await interceptor.audit(spec, { model, forceRefresh, noCache })
      writeJson(res, 200, { ok: true, report })
    } catch (err) {
      writeJson(res, 500, {
        ok: false,
        error: `预审失败: ${err instanceof Error ? err.message : String(err)}`,
      })
    }
    return true
  }

  // 2. Approve Endpoint: POST /api/plugin-guard/approve or /gateway/guard/approve
  if (
    (pathname === `${GUARD_API_PREFIX}/approve` || pathname === `${LEGACY_GUARD_PREFIX}/approve`) &&
    req.method === 'POST'
  ) {
    const body = (await readJsonBody(req).catch(() => null)) as Record<string, unknown> | null
    const spec = typeof body?.['spec'] === 'string' ? body['spec'] : undefined
    const force = Boolean(body?.['force'])
    const model = typeof body?.['model'] === 'string' ? body['model'] : undefined

    if (!spec || !spec.trim()) {
      writeJson(res, 400, { error: '缺少 spec 参数' })
      return true
    }

    try {
      const result = await interceptor.approve(spec, { force, model })
      writeJson(res, 200, { ok: true, ...result })
    } catch (err) {
      writeJson(res, 403, {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      })
    }
    return true
  }

  // 3. Cache Management Endpoint: /api/plugin-guard/cache or /gateway/guard/cache
  if (
    pathname === `${GUARD_API_PREFIX}/cache` ||
    pathname === `${LEGACY_GUARD_PREFIX}/cache`
  ) {
    const cacheManager = interceptor.getCacheManager()
    if (req.method === 'GET') {
      const stats = await cacheManager.getStats()
      const entries = await cacheManager.list()
      writeJson(res, 200, { ok: true, stats, entries })
      return true
    }
    if (req.method === 'DELETE') {
      const hash = parsed.searchParams.get('hash') || parsed.searchParams.get('key')
      if (hash) {
        const deleted = await cacheManager.deleteByHash(hash)
        writeJson(res, 200, { ok: true, deleted })
        return true
      }
      const cleared = await cacheManager.clear()
      writeJson(res, 200, { ok: true, cleared })
      return true
    }
  }

  if (
    pathname === `${GUARD_API_PREFIX}/cache/clear` ||
    pathname === `${LEGACY_GUARD_PREFIX}/cache/clear`
  ) {
    if (req.method === 'POST' || req.method === 'GET') {
      const cleared = await interceptor.getCacheManager().clear()
      writeJson(res, 200, { ok: true, cleared })
      return true
    }
  }

  // 4. Config Endpoint: GET or POST /api/plugin-guard/config or /gateway/guard/config
  if (
    pathname === `${GUARD_API_PREFIX}/config` ||
    pathname === `${LEGACY_GUARD_PREFIX}/config`
  ) {
    if (req.method === 'GET') {
      writeJson(res, 200, { ok: true, config: interceptor.getConfig() })
      return true
    }
    if (req.method === 'POST') {
      const body = (await readJsonBody(req).catch(() => null)) as Partial<GuardConfig> | null
      if (!body || typeof body !== 'object') {
        writeJson(res, 400, { ok: false, error: '缺少有效的 JSON 配置请求体' })
        return true
      }
      const updated = interceptor.updateConfig(body)
      syncPatchFile(updated)
      writeJson(res, 200, { ok: true, config: updated })
      return true
    }
  }

  // 5. Intercept Install Gate: POST /api/plugin-manager/install or /gateway/install
  if (INTERCEPT_INSTALL_PATHS.has(pathname) && req.method === 'POST') {
    let body: Record<string, unknown> | null = null
    try {
      body = await readJsonBody(req)
    } catch {
      // Ignored
    }

    const spec = typeof body?.['spec'] === 'string' ? body['spec'] : undefined
    const auditToken =
      (typeof body?.['auditToken'] === 'string' ? body['auditToken'] : undefined) ||
      (req.headers['x-audit-token'] as string | undefined) ||
      parsed.searchParams.get('auditToken') ||
      undefined

    if (spec) {
      const check = interceptor.validateInstallRequest(spec, auditToken)
      if (!check.allowed) {
        writeJson(res, 403, {
          ok: false,
          error: check.reason,
          requireAudit: true,
          spec,
        })
        return true
      }
    }

    // If allowed, let next middleware handle the original install
    return false
  }

  return false
}
