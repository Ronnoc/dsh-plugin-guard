/**
 * DSH Plugin Guard: Host HTTP Route Handlers & Interception Middleware
 * Intercepts /api/plugin-manager/install and exposes /api/plugin-guard audit APIs.
 * @module dsh-plugin-guard/host/routes
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import { URL } from 'node:url'
import type { GuardInterceptor } from './interceptor.js'
import { GUARD_API_PREFIX, LEGACY_GUARD_PREFIX } from '../core/constants.js'

export { GUARD_API_PREFIX, LEGACY_GUARD_PREFIX }

export const INTERCEPT_INSTALL_PATHS = new Set([
  '/api/plugin-manager/install',
  '/gateway/install',
  '/api/plugin-manager/update',
  '/gateway/update',
])

export async function readJsonBody<T = Record<string, unknown>>(
  req: IncomingMessage,
  maxBytes: number = 64 * 1024,
): Promise<T | null> {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks: Buffer[] = []

    req.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > maxBytes) {
        req.destroy()
        reject(new Error(`Payload exceeds maximum allowed size of ${maxBytes} bytes`))
        return
      }
      chunks.push(chunk)
    })

    req.on('end', () => {
      if (chunks.length === 0) {
        resolve(null)
        return
      }
      try {
        const text = Buffer.concat(chunks).toString('utf-8')
        resolve(JSON.parse(text) as T)
      } catch (err) {
        reject(err)
      }
    })

    req.on('error', reject)
  })
}

export function writeJson(res: ServerResponse, status: number, data: unknown): void {
  const content = JSON.stringify(data)
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(content),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Audit-Token',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  })
  res.end(content)
}

export interface GuardRouteOptions {
  interceptor: GuardInterceptor
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

    if (req.method === 'GET') {
      spec = parsed.searchParams.get('spec') ?? undefined
    } else if (req.method === 'POST') {
      const body = (await readJsonBody(req).catch(() => null)) as Record<string, unknown> | null
      spec = typeof body?.['spec'] === 'string' ? body['spec'] : undefined
    }

    if (!spec || !spec.trim()) {
      writeJson(res, 400, { error: '缺少 spec 参数 (例如: foo@1.0.0)' })
      return true
    }

    try {
      const report = await interceptor.audit(spec)
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

    if (!spec || !spec.trim()) {
      writeJson(res, 400, { error: '缺少 spec 参数' })
      return true
    }

    try {
      const result = await interceptor.approve(spec, { force })
      writeJson(res, 200, { ok: true, ...result })
    } catch (err) {
      writeJson(res, 403, {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      })
    }
    return true
  }

  // 3. Intercept Install Gate: POST /api/plugin-manager/install or /gateway/install
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
