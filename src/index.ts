import Schema from 'schemastery'
/**
 * DSH Plugin Guard: Host-side Cordis Plugin Entrypoint
 * Registers pre-install security audits and gating routes in the DSH host web server.
 * @module dsh-plugin-guard
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import type { GuardConfig } from './core/types.js'
import { GuardInterceptor } from './host/interceptor.js'
import {
  GUARD_API_PREFIX,
  LEGACY_GUARD_PREFIX,
  handleGuardRequest,
} from './host/routes.js'

export const name = 'dsh-plugin-guard'
export const inject = ['webServer']

export const Config: Schema<GuardConfig> = Schema.object({
  strictMode: Schema.boolean().default(true).description('严格模式：发现 CRITICAL 级别威胁时自动阻断安装'),
  scanOnInstall: Schema.boolean().default(true).description('是否拦截并预审插件安装请求'),
  scanOnUpdate: Schema.boolean().default(true).description('是否拦截并预审插件更新请求'),
  allowedDomains: Schema.array(Schema.string()).default([
    'registry.npmjs.org',
    'github.com',
    'api.github.com',
    'dsh-market.com',
  ]).description('插件网络外联的合规白名单域名'),
  stagingTtlMs: Schema.number().default(300000).description('沙箱暂存区与放行凭证保留时长 (毫秒)'),
  tokenSecret: Schema.string().role('secret').description('用于签名放行 Token 的密钥 (留空自动生成)'),
})

export interface CordisWebServer {
  register(route: {
    kind: 'exact' | 'prefix'
    path: string
    handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>
  }): void
}

export interface PluginContext {
  webServer?: CordisWebServer
  logger?: {
    info(msg: string, ...args: unknown[]): void
    warn(msg: string, ...args: unknown[]): void
    error(msg: string, ...args: unknown[]): void
  }
  on?(event: string, listener: (...args: unknown[]) => void): void
}

/**
 * Mount the host-side Cordis plugin.
 */
export function apply(ctx: PluginContext, config: GuardConfig = {}): void {
  const interceptor = new GuardInterceptor(config)
  const webServer = ctx.webServer

  if (!webServer) {
    ctx.logger?.warn?.('[dsh-plugin-guard] webServer service not found in Cordis context. Guard routes cannot be bound.')
    return
  }

  ctx.logger?.info?.('[dsh-plugin-guard] Initializing security guard and route gates...')

  // Register modern prefix: /api/plugin-guard
  webServer.register({
    kind: 'prefix',
    path: GUARD_API_PREFIX,
    handler: async (req, res) => {
      await handleGuardRequest(req, res, { interceptor })
    },
  })

  // Register legacy compatibility prefix: /gateway/guard
  webServer.register({
    kind: 'prefix',
    path: LEGACY_GUARD_PREFIX,
    handler: async (req, res) => {
      await handleGuardRequest(req, res, { interceptor })
    },
  })

  // Cleanup on context dispose
  if (typeof ctx.on === 'function') {
    ctx.on('dispose', () => {
      void interceptor.dispose()
    })
  }
}

export default { name, inject, Config, apply }

// Re-export core capabilities for programmatic usage
export * from './core/types.js'
export * from './core/stager.js'
export * from './core/scanner.js'
export * from './host/token.js'
export * from './host/interceptor.js'
export * from './host/routes.js'
