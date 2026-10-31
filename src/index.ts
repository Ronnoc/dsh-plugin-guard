import Schema from 'schemastery'
/**
 * DSH Plugin Guard: Host-side Cordis Plugin Entrypoint
 * Registers pre-install security audits and gating routes in the DSH host web server.
 * @module dsh-plugin-vetter
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import type { GuardConfig } from './core/types.js'
import { GuardInterceptor } from './host/interceptor.js'
import {
  GUARD_API_PREFIX,
  LEGACY_GUARD_PREFIX,
  handleGuardRequest,
  INTERCEPT_INSTALL_PATHS,
} from './host/routes.js'

export const name = 'dsh-plugin-vetter'
export const inject = ['webServer']

export const Config: Schema<GuardConfig> = Schema.object({
  strictMode: Schema.boolean().default(true).description('严格模式：发现 CRITICAL 级别威胁时自动阻断安装'),
  scanOnInstall: Schema.boolean().default(true).description('是否拦截并预审插件安装请求'),
  scanOnUpdate: Schema.boolean().default(true).description('是否拦截并预审插件更新请求'),
  enableCache: Schema.boolean().default(true).description('是否启用本地审计结果持久化缓存，避免重复扫描与 Token 消耗'),
  model: Schema.string().default('static').description('默认审计模型或引擎标识 (默认为 static 静态规则引擎)'),
  cacheDir: Schema.string().description('本地审计持久化缓存目录 (留空使用默认 ~/.dsh/cache/plugin-vetter)'),
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
  pluginManager?: any
  logger?: {
    info(msg: string, ...args: unknown[]): void
    warn(msg: string, ...args: unknown[]): void
    error(msg: string, ...args: unknown[]): void
  }
  get?(name: string): unknown
  inject?(deps: string[], callback: (ctx: any) => void): void
  on?(event: string, listener: (...args: unknown[]) => void): void
}

function parseSpecAndQuery(rawSpec: string): {
  cleanSpec: string
  tokenFromQuery?: string
  forceFromQuery?: boolean
} {
  const qIdx = rawSpec.indexOf('?')
  if (qIdx === -1) {
    return { cleanSpec: rawSpec.trim() }
  }
  const cleanSpec = rawSpec.slice(0, qIdx).trim()
  const searchParams = new URLSearchParams(rawSpec.slice(qIdx + 1))
  const tokenFromQuery = searchParams.get('auditToken') || undefined
  const forceFromQuery = searchParams.get('force') === 'true'
  return { cleanSpec, tokenFromQuery, forceFromQuery }
}

/**
 * Monkey-patches host-side pluginManager.installBundle to enforce security audits.
 */
export function hookHostPluginManager(
  pm: any,
  interceptor: GuardInterceptor,
  logger?: PluginContext['logger'],
): (() => void) | false {
  if (!pm) return false

  // If already patched by a previous instance (e.g. before hot-reloading), unhook first
  if (pm.__pluginGuardHostPatched && typeof pm.__origInstallBundle === 'function') {
    pm.installBundle = pm.__origInstallBundle
    delete pm.__origInstallBundle
    delete pm.__pluginGuardHostPatched
  }

  const origInstallBundle = pm.installBundle
  if (typeof origInstallBundle !== 'function') return false

  pm.__origInstallBundle = origInstallBundle

  const unhook = () => {
    if (pm.__origInstallBundle) {
      pm.installBundle = pm.__origInstallBundle
      delete pm.__origInstallBundle
      delete pm.__pluginGuardHostPatched
      logger?.info?.('[dsh-plugin-vetter] 宿主 pluginManager.installBundle 安全门禁已卸载/拔出。')
    }
  }

  pm.installBundle = async function (rawSpec: string, options?: any) {
    // Hot unplug: if guard is disposed, immediately bypass
    if (interceptor.isDisposed()) {
      return origInstallBundle.call(this, rawSpec, options)
    }

    const config = interceptor.getConfig()
    if (config.scanOnInstall !== false) {
      const { cleanSpec, tokenFromQuery, forceFromQuery } = parseSpecAndQuery(rawSpec)
      const isForce = Boolean(options?.force || options?.bypassGuard || forceFromQuery)
      const auditToken = options?.auditToken || tokenFromQuery

      const validation = interceptor.validateInstallRequest(cleanSpec, auditToken, { force: isForce })

      if (!validation.allowed && !isForce) {
        if (interceptor.isApproved(cleanSpec)) {
          interceptor.grantInstallWindow(cleanSpec)
          logger?.info?.(
            `[dsh-plugin-vetter] 插件 ${cleanSpec} 凭借已授权凭证/预审记录放行安装。`,
          )
        } else {
          logger?.warn?.(
            `[dsh-plugin-vetter] 宿主插件安装请求未带放行凭证，执行后备自动安全审计: spec=${cleanSpec}`,
          )
          const report = await interceptor.audit(cleanSpec)

          if (config.strictMode && report.verdict === 'DANGEROUS') {
            throw new Error(
              `[dsh-plugin-vetter] 严格模式阻断：插件 ${cleanSpec} 存在高危安全漏洞 (评级: ${report.verdict}, 得分: ${report.score}/100)，禁止安装。如需在已知风险下强制安装，请在确认放行后重试或使用强制放行模式。`,
            )
          }

          if (report.verdict === 'DANGEROUS') {
            logger?.warn?.(
              `[dsh-plugin-vetter] 安全提示：插件 ${cleanSpec} 评估为高危 (评级: ${report.verdict}, 得分: ${report.score}/100)，非严格模式放行安装。`,
            )
          } else {
            logger?.info?.(
              `[dsh-plugin-vetter] 插件 ${cleanSpec} 静态审计评估通过 (评级: ${report.verdict})，放行安装。`,
            )
          }
        }
      } else {
        interceptor.grantInstallWindow(cleanSpec)
        if (isForce) {
          logger?.info?.(`[dsh-plugin-vetter] 插件 ${cleanSpec} 检测到强制放行标记，放行安装。`)
        } else {
          logger?.info?.(`[dsh-plugin-vetter] 插件 ${cleanSpec} 凭借已授权凭证/预审记录放行安装。`)
        }
      }

      return origInstallBundle.call(this, cleanSpec, options)
    }

    return origInstallBundle.call(this, rawSpec, options)
  }

  pm.__pluginGuardHostPatched = true
  logger?.info?.('[dsh-plugin-vetter] 宿主 pluginManager.installBundle 安全门禁装载完成。')
  return unhook
}

/**
 * Mount the host-side Cordis plugin.
 */
export function apply(ctx: PluginContext, config: GuardConfig = {}): void {
  const interceptor = new GuardInterceptor(config, ctx)
  const webServer = ctx.webServer

  const unhooks: (() => void)[] = []

  // Multi-context hook for host pluginManager (lazy loaded Cordis service)
  const tryHookPm = (targetCtx: any) => {
    if (!targetCtx) return
    const pm = targetCtx.get?.('pluginManager') ?? targetCtx.pluginManager
    if (pm) {
      const unhook = hookHostPluginManager(pm, interceptor, ctx.logger)
      if (typeof unhook === 'function') unhooks.push(unhook)
    }
    interceptor.setHostContext(targetCtx)
  }

  tryHookPm(ctx)

  if (typeof ctx.inject === 'function') {
    try {
      ctx.inject(['pluginManager'], (c: any) => {
        tryHookPm(c)
        tryHookPm(ctx)
      })
    } catch {}

    try {
      ctx.inject(['llm'], (c: any) => {
        interceptor.setHostContext(c || ctx)
      })
    } catch {}

    try {
      ctx.inject(['agentDefaultModel'], (c: any) => {
        interceptor.setHostContext(c || ctx)
      })
    } catch {}

    try {
      ctx.inject(['webServer'], (c: any) => {
        tryHookPm(c)
        tryHookPm(ctx)
      })
    } catch {}
  }

  let restoreRegister: (() => void) | undefined
  if (webServer) {
    ctx.logger?.info?.('[dsh-plugin-vetter] Initializing security guard and route gates...')

    // Wrap webServer.register to intercept installer routes if registered
    const origRegister = webServer.register.bind(webServer)
    restoreRegister = () => {
      webServer.register = origRegister
    }

    webServer.register = function (route: any) {
      if (route && typeof route.path === 'string' && INTERCEPT_INSTALL_PATHS.has(route.path)) {
        const origHandler = route.handler
        route.handler = async function (req: IncomingMessage, res: ServerResponse) {
          if (interceptor.isDisposed()) {
            return origHandler(req, res)
          }
          const handled = await handleGuardRequest(req, res, { interceptor })
          if (handled) return
          return origHandler(req, res)
        }
      }
      return origRegister(route)
    }

    // Register modern prefix: /api/plugin-vetter
    webServer.register({
      kind: 'prefix',
      path: GUARD_API_PREFIX,
      handler: async (req, res) => {
        await handleGuardRequest(req, res, { interceptor })
      },
    })

    // Register legacy compatibility prefix: /gateway/vetter
    webServer.register({
      kind: 'prefix',
      path: LEGACY_GUARD_PREFIX,
      handler: async (req, res) => {
        await handleGuardRequest(req, res, { interceptor })
      },
    })

    // Register backward-compatible legacy prefixes
    webServer.register({
      kind: 'prefix',
      path: '/api/plugin-guard',
      handler: async (req, res) => {
        await handleGuardRequest(req, res, { interceptor })
      },
    })
    webServer.register({
      kind: 'prefix',
      path: '/gateway/guard',
      handler: async (req, res) => {
        await handleGuardRequest(req, res, { interceptor })
      },
    })
  } else {
    ctx.logger?.warn?.('[dsh-plugin-vetter] webServer service not found in Cordis context. Guard routes cannot be bound.')
  }

  // Cleanup on context dispose (Hot Unplug)
  if (typeof ctx.on === 'function') {
    ctx.on('dispose', async () => {
      ctx.logger?.info?.('[dsh-plugin-vetter] 接收到插件停用信号，执行热拔出清理...')
      for (const unhook of unhooks) {
        try {
          unhook()
        } catch {}
      }
      unhooks.length = 0
      if (restoreRegister) {
        try {
          restoreRegister()
        } catch {}
      }
      await interceptor.dispose()
      ctx.logger?.info?.('[dsh-plugin-vetter] 安全防御热拔出完成，所有拦截门禁已旁路放行。')
    })
  }
}

export default { name, inject, Config, apply }

// Re-export core capabilities for programmatic usage
export * from './core/constants.js'
export * from './core/types.js'
export * from './core/cache.js'
export * from './core/stager.js'
export * from './core/scanner.js'
export * from './core/agent-reviewer.js'
export * from './core/resolver.js'
export * from './host/token.js'
export * from './host/interceptor.js'
export * from './host/routes.js'
