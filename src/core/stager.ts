/**
 * DSH Plugin Guard: Safe Isolated Stager
 * Fetches and unpacks npm packages into a transient isolated sandbox using `--ignore-scripts`.
 * Guarantees zero code execution during the auditing phase.
 * @module dsh-plugin-vetter/core/stager
 */

import { createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import { mkdirSync, readdirSync, readFileSync, rmSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { promisify } from 'node:util'
import { GUARD_VERSION } from './constants.js'
import type { AuditOptions, AuditReport, GuardConfig } from './types.js'
import { auditPackageDirectory } from './scanner.js'
import { auditPackageWithAgent } from './agent-reviewer.js'
import type { AuditCacheManager } from './cache.js'
import { resolveInstallSpec } from './resolver.js'

const pExecFile = promisify(execFile)

export interface StageSession {
  spec: string
  stageDir: string
  unpackedDir: string
  tarballPath: string
  tarballSha256: string
  report: AuditReport
  cleanup: () => Promise<void>
}

export interface StageOptions extends AuditOptions {
  cacheManager?: AuditCacheManager
}

/**
 * Downloads a package tarball and unpacks it strictly isolated from host runtime.
 * Leverages local persistent cache by (model, pluginGuardVersion, plugin, tarballSha256)
 * to skip redundant unpacking, AST parsing, and model re-evaluation.
 */
export async function stageAndAuditPackage(
  spec: string,
  config: GuardConfig = {},
  options?: StageOptions,
): Promise<StageSession> {
  const nonce = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`
  const stageDir = join(tmpdir(), 'dsh-guard-staging', nonce)
  const unpackedDir = join(stageDir, 'unpacked')

  mkdirSync(stageDir, { recursive: true })
  mkdirSync(unpackedDir, { recursive: true })

  const cleanup = async (): Promise<void> => {
    try {
      rmSync(stageDir, { recursive: true, force: true })
    } catch {
      // Best-effort cleanup
    }
  }

  try {
    const trimmedSpec = spec.trim()
    if (!trimmedSpec || /[;&|`$<>]/.test(trimmedSpec)) {
      throw new Error(`[dsh-plugin-vetter] 非法的包名称或版本标识符: "${spec}"`)
    }

    const scanStart = Date.now()

    // 1. Resolve marketplace spec/ID (e.g. 'amlyczz--dsh-agy-link' -> 'dsh-agy-link')
    const specInfo = await resolveInstallSpec(trimmedSpec)
    const downloadSpec = specInfo.resolvedSpec

    // 2. Download tarball with --ignore-scripts to prevent any lifecycle script execution
    // npm pack outputs the filename to stdout
    const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm'
    const { stdout } = await pExecFile(
      npmCmd,
      ['pack', downloadSpec, '--pack-destination', stageDir, '--ignore-scripts'],
      {
        windowsHide: true,
        shell: process.platform === 'win32',
        timeout: 60000,
      },
    )

    // Find the generated .tgz file in stageDir
    const files = readdirSync(stageDir)
    const tgzName = files.find(f => f.endsWith('.tgz'))
    if (!tgzName) {
      throw new Error(`npm pack 未在暂存目录中产出 .tgz 文件: ${stdout}`)
    }

    const tarballPath = join(stageDir, tgzName)

    // 2. Compute SHA-256 digest of the pristine tarball
    const buffer = readFileSync(tarballPath)
    const tarballSha256 = createHash('sha256').update(buffer).digest('hex')

    const model = options?.model || config.model || 'static'
    const cacheManager = options?.cacheManager
    const shouldCheckCache = cacheManager && !options?.forceRefresh && !options?.noCache

    // 3. Fast check persistent disk cache by content SHA-256 and (model, version, plugin)
    if (shouldCheckCache) {
      const cachedReport = await cacheManager.get({
        model,
        pluginGuardVersion: GUARD_VERSION,
        plugin: trimmedSpec,
        tarballSha256,
      })

      if (cachedReport) {
        return {
          spec: trimmedSpec,
          stageDir,
          unpackedDir: '',
          tarballPath,
          tarballSha256,
          report: cachedReport,
          cleanup,
        }
      }
    }

    // 4. Unpack tarball safely using system tar (bsdtar is native in modern Windows/macOS/Linux)
    const tarCmd =
      process.platform === 'win32' && existsSync('C:/Windows/System32/tar.exe')
        ? 'C:/Windows/System32/tar.exe'
        : 'tar'
    const tarArgs = ['-xzf', tarballPath, '-C', unpackedDir]
    if (tarCmd === 'tar' && process.platform === 'win32') {
      tarArgs.unshift('--force-local')
    }

    await pExecFile(tarCmd, tarArgs, {
      windowsHide: true,
      timeout: 30000,
    })

    // npm packages unpack into a top-level 'package/' directory
    const extractedEntries = readdirSync(unpackedDir)
    const packageRoot = extractedEntries.includes('package')
      ? join(unpackedDir, 'package')
      : unpackedDir

    // 5. Run agent-driven sandbox security review against standards
    let report: AuditReport
    if (model === 'static') {
      report = auditPackageDirectory(spec, packageRoot, tarballSha256, config)
      report.model = 'static'
      report.pluginGuardVersion = GUARD_VERSION
    } else {
      report = await auditPackageWithAgent(spec, packageRoot, tarballSha256, config, {
        model,
        hostContext: options?.hostContext,
      })
    }
    report.originalSpec = trimmedSpec
    report.resolvedSpec = downloadSpec
    if (!report.packageName || report.packageName === trimmedSpec) {
      report.packageName = specInfo.packageName
    }
    const durationMs = Date.now() - scanStart

    // 6. Save audit report to persistent local disk cache
    if (cacheManager && !options?.noCache) {
      await cacheManager.set(
        {
          model,
          pluginGuardVersion: GUARD_VERSION,
          plugin: report.packageName,
          tarballSha256,
        },
        report,
        durationMs,
      )
      if (trimmedSpec !== report.packageName) {
        await cacheManager.set(
          {
            model,
            pluginGuardVersion: GUARD_VERSION,
            plugin: trimmedSpec,
            tarballSha256,
          },
          report,
          durationMs,
        )
      }
      if (downloadSpec !== report.packageName && downloadSpec !== trimmedSpec) {
        await cacheManager.set(
          {
            model,
            pluginGuardVersion: GUARD_VERSION,
            plugin: downloadSpec,
            tarballSha256,
          },
          report,
          durationMs,
        )
      }
    }

    return {
      spec,
      stageDir,
      unpackedDir: packageRoot,
      tarballPath,
      tarballSha256,
      report,
      cleanup,
    }
  } catch (error) {
    await cleanup()
    throw error
  }
}
