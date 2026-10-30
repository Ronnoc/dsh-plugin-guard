/**
 * DSH Plugin Guard: Safe Isolated Stager
 * Fetches and unpacks npm packages into a transient isolated sandbox using `--ignore-scripts`.
 * Guarantees zero code execution during the auditing phase.
 * @module dsh-plugin-guard/core/stager
 */

import { createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { promisify } from 'node:util'
import type { AuditReport, GuardConfig } from './types.js'
import { auditPackageDirectory } from './scanner.js'

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

/**
 * Downloads a package tarball and unpacks it strictly isolated from host runtime.
 */
export async function stageAndAuditPackage(
  spec: string,
  config: GuardConfig = {},
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
    // 1. Download tarball with --ignore-scripts to prevent any lifecycle script execution
    // npm pack outputs the filename to stdout
    const { stdout } = await pExecFile('npm', ['pack', spec, '--pack-destination', stageDir, '--ignore-scripts'], {
      windowsHide: true,
      timeout: 60000,
    })

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

    // 3. Unpack tarball safely using system tar (bsdtar is native in modern Windows/macOS/Linux)
    await pExecFile('tar', ['-xzf', tarballPath, '-C', unpackedDir], {
      windowsHide: true,
      timeout: 30000,
    })

    // npm packages unpack into a top-level 'package/' directory
    const extractedEntries = readdirSync(unpackedDir)
    const packageRoot = extractedEntries.includes('package')
      ? join(unpackedDir, 'package')
      : unpackedDir

    // 4. Run static rule audit
    const report = auditPackageDirectory(spec, packageRoot, tarballSha256, config)

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
