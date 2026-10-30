/**
 * DSH Plugin Guard: Cryptographic Approval Token Manager
 * Generates and validates tamper-proof, single-use, time-bound approval tokens.
 * @module dsh-plugin-guard/host/token
 */

import { createHmac, randomBytes } from 'node:crypto'

export interface TokenPayload {
  spec: string
  tarballSha256?: string
  issuedAt: number
  expiresAt: number
  nonce: string
}

export class TokenManager {
  private secret: string
  private defaultTtlMs: number
  private consumedTokens = new Map<string, number>() // tokenNonce -> expiryTime

  constructor(secret?: string, defaultTtlMs: number = 300_000) {
    this.secret = secret || randomBytes(32).toString('hex')
    this.defaultTtlMs = defaultTtlMs
  }

  /**
   * Periodically purge expired tokens from the consumed set.
   */
  private sweepConsumed(): void {
    const now = Date.now()
    for (const [nonce, expiresAt] of this.consumedTokens.entries()) {
      if (now > expiresAt) {
        this.consumedTokens.delete(nonce)
      }
    }
  }

  /**
   * Generate a signed approval token for a specific spec and tarball SHA-256 digest.
   */
  generateToken(spec: string, tarballSha256?: string, ttlMs?: number): string {
    this.sweepConsumed()
    const now = Date.now()
    const expiresAt = now + (ttlMs ?? this.defaultTtlMs)
    const nonce = randomBytes(16).toString('hex')

    const payload: TokenPayload = {
      spec: spec.trim(),
      tarballSha256: tarballSha256?.toLowerCase(),
      issuedAt: now,
      expiresAt,
      nonce,
    }

    const payloadStr = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const signature = createHmac('sha256', this.secret).update(payloadStr).digest('base64url')

    return `${payloadStr}.${signature}`
  }

  /**
   * Verify token integrity, expiration, and spec match without consuming it.
   */
  verifyToken(
    token: string,
    spec: string,
    tarballSha256?: string,
  ): { valid: boolean; reason?: string; payload?: TokenPayload } {
    this.sweepConsumed()
    if (!token || typeof token !== 'string') {
      return { valid: false, reason: '未提供审批 Token' }
    }

    const parts = token.split('.')
    if (parts.length !== 2) {
      return { valid: false, reason: 'Token 格式无效' }
    }

    const [payloadStr, signature] = parts
    const expectedSig = createHmac('sha256', this.secret).update(payloadStr).digest('base64url')
    if (signature !== expectedSig) {
      return { valid: false, reason: 'Token 签名校验失败，可能已被篡改' }
    }

    let payload: TokenPayload
    try {
      payload = JSON.parse(Buffer.from(payloadStr, 'base64url').toString('utf-8'))
    } catch {
      return { valid: false, reason: 'Token 负载解析失败' }
    }

    if (Date.now() > payload.expiresAt) {
      return { valid: false, reason: 'Token 已过期' }
    }

    if (this.consumedTokens.has(payload.nonce)) {
      return { valid: false, reason: 'Token 已被使用（禁止重放）' }
    }

    if (payload.spec.toLowerCase() !== spec.trim().toLowerCase()) {
      return { valid: false, reason: `Token 所属包 (${payload.spec}) 与安装目标 (${spec}) 不匹配` }
    }

    if (tarballSha256 && payload.tarballSha256 && payload.tarballSha256 !== tarballSha256.toLowerCase()) {
      return { valid: false, reason: '安装包 SHA256 哈希与审批记录不一致' }
    }

    return { valid: true, payload }
  }

  /**
   * Consume an approval token (single-use enforcement).
   */
  consumeToken(
    token: string,
    spec: string,
    tarballSha256?: string,
  ): { valid: boolean; reason?: string } {
    const verification = this.verifyToken(token, spec, tarballSha256)
    if (!verification.valid || !verification.payload) {
      return { valid: false, reason: verification.reason }
    }

    // Mark nonce as consumed
    this.consumedTokens.set(verification.payload.nonce, verification.payload.expiresAt)
    return { valid: true }
  }
}
