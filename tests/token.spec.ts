import { describe, expect, it } from 'vitest'
import { TokenManager } from '../src/host/token.js'

describe('TokenManager', () => {
  const secret = 'super-secret-key-for-test-32bytes!'
  const manager = new TokenManager(secret, 60_000)

  it('generates a valid signed approval token', () => {
    const spec = 'test-plugin@1.0.0'
    const sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

    const token = manager.generateToken(spec, sha)
    expect(token).toBeTypeOf('string')
    expect(token.includes('.')).toBe(true)

    const verification = manager.verifyToken(token, spec, sha)
    expect(verification.valid).toBe(true)
    expect(verification.payload?.spec).toBe(spec)
    expect(verification.payload?.tarballSha256).toBe(sha)
  })

  it('rejects tampered tokens', () => {
    const spec = 'test-plugin@1.0.0'
    const token = manager.generateToken(spec)
    const [payload, sig] = token.split('.')

    // Tamper with payload
    const tamperedPayload = Buffer.from('{"spec":"malicious-pkg"}').toString('base64url')
    const tamperedToken = `${tamperedPayload}.${sig}`

    const res = manager.verifyToken(tamperedToken, spec)
    expect(res.valid).toBe(false)
    expect(res.reason).toContain('签名校验失败')
  })

  it('rejects expired tokens', async () => {
    const shortLivedManager = new TokenManager(secret, 10) // 10ms
    const token = shortLivedManager.generateToken('pkg@1.0.0')

    await new Promise(resolve => setTimeout(resolve, 20))
    const res = shortLivedManager.verifyToken(token, 'pkg@1.0.0')
    expect(res.valid).toBe(false)
    expect(res.reason).toContain('过期')
  })

  it('enforces single-use consumption (anti-replay)', () => {
    const spec = 'reusable-plugin@1.0.0'
    const token = manager.generateToken(spec)

    // First consumption succeeds
    const firstUse = manager.consumeToken(token, spec)
    expect(firstUse.valid).toBe(true)

    // Second consumption must fail
    const secondUse = manager.consumeToken(token, spec)
    expect(secondUse.valid).toBe(false)
    expect(secondUse.reason).toContain('禁止重放')
  })

  it('rejects mismatching spec or tarball sha', () => {
    const token = manager.generateToken('pkg-a@1.0.0', 'hash-a')

    const specMismatch = manager.verifyToken(token, 'pkg-b@1.0.0', 'hash-a')
    expect(specMismatch.valid).toBe(false)
    expect(specMismatch.reason).toContain('不匹配')

    const hashMismatch = manager.verifyToken(token, 'pkg-a@1.0.0', 'hash-b')
    expect(hashMismatch.valid).toBe(false)
    expect(hashMismatch.reason).toContain('不一致')
  })
})
