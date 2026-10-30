import { describe, expect, it } from 'vitest'
import { GuardInterceptor } from '../src/host/interceptor.js'

describe('GuardInterceptor', () => {
  it('blocks install requests when auditToken is missing', () => {
    const interceptor = new GuardInterceptor({ scanOnInstall: true })
    const check = interceptor.validateInstallRequest('some-package@1.0.0')

    expect(check.allowed).toBe(false)
    expect(check.reason).toContain('缺少安全预审放行凭证')
  })

  it('allows install request when scanOnInstall is false', () => {
    const interceptor = new GuardInterceptor({ scanOnInstall: false })
    const check = interceptor.validateInstallRequest('some-package@1.0.0')

    expect(check.allowed).toBe(true)
  })

  it('allows install when a valid token is provided and consumed', async () => {
    const interceptor = new GuardInterceptor({ scanOnInstall: true, strictMode: false })
    // Simulate approval by using token manager inside interceptor directly or approving
    const token = (interceptor as unknown as { tokenManager: { generateToken: (s: string) => string } }).tokenManager.generateToken('clean-plugin@1.0.0')

    const check = interceptor.validateInstallRequest('clean-plugin@1.0.0', token)
    expect(check.allowed).toBe(true)

    // Replay must be rejected
    const replayCheck = interceptor.validateInstallRequest('clean-plugin@1.0.0', token)
    expect(replayCheck.allowed).toBe(false)
    expect(replayCheck.reason).toContain('禁止重放')
  })
})
