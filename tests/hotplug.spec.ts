import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { apply as applyHost, hookHostPluginManager } from '../src/index.js'
import { GuardInterceptor } from '../src/host/interceptor.js'
import {
  apply as applyClient,
  patchFetch,
  unpatchFetch,
  unpatchAll,
  isClientPlugged,
} from '../src/client.js'

describe('Hot-pluggability (热插拔) lifecycle', () => {
  describe('Host side hot-unplug', () => {
    it('restores origInstallBundle and unblocks installs when context is disposed', async () => {
      const origInstallBundle = vi.fn().mockResolvedValue({ installed: true, source: 'orig' })
      const pm = {
        installBundle: origInstallBundle,
      }

      let disposeCallback: (() => Promise<void>) | null = null
      const mockCtx: any = {
        pluginManager: pm,
        on: vi.fn().mockImplementation((event: string, cb: any) => {
          if (event === 'dispose') disposeCallback = cb
        }),
        logger: {
          info: vi.fn(),
          warn: vi.fn(),
          error: vi.fn(),
        },
      }

      // Mount host plugin
      applyHost(mockCtx, { scanOnInstall: true, strictMode: true })
      expect((pm as any).__origInstallBundle).toBeDefined()

      // When mounted, installing an unapproved dangerous package throws
      const interceptor = (pm.installBundle as any).__interceptor || new GuardInterceptor()
      // Now trigger hot unplug via Cordis ctx.on('dispose')
      expect(disposeCallback).toBeDefined()
      await disposeCallback!()

      // After hot unplug, origInstallBundle must be restored
      expect(pm.installBundle).toBe(origInstallBundle)

      // Directly calling installBundle now bypasses guard completely and invokes origInstallBundle
      const res = await pm.installBundle('amlyczz--dsh-agy-link', { anyOption: true })
      expect(res).toEqual({ installed: true, source: 'orig' })
      expect(origInstallBundle).toHaveBeenCalledWith('amlyczz--dsh-agy-link', { anyOption: true })
    })

    it('interceptor.validateInstallRequest immediately allows all when disposed', () => {
      const interceptor = new GuardInterceptor({ scanOnInstall: true })
      expect(interceptor.validateInstallRequest('unapproved-pkg').allowed).toBe(false)

      interceptor.dispose()
      expect(interceptor.isDisposed()).toBe(true)
      expect(interceptor.validateInstallRequest('unapproved-pkg').allowed).toBe(true)
    })
  })

  describe('Client side hot-unplug', () => {
    let origFetchMock: any

    beforeEach(() => {
      origFetchMock = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ success: true, bypassed: true }),
      })
      vi.stubGlobal('fetch', origFetchMock)
    })

    afterEach(() => {
      unpatchAll()
      vi.unstubAllGlobals()
    })

    it('unpatchAll restores global fetch and allows /dshm requests without guard intervention', async () => {
      patchFetch()
      expect(isClientPlugged()).toBe(true)

      // Unpatch / hot-unplug
      unpatchAll()
      expect(isClientPlugged()).toBe(false)
      expect(globalThis.fetch).toBe(origFetchMock)

      // Call /dshm fetch
      const res = await fetch('/dshm', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ method: 'install', id: 'amlyczz--dsh-agy-link' }),
      })
      const data = await res.json()

      expect(data.bypassed).toBe(true)
      expect(origFetchMock).toHaveBeenCalledTimes(1)
      expect(origFetchMock.mock.calls[0][0]).toBe('/dshm')
    })

    it('client apply ctx.on("dispose") cleanly hot-unplugs fetch, managers and slots', async () => {
      let clientDisposeCb: (() => void) | null = null
      const registeredSlots: string[] = []

      const mockCtx: any = {
        on: vi.fn().mockImplementation((event: string, cb: any) => {
          if (event === 'dispose') clientDisposeCb = cb
        }),
        slots: {
          inject: (name: string, fn: any) => fn(),
          register: (options: any) => {
            registeredSlots.push(options.id || options.key)
            return () => {
              const idx = registeredSlots.indexOf(options.id || options.key)
              if (idx !== -1) registeredSlots.splice(idx, 1)
            }
          },
        },
      }

      applyClient(mockCtx)
      expect(isClientPlugged()).toBe(true)
      expect(registeredSlots.length).toBeGreaterThan(0)

      // Trigger client hot-unplug
      expect(clientDisposeCb).toBeDefined()
      clientDisposeCb!()

      expect(isClientPlugged()).toBe(false)
      expect(registeredSlots.length).toBe(0)
    })
  })
})
