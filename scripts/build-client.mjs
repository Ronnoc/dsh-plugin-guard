import { build } from 'esbuild'
import { writeFileSync, mkdirSync } from 'node:fs'

const result = await build({
  entryPoints: ['src/client.ts'],
  bundle: true,
  format: 'cjs',
  platform: 'browser',
  target: 'es2022',
  external: ['react', 'react-dom'],
  write: false,
})

const code = result.outputFiles[0].text

const output = `(function() {
  function __factory__(require) {
    var module = { exports: {} };
    var exports = module.exports;
${code}
    return module.exports;
  }

  if (typeof window !== "undefined" && window.__ModuleLoader__) {
    window.__ModuleLoader__.load({
      id: "dsh-plugin-vetter",
      factory: __factory__
    });
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = __factory__(typeof require === "function" ? require : function() {});
  }
})();
`

mkdirSync('lib', { recursive: true })
writeFileSync('lib/client.js', output, 'utf-8')
console.log('Successfully built lib/client.js (DSH ModuleLoader format)')
