import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'path'
import { fileURLToPath } from 'url'

// Vite 8's native config loader no longer injects CommonJS `__dirname`; derive
// it from import.meta.url so the '@' alias keeps resolving under both loaders.
const dirname = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(dirname, './src'),
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: true,
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    // Use forked child processes rather than worker threads. Under React 19's
    // dev bundle + Vite 8 the worker-thread pool trended toward exhausting the
    // shared V8 isolate; forks give each worker its own process. In Vitest 4
    // the old `test.poolOptions.forks.*` block was flattened to these top-level
    // options (see the v4 migration guide), so keep them here or they silently
    // no-op. Bound the fork count to cap total peak memory across the suite.
    pool: 'forks',
    maxForks: 4,
    minForks: 1,
    isolate: true,
    // Fix for jsdom ES module issues with certain packages
    deps: {
      interopDefault: true,
    },
    // Use tsconfig paths for resolution
    tsconfig: './tsconfig.json',
    coverage: {
      provider: 'v8',
      // text -> console summary, lcov -> codecov upload, html -> local inspection
      reporter: ['text', 'lcov', 'html'],
      reportsDirectory: './coverage',
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        'src/**/*.{test,spec}.{ts,tsx}',
        'src/test/**',
        'src/**/__mocks__/**',
        'src/**/*.d.ts',
        'src/main.tsx',
        'src/vite-env.d.ts',
      ],
    },
  },
})
