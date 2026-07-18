import { readFileSync } from 'node:fs';
import { build } from 'esbuild';

const isDev = process.argv.includes('--dev');
const { version } = JSON.parse(readFileSync('package.json', 'utf8'));

await build({
  entryPoints: ['src/server.js'],
  bundle: true,
  outfile: 'dist/server.cjs',
  platform: 'node',
  // Match the package.json engines floor (>=22). Targeting a higher version than
  // we advertise risks emitting syntax that breaks for users on Node 22.
  target: 'node22',
  format: 'cjs',
  minify: !isDev,
  sourcemap: isDev,
  banner: { js: '#!/usr/bin/env node' },
  define: { __MCP_VERSION__: JSON.stringify(version) },
});

console.log('Built dist/server.cjs');
