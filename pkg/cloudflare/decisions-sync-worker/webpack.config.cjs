const path = require('path');

const NodePolyfillPlugin = require('node-polyfill-webpack-plugin');

function buildConfig(entry, filename) {
  return {
    entry,
    mode: 'production',
    output: {
      filename,
      path: path.resolve(__dirname, 'dist'),
      library: {
        type: 'module',
      },
    },
    experiments: {
      outputModule: true,
    },
    plugins: [new NodePolyfillPlugin()],
    optimization: {
      minimize: false,
    },
  };
}

// Two independent compiled workers, each with exactly one sync target. Which
// one gets deployed is chosen at deploy time (see pkg/cloudflare), not by a
// runtime env flag — so each bundle is self-contained and never includes the
// other target's code.
module.exports = [
  buildConfig('./src/index-kv.js', 'kv-sync-worker.js'),
  buildConfig('./src/index-ip-lists.js', 'ip-lists-sync-worker.js'),
];
