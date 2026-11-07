import { defineConfig } from 'vite';
import { buildInfo } from '../../scripts/build-version.mjs';
import { syncAgentIcons } from '../../scripts/sync-agent-icons.mjs';

export default defineConfig(({ command }) => {
  syncAgentIcons(new URL('./public/agent-icons/', import.meta.url));
  const info = buildInfo({ development: command === 'serve' });
  return {
  clearScreen:false,
  server:{port:1420,strictPort:true},
  envPrefix:['VITE_','TAURI_ENV_'],
  define:{
    'import.meta.env.VITE_BUILD_VERSION':JSON.stringify(info.version),
    'import.meta.env.VITE_BUILD_COMMIT':JSON.stringify(info.source_commit),
    'import.meta.env.VITE_BUILD_TIME':JSON.stringify(info.built_at),
    'import.meta.env.VITE_ENTERPRISE_ONLY':JSON.stringify(info.desktop_edition === 'enterprise'),
  },
  };
});
