import { defineConfig } from '@playwright/test';
import config from './src-tauri/tauri.conf.json' with {type:'json'};
const {width, height} = config.app.windows[0];
export default defineConfig({testDir:'tests',reporter:[['list'],['html',{open:'never'}]],use:{baseURL:'http://127.0.0.1:1421',headless:true,locale:'en-US',viewport:{width,height},screenshot:'on',trace:'retain-on-failure'},projects:[{name:'chromium',use:{browserName:'chromium'}},{name:'webkit',use:{browserName:'webkit'}}],webServer:{command:'pnpm run dev --port 1421',url:'http://127.0.0.1:1421',reuseExistingServer:false,env:{OPENAIDR_BUILD_DATE:'2026-10-02T08:27:00.000Z'}}});
