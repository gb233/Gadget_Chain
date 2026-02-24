import { chromium } from '@playwright/test';

const browser = await chromium.launch();
const page = await browser.newPage();

page.on('console', msg => {
  console.log(`[${msg.type()}] ${msg.text()}`);
});

page.on('pageerror', error => {
  console.log(`[PAGE ERROR] ${error.message}`);
});

await page.goto('http://localhost:3000');
await page.waitForTimeout(3000);

const content = await page.content();
console.log('Page content length:', content.length);
console.log('Has #app:', content.includes('id="app"'));
console.log('Has vue:', content.includes('__VUE__') || content.includes('data-v-'));

await browser.close();
