import { test, expect } from './fixtures';
import config from '../src-tauri/tauri.conf.json' with {type:'json'};

test.use({deviceScaleFactor:2});

for (const colorScheme of ['light','dark'] as const) {
  for (const maxWindowHeight of [720,320]) {
    test(`app and model cost mock in ${colorScheme} with a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
      await page.emulateMedia({colorScheme});
      await page.setViewportSize({width:config.app.windows[0].width,height:maxWindowHeight});
      await page.goto('/docs/app-model-cost-mock.html');
      const contentHeight = await page.locator('main').evaluate(node => Math.ceil(node.getBoundingClientRect().height));
      await page.setViewportSize({width:config.app.windows[0].width,height:Math.min(720,maxWindowHeight,Math.max(160,contentHeight))});
      await expect(page.getByText('Design preview · Sample data')).toBeVisible();
      await expect(page.locator('#usage-cost')).toHaveText('$1,099.18');
      await expect(page.locator('#usage-tokens')).toHaveText('2.0 B in (98% cached) / 10.0 M out');
      await expect(page.locator('#usage-average')).toHaveText('$36.64');
      await expect(page.locator('#application-models .app-heading')).toHaveText(['Codex$750.12','Claude Code$349.06']);
      for (const swatch of await page.locator('[data-app="codex"]>.swatch,[data-app="codex"]>.app-heading>.swatch').all()) {
        await expect(swatch).toHaveCSS('background-color','rgb(16, 163, 127)');
      }
      const app = page.locator('#app');
      expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(maxWindowHeight === 320);
      if (maxWindowHeight === 720) {
        await expect(page.locator('footer')).toBeInViewport({ratio:1});
        expect(await page.locator('main *').evaluateAll(nodes => nodes.filter(node => {
          const r=node.getBoundingClientRect();return r.width && r.height && (r.left < 0 || r.right > innerWidth || r.top < 0 || r.bottom > innerHeight);
        }).map(node => node.id || node.className))).toEqual([]);
        await page.screenshot({path:testInfo.outputPath(`app-model-cost-${colorScheme}.png`)});
      }
      const day = page.locator('.usage-day').last();
      const shades = await day.locator('.usage-stack>span').evaluateAll(nodes => nodes.map(node => getComputedStyle(node).backgroundColor));
      expect(new Set(shades).size).toBe(5);
      expect(await page.locator('.model-row .swatch').evaluateAll(nodes => nodes.map(node => getComputedStyle(node).backgroundColor))).toEqual(shades);
      await day.focus();
      const tooltip = page.getByRole('tooltip');
      await expect(tooltip).toBeVisible();
      await expect(tooltip).toContainText('Oct 9');
      await expect(tooltip.locator('.tooltip-app')).toHaveCount(2);
      await expect(tooltip.locator('.tooltip-model')).toHaveCount(5);
      await expect(tooltip).toBeInViewport({ratio:1});
      const values = await tooltip.locator('b').allTextContents();
      const cents = (value:string) => Math.round(Number(value.replace(/[$,]/g,''))*100);
      expect(cents(values[1])+cents(values[5])).toBe(cents(values[0]));
      expect(values.slice(2,5).map(cents).reduce((a,b) => a+b,0)).toBe(cents(values[1]));
      expect(values.slice(6).map(cents).reduce((a,b) => a+b,0)).toBe(cents(values[5]));
      await page.screenshot({path:testInfo.outputPath(`app-model-cost-tooltip-${colorScheme}.png`)});
      await page.keyboard.press('Escape');
      await expect(tooltip).toBeHidden();
      await page.getByRole('button',{name:'14 days',exact:true}).click();
      await expect(page.locator('.usage-day')).toHaveCount(14);
      expect(await page.locator('.usage-day').last().locator('.usage-stack>span').evaluateAll(nodes => nodes.map(node => getComputedStyle(node).backgroundColor))).toEqual(shades);
      await page.getByRole('button',{name:'30 days',exact:true}).click();
      await expect(page.locator('#usage-cost')).toHaveText('$1,099.18');
      await day.hover();
      await expect(tooltip).toBeVisible();
      await tooltip.hover();
      await expect(tooltip).toBeVisible();
      await page.getByRole('heading',{name:'Your usage',exact:true}).hover();
      await expect(tooltip).toBeHidden();
      if (maxWindowHeight === 320) {
        await app.hover();
        await page.mouse.wheel(0,1000);
        await expect(page.locator('footer')).toBeInViewport({ratio:1});
        await expect(page.locator('.model-row').last()).toBeInViewport({ratio:1});
        await page.screenshot({path:testInfo.outputPath(`app-model-cost-small-${colorScheme}.png`)});
        await page.getByRole('button',{name:'14 days',exact:true}).focus();
        await expect(page.getByRole('button',{name:'14 days',exact:true})).toBeInViewport({ratio:1});
      }
    });
  }
}
