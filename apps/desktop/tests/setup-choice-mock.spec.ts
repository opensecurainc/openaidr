import { test, expect } from './fixtures';
import config from '../src-tauri/tauri.conf.json' with {type:'json'};

test.use({deviceScaleFactor:2,colorScheme:'light'});

for (const maxWindowHeight of [720,320]) {
  test(`setup choice mock fits a ${maxWindowHeight}px work area`, async ({page}, testInfo) => {
    const width = config.app.windows[0].width;
    await page.setViewportSize({width,height:maxWindowHeight});
    await page.goto('/docs/setup-choice-mock.html');
    await page.evaluate(() => document.fonts.ready);
    const contentHeight = await page.locator('main').evaluate(node => Math.ceil(node.getBoundingClientRect().height));
    const chromeHeight = await page.locator('.titlebar').evaluate(node => node.getBoundingClientRect().height + 2);
    await page.setViewportSize({width,height:Math.min(720,maxWindowHeight,Math.max(160,contentHeight + chromeHeight))});
    await expect(page.getByText('Design preview',{exact:true})).toBeVisible();
    await expect(page.getByRole('heading',{name:'Welcome to OpenAIDR'})).toBeVisible();
    await expect(page.getByRole('region',{name:'Use OpenAIDR for free'})).toBeVisible();
    await expect(page.getByRole('region',{name:'Connect to your organization'})).toBeVisible();
    const cards = await page.locator('.choice').evaluateAll(nodes => nodes.map(node => {
      const {x,y,width,height} = node.getBoundingClientRect();
      return {x,y,width,height};
    }));
    expect(cards).toHaveLength(2);
    expect(cards[0].y).toBe(cards[1].y);
    expect(cards[0].width).toBe(cards[1].width);
    expect(cards[0].height).toBe(cards[1].height);
    expect(cards[0].x + cards[0].width).toBeLessThan(cards[1].x);
    const buttons = page.locator('.choice-actions > .button');
    const positions = await buttons.evaluateAll(nodes => nodes.map(node => node.getBoundingClientRect().y));
    expect(positions[0]).toBe(positions[1]);
    const app = page.locator('#app');
    expect(await app.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    expect(await app.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(maxWindowHeight === 320);
    expect(await page.locator('main *').evaluateAll(nodes => nodes.filter(node => {
      const r = node.getBoundingClientRect();
      return r.width && r.height && (r.left < 0 || r.right > innerWidth || node.scrollWidth > node.clientWidth + 1);
    }).map(node => node.id || node.className))).toEqual([]);
    if (maxWindowHeight === 720) {
      await expect(page.locator('footer')).toBeInViewport({ratio:1});
      await expect(page.locator('.choices')).toBeInViewport({ratio:1});
      await page.screenshot({path:testInfo.outputPath('setup-choice.png')});
    }
    for (const control of await page.getByRole('button').all()) {
      await expect(control).toHaveAttribute('aria-disabled','true');
      await control.focus();
      await expect(control).toBeFocused();
      await expect(control).toBeInViewport({ratio:1});
    }
    if (maxWindowHeight === 320) {
      await expect(page.locator('footer')).toBeInViewport({ratio:1});
      await page.screenshot({path:testInfo.outputPath('setup-choice-small.png')});
    }
  });
}
