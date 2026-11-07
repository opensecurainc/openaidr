import {test as appTest, expect} from './fixtures';

const testTimeout = 3_000;
let delayedPageCreation = false;
const test = appTest.extend({
  context: async ({context}, use) => {
    const newPage = context.newPage.bind(context);
    context.newPage = async () => {
      await new Promise(resolve => setTimeout(resolve, testTimeout + 500));
      delayedPageCreation = true;
      return newPage();
    };
    await use(context);
  },
});

test.describe.configure({timeout: testTimeout});

test('slow page creation does not use the test timeout', async ({page}) => {
  expect(delayedPageCreation).toBe(true);
  expect(page.isClosed()).toBe(false);
});
