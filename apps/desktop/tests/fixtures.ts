import {test as base} from '@playwright/test';

export * from '@playwright/test';

// Fixtures without their own timeout share the test timeout. Under CI load the
// first WebKit page in a worker has taken over 18 s to create, which left the
// test body too little time. Give page creation a separate budget so the test
// timeout measures only the test.
export const pageCreationTimeout = 60_000;

export const test = base.extend({
  // Matches the built-in fixture: reuse the first page of a reused context.
  page: [async ({context}, use) => {
    await use(context.pages()[0] ?? await context.newPage());
  }, {scope: 'test', timeout: pageCreationTimeout}],
});
