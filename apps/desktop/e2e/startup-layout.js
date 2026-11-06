(() => {
  const app = document.querySelector('#app');
  const errors = window.__startupErrors ?? window.__e2eErrors ?? [];
  if (!app || !document.querySelector('main') || !document.querySelector('#continue-free') || !document.querySelector('#choose-organization'))
    return {fits:false, hidden:document.hidden, viewport:{width:innerWidth,height:innerHeight}, errors, error:'Setup choices have not rendered'};
  const bounds = app.getBoundingClientRect();
  const controls = ['#continue-free', '#choose-organization'].map(selector => {
    const element = document.querySelector(selector);
    const rect = element.getBoundingClientRect();
    return {selector, ...rect.toJSON(), visible:!!element.getClientRects().length && getComputedStyle(element).visibility !== 'hidden',
      fits:rect.width > 0 && rect.height > 0 && rect.top >= 0 && rect.left >= 0 && rect.bottom <= Math.min(innerHeight, bounds.bottom) && rect.right <= Math.min(innerWidth, bounds.right)};
  });
  const scroll = {width:app.clientWidth, height:app.clientHeight, contentWidth:app.scrollWidth,
    contentHeight:app.scrollHeight, top:app.scrollTop, left:app.scrollLeft};
  return {version:document.querySelector('#build-info')?.textContent, hidden:document.hidden,
    viewport:{width:innerWidth,height:innerHeight}, content:document.querySelector('main').getBoundingClientRect().toJSON(),
    scroll, controls, events:window.__startupEvents ?? [], errors,
    fits:!document.hidden && errors.length === 0 && scroll.top === 0 && scroll.left === 0
      && scroll.contentHeight <= scroll.height && scroll.contentWidth <= scroll.width
      && controls.every(control => control.visible && control.fits)};
})()
