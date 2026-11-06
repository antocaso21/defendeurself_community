(() => {
  const contrast = document.querySelector('[data-contrast]');
  const textSize = document.querySelector('[data-text-size]');
  const safeGet = (k) => { try {return localStorage.getItem(k)} catch { return null } };
  const safeSet = (k,v) => { try {localStorage.setItem(k,v)} catch {} };
  if (safeGet('defend_contrast') === '1') document.body.classList.add('high-contrast');
  if (safeGet('defend_larger') === '1') document.body.classList.add('large-text');
  contrast?.addEventListener('click', () => {const yes=document.body.classList.toggle('high-contrast');safeSet('defend_contrast',yes?'1':'0')});
  textSize?.addEventListener('click', () => {const yes=document.body.classList.toggle('large-text');safeSet('defend_larger',yes?'1':'0')});
  document.querySelector('[data-confirm-delete]')?.addEventListener('submit', e => {
    if (!confirm('Permanently delete your account and all its contributions?')) e.preventDefault();
  });
})();
