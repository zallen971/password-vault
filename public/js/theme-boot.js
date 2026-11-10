// Runs before first paint so the page never flashes the wrong theme.
(function () {
  var theme = 'system';
  try {
    theme = JSON.parse(localStorage.getItem('vault.prefs.v1') || '{}').theme || 'system';
  } catch (error) {
    /* fall back to the system theme */
  }
  if (theme !== 'light' && theme !== 'dark') {
    theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  document.documentElement.dataset.theme = theme;
})();
