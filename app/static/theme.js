(function () {
  var root = document.documentElement;
  var preference = root.getAttribute('data-theme-preference') || 'system';
  var media = window.matchMedia('(prefers-color-scheme: dark)');
  function applyTheme() {
    var theme = preference === 'system' ? (media.matches ? 'dark' : 'light') : preference;
    root.setAttribute('data-theme', theme);
    root.style.colorScheme = theme;
    var color = document.querySelector('meta[name="theme-color"]');
    if (color) color.setAttribute('content', theme === 'light' ? '#f4f7fb' : '#071018');
  }
  applyTheme();
  if (preference === 'system') {
    if (media.addEventListener) media.addEventListener('change', applyTheme);
    else if (media.addListener) media.addListener(applyTheme);
  }
}());
