// Apply the saved preference before the first paint; storage may be unavailable.
try { const theme = localStorage.getItem('fallbck.theme'); if (theme === 'dark' || theme === 'light') document.documentElement.dataset.theme = theme; } catch (_) {}
