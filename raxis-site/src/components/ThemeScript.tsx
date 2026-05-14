// Inline script that sets the initial theme class on <html> before React hydrates,
// avoiding the dark/light flash. Stored preference wins; otherwise we follow the OS.
export function ThemeScript() {
  const code = `
    (function () {
      try {
        var stored = localStorage.getItem('raxis-theme');
        var dark = stored ? stored === 'dark' : false;
        if (dark) document.documentElement.classList.add('dark');
        else document.documentElement.classList.remove('dark');
      } catch (e) {}
    })();
  `;
  return <script suppressHydrationWarning dangerouslySetInnerHTML={{ __html: code }} />;
}
