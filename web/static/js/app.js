// HTMX owns requests, HTML swaps, navigation and polling. This file only handles
// local presentation: dialogs, conditional fields, theme, navigation and clipboard.
(() => {
  let returnFocus;
  const dialog = () => document.getElementById('editor');
  function themeLabel() {
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      const dark = document.documentElement.dataset.theme === 'dark';
      button.textContent = dark ? 'Light' : 'Dark';
      button.setAttribute('aria-label', `Switch to ${dark ? 'light' : 'dark'} theme`);
    });
  }
  function fields() {
    const form = document.getElementById('resource-form');
    if (!form) return;
    form.querySelectorAll('[data-when]').forEach(section => {
      const visible = section.dataset.when.split(' ').every(condition => {
        const [name, value] = condition.split('=');
        return form.elements.namedItem(name)?.value === value;
      });
      section.hidden = !visible;
      section.disabled = !visible;
    });
  }
  function closeDialog() {
    const editor = dialog();
    if (!editor?.open) return;
    editor.close();
    document.getElementById('dialog-body').replaceChildren();
    if (returnFocus?.isConnected) returnFocus.focus();
  }
  function notify(message) {
    const formErrors = dialog()?.open ? document.getElementById('form-errors') : null;
    const secretScroll = dialog()?.open ? document.querySelector('#dialog-body .dialog-scroll') : null;
    const host = formErrors || secretScroll || document.getElementById('notifications');
    const previousFocus = document.activeElement;
    if (!host) return;
    const box = document.createElement('div');
    box.className = 'notice error'; box.setAttribute('role', 'alert');
    box.tabIndex = -1; box.textContent = message;
    const close = document.createElement('button');
    close.className = 'btn btn-small'; close.textContent = 'Dismiss';
    close.addEventListener('click', () => {
      box.remove(); if (previousFocus?.isConnected) previousFocus.focus();
    }); box.append(close);
    if (secretScroll && !formErrors) host.prepend(box); else host.replaceChildren(box);
    box.focus();
  }
  document.addEventListener('click', async event => {
    const target = event.target.closest('button, a');
    if (!target) return;
    if (target.matches('[hx-target="#dialog-body"]')) returnFocus = target;
    if (target.matches('[data-close-dialog]')) closeDialog();
    if (target.matches('[data-theme-toggle]')) {
      const theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
      document.documentElement.dataset.theme = theme;
      try { localStorage.setItem('fallbck.theme', theme); } catch (_) {}
      themeLabel();
    }
    if (target.matches('[data-live-control]')) {
      const paused = target.getAttribute('aria-pressed') !== 'true';
      target.setAttribute('aria-pressed', String(paused));
      target.textContent = paused ? 'Resume live updates' : 'Pause live updates';
      document.getElementById('live-update-status').textContent = paused
        ? 'Live updates paused. The backup continues in the background.'
        : 'Live updates resumed. Updates pause while you use the record.';
    }
    if (target.matches('[data-menu]')) {
      const expanded = target.getAttribute('aria-expanded') !== 'true';
      target.setAttribute('aria-expanded', String(expanded));
      document.querySelector('.sidebar')?.classList.toggle('menu-open', expanded);
    }
    if (target.matches('[data-copy]')) {
      const element = document.getElementById(target.dataset.copy);
      const status = document.getElementById('copy-status');
      try { await navigator.clipboard.writeText(element.textContent); if (status) status.textContent = 'Copied to clipboard.'; }
      catch (_) { if (status) status.textContent = 'Clipboard unavailable. Select and copy the text above.'; element?.focus(); }
    }
  });
  document.addEventListener('change', event => { if (event.target.closest('#resource-form')) fields(); });
  document.addEventListener('keydown', event => {
    if (event.key === 'Tab' && dialog()?.open) {
      const stops = [...dialog().querySelectorAll('a[href],button,input,select,textarea,[tabindex]')]
        .filter(element => element.tabIndex >= 0 && !element.matches(':disabled') && element.getClientRects().length);
      const first = stops[0], last = stops[stops.length - 1];
      if (event.shiftKey && (document.activeElement === first || !stops.includes(document.activeElement))) {
        event.preventDefault(); last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault(); first?.focus();
      }
    }
    if (event.key === 'Escape') {
      const menu = document.querySelector('[data-menu]');
      if (menu?.getAttribute('aria-expanded') === 'true') { menu.click(); menu.focus(); }
    }
  });
  dialog()?.addEventListener('cancel', event => {
    event.preventDefault();
    const done = document.querySelector('[data-secret-done]');
    if (done) done.click(); else closeDialog();
  });
  function holdRunUpdate(event) {
    if (event.detail.ctx?.sourceElement?.id !== 'run-panel') return false;
    const panel = document.getElementById('run-panel');
    const paused = document.querySelector('[data-live-control]')?.getAttribute('aria-pressed') === 'true';
    // Do not replace controls being used, open disclosures or selected log text.
    const selection = document.getSelection();
    const interacting = panel?.contains(document.activeElement) || panel?.querySelector('details[open]') ||
      (selection && !selection.isCollapsed && panel?.contains(selection.anchorNode)) || dialog()?.open;
    if (paused || interacting) { event.preventDefault(); return true; }
    return false;
  }
  document.addEventListener('htmx:before:swap', event => {
    // Keep the form intact when authentication middleware rejects a request.
    if (event.detail.ctx?.response?.status === 403) event.preventDefault();
    holdRunUpdate(event);
  });
  document.addEventListener('htmx:before:request', event => {
    if (holdRunUpdate(event)) return;
    event.detail.ctx?.sourceElement?.setAttribute('aria-busy', 'true');
  });
  document.addEventListener('htmx:after:request', event => {
    event.detail.ctx?.sourceElement?.removeAttribute('aria-busy');
  });
  document.addEventListener('htmx:after:swap', event => {
    const target = event.detail.ctx?.target;
    if (target === '#notifications' || target?.id === 'notifications') {
      document.querySelector('#notifications [role="alert"]')?.focus();
    }
    const liveControl = document.querySelector('[data-live-control]');
    if (liveControl && !document.getElementById('run-panel')?.hasAttribute('hx-trigger')) {
      liveControl.disabled = true;
      liveControl.textContent = 'Live updates finished';
      document.getElementById('live-update-status').textContent = 'This run has finished. The final record is shown below.';
    }
    if (target === '#dialog-body' || target?.id === 'dialog-body' || document.getElementById('dialog-body')?.children.length && !dialog()?.open) {
      fields(); if (!dialog().open) dialog().showModal();
      document.getElementById('dialog-title')?.focus();
    }
    themeLabel();
  });
  document.addEventListener('htmx:after:settle', event => {
    // Page replacements close the dialog; polling must never steal focus.
    if (event.detail.newContent?.some?.(node => node.id === 'app')) {
      closeDialog(); document.getElementById('main')?.focus({preventScroll: true});
      document.getElementById('notifications')?.replaceChildren();
    }
    document.querySelector('#form-errors [role="alert"]')?.focus();
    themeLabel();
  });
  document.addEventListener('htmx:error', event => { event.detail.ctx?.sourceElement?.removeAttribute('aria-busy'); notify('The server could not be reached. Your input is still here. Check your connection and try again.'); });
  document.addEventListener('htmx:response:error', event => {
    const ctx = event.detail.ctx;
    if (ctx?.response?.status === 403) notify('Your request was rejected. Reload the page and sign in again if needed.');
    if (ctx?.sourceElement?.id === 'run-panel') notify('Live updates are temporarily unavailable. Retrying automatically.');
  });
  themeLabel(); fields();
})();
