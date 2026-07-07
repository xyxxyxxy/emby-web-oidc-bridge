package handler

// watchpartyAutoLoginScript is a self-executing JavaScript function that
// detects watchparty v2 login forms via MutationObserver, fetches the user's
// Emby credentials from the bridge's /api/credentials endpoint, fills the
// form fields with proper Vue.js reactivity events, and submits.
const watchpartyAutoLoginScript = `(function() {
  var inFlight = false;

  function tryAutoLogin(form) {
    if (inFlight) return;

    var usernameInput = form.querySelector('input[autocomplete="username"]');
    var passwordInput = form.querySelector('input[autocomplete="current-password"]');
    if (!usernameInput || !passwordInput) return;

    var submitBtn = form.querySelector('button[type="submit"]');
    if (!submitBtn) submitBtn = form.querySelector('button');
    if (!submitBtn) return;

    inFlight = true;

    var controller = new AbortController();
    var timeout = setTimeout(function() { controller.abort(); }, 10000);

    fetch('/api/credentials', {
      credentials: 'same-origin',
      signal: controller.signal
    }).then(function(resp) {
      clearTimeout(timeout);
      if (!resp.ok) throw new Error('credentials fetch failed: ' + resp.status);
      return resp.json();
    }).then(function(creds) {
      var username = creds.username;
      var password = creds.password;

      usernameInput.value = username;
      usernameInput.dispatchEvent(new Event('input', { bubbles: true }));

      passwordInput.value = password;
      passwordInput.dispatchEvent(new Event('input', { bubbles: true }));

      username = null;
      password = null;
      creds = null;

      submitBtn.click();
      inFlight = false;
    }).catch(function(err) {
      clearTimeout(timeout);
      console.warn('[emby-bridge] auto-login failed:', err.message || err);
      inFlight = false;
    });
  }

  var observer = new MutationObserver(function(mutations) {
    for (var i = 0; i < mutations.length; i++) {
      var added = mutations[i].addedNodes;
      for (var j = 0; j < added.length; j++) {
        var node = added[j];
        if (node.nodeType !== 1) continue;
        var forms = node.tagName === 'FORM' ? [node] : node.querySelectorAll ? Array.prototype.slice.call(node.querySelectorAll('form')) : [];
        for (var k = 0; k < forms.length; k++) {
          var f = forms[k];
          if (f.querySelector('input[autocomplete="username"]') && f.querySelector('input[autocomplete="current-password"]')) {
            tryAutoLogin(f);
          }
        }
      }
    }
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });

  // Check for forms already in the DOM at script execution time.
  var existing = document.querySelectorAll('form');
  for (var i = 0; i < existing.length; i++) {
    var f = existing[i];
    if (f.querySelector('input[autocomplete="username"]') && f.querySelector('input[autocomplete="current-password"]')) {
      tryAutoLogin(f);
      break;
    }
  }
})();`
