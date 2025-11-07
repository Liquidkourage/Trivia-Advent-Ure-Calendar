(function() {
  function countOccurrences(haystack, needle) {
    const h = String(haystack || '').toLowerCase();
    const n = String(needle || '').toLowerCase();
    if (!n.length) return 0;
    let count = 0;
    let idx = 0;
    while (true) {
      idx = h.indexOf(n, idx);
      if (idx === -1) break;
      count++;
      idx += n.length;
    }
    return count;
  }

  function ensureHint(afterEl, id) {
    let hint = document.getElementById(id);
    if (!hint) {
      hint = document.createElement('div');
      hint.id = id;
      hint.style.marginTop = '4px';
      hint.style.fontSize = '0.9em';
      hint.style.opacity = '0.9';
      afterEl.insertAdjacentElement('afterend', hint);
    }
    return hint;
  }

  function validateOne(form, index) {
    const textEl = form.querySelector(`[name="q${index}_text"]`);
    const askEl = form.querySelector(`[name="q${index}_ask"]`);
    if (!textEl || !askEl) return { valid: true };
    const hint = ensureHint(askEl, `ask_hint_${index}`);

    const text = textEl.value.trim();
    const ask = askEl.value.trim();

    // Reset styles
    askEl.style.borderColor = '#ccc';
    hint.textContent = '';

    if (!ask) {
      // Ask is optional; no error if empty
      hint.style.color = '#888';
      return { valid: true };
    }

    const occurrences = countOccurrences(text, ask);
    if (!occurrences) {
      hint.textContent = 'Ask must appear verbatim in the Text.';
      hint.style.color = '#d32f2f';
      askEl.style.borderColor = '#d32f2f';
      return { valid: false };
    }
    if (occurrences > 1) {
      hint.textContent = `Ask appears ${occurrences} times in the Text; it must be unique.`;
      hint.style.color = '#ef6c00';
      askEl.style.borderColor = '#ef6c00';
      return { valid: false };
    }

    hint.textContent = 'Looks good: appears once in the Text.';
    hint.style.color = '#2e7d32';
    askEl.style.borderColor = '#2e7d32';
    return { valid: true };
  }

  function validateAll(form) {
    let allValid = true;
    for (let i = 1; i <= 10; i++) {
      const result = validateOne(form, i);
      // Only block submission when Ask is present but invalid
      const askEl = form.querySelector(`[name="q${i}_ask"]`);
      if (askEl && askEl.value.trim() && !result.valid) allValid = false;
    }
    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = !allValid;
  }

  function wire() {
    const form = document.querySelector('form[action^="/writer/"]');
    if (!form) return;
    for (let i = 1; i <= 10; i++) {
      const textEl = form.querySelector(`[name="q${i}_text"]`);
      const askEl = form.querySelector(`[name="q${i}_ask"]`);
      if (!textEl || !askEl) continue;
      const handler = () => validateAll(form);
      textEl.addEventListener('input', handler);
      askEl.addEventListener('input', handler);
    }
    validateAll(form);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wire);
  } else {
    wire();
  }
})();


