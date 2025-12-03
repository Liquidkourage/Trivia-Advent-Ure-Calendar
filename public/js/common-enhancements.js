(function() {
  'use strict';

  // Loading states for forms
  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (form.tagName !== 'FORM') return;
    
    const submitBtn = form.querySelector('button[type="submit"]');
    if (!submitBtn) return;
    
    // Skip if already processing
    if (submitBtn.disabled) return;
    
    // Add loading state
    submitBtn.disabled = true;
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'Loading...';
    submitBtn.style.opacity = '0.7';
    
    // Re-enable after 30 seconds as fallback
    setTimeout(() => {
      submitBtn.disabled = false;
      submitBtn.textContent = originalText;
      submitBtn.style.opacity = '1';
    }, 30000);
  });

  // Confirmation dialogs for destructive actions
  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (form.tagName !== 'FORM') return;
    
    // Skip confirmation if form has data-skip-confirm attribute
    if (form.hasAttribute('data-skip-confirm')) {
      return;
    }
    
    // Check for destructive action indicators
    const action = form.action || '';
    const method = (form.method || 'GET').toUpperCase();
    const hasConfirm = form.hasAttribute('data-confirm');
    const confirmMsg = form.getAttribute('data-confirm');
    
    if (hasConfirm && confirmMsg) {
      if (!confirm(confirmMsg)) {
        e.preventDefault();
        return false;
      }
    }
    
    // Auto-detect destructive actions
    const destructivePatterns = [
      /delete/i,
      /remove/i,
      /revoke/i,
      /reset/i,
      /clear/i
    ];
    
    const isDestructive = destructivePatterns.some(pattern => 
      pattern.test(action) || pattern.test(form.innerHTML)
    );
    
    if (isDestructive && method === 'POST' && !hasConfirm) {
      const defaultMsg = 'Are you sure you want to perform this action? This may not be undoable.';
      if (!confirm(defaultMsg)) {
        e.preventDefault();
        return false;
      }
    }
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + K for search (if search box exists)
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      const searchInput = document.querySelector('input[type="text"][id*="search"], input[type="text"][placeholder*="Search"]');
      if (searchInput) {
        e.preventDefault();
        searchInput.focus();
        searchInput.select();
      }
    }
    
    // Escape to clear search
    if (e.key === 'Escape') {
      const searchInput = document.querySelector('input[type="text"][id*="search"]:focus');
      if (searchInput) {
        searchInput.value = '';
        searchInput.blur();
        // Trigger change event if filter function exists
        if (typeof filterPlayers === 'function') filterPlayers();
        if (typeof filterQuizzes === 'function') filterQuizzes();
      }
    }
  });

  // Add loading spinner utility
  window.showLoading = function(element) {
    if (!element) return;
    element.style.position = 'relative';
    const spinner = document.createElement('div');
    spinner.className = 'loading-spinner';
    spinner.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:20px;height:20px;border:3px solid rgba(255,255,255,0.3);border-top-color:#ffd700;border-radius:50%;animation:spin 0.8s linear infinite;z-index:1000;';
    element.appendChild(spinner);
    
    // Add spin animation if not exists
    if (!document.getElementById('spinner-style')) {
      const style = document.createElement('style');
      style.id = 'spinner-style';
      style.textContent = '@keyframes spin { to { transform: translate(-50%,-50%) rotate(360deg); } }';
      document.head.appendChild(style);
    }
  };

  window.hideLoading = function(element) {
    if (!element) return;
    const spinner = element.querySelector('.loading-spinner');
    if (spinner) spinner.remove();
  };

  // Hamburger menu toggle - use event delegation to work regardless of load timing
  (function() {
    // Use event delegation on document body - works even if elements aren't ready yet
    document.addEventListener('click', function(e) {
      const menuToggle = e.target.closest('.ta-menu-toggle');
      if (menuToggle) {
        e.preventDefault();
        e.stopPropagation();
        const nav = document.querySelector('.ta-nav');
        if (nav) {
          const isExpanded = menuToggle.getAttribute('aria-expanded') === 'true';
          menuToggle.setAttribute('aria-expanded', !isExpanded);
          nav.setAttribute('aria-expanded', !isExpanded);
        }
        return;
      }
      
      // Close menu when clicking outside
      const nav = document.querySelector('.ta-nav');
      const toggle = document.querySelector('.ta-menu-toggle');
      if (nav && toggle && nav.getAttribute('aria-expanded') === 'true') {
        if (!nav.contains(e.target) && !toggle.contains(e.target)) {
          toggle.setAttribute('aria-expanded', 'false');
          nav.setAttribute('aria-expanded', 'false');
        }
      }
      
      // Close menu when clicking a nav link (mobile)
      if (nav && toggle && e.target.tagName === 'A' && nav.contains(e.target) && window.innerWidth <= 768) {
        toggle.setAttribute('aria-expanded', 'false');
        nav.setAttribute('aria-expanded', 'false');
      }
    }, true); // Use capture phase to catch events early
  })();
})();


