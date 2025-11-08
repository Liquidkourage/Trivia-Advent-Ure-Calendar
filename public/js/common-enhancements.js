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

  // Hamburger menu toggle
  (function() {
    const menuToggle = document.querySelector('.ta-menu-toggle');
    const nav = document.querySelector('.ta-nav');
    
    if (menuToggle && nav) {
      menuToggle.addEventListener('click', function() {
        const isExpanded = menuToggle.getAttribute('aria-expanded') === 'true';
        menuToggle.setAttribute('aria-expanded', !isExpanded);
        nav.setAttribute('aria-expanded', !isExpanded);
      });
      
      // Close menu when clicking outside
      document.addEventListener('click', function(e) {
        if (!nav.contains(e.target) && !menuToggle.contains(e.target)) {
          menuToggle.setAttribute('aria-expanded', 'false');
          nav.setAttribute('aria-expanded', 'false');
        }
      });
      
      // Close menu when clicking a nav link (mobile)
      nav.addEventListener('click', function(e) {
        if (e.target.tagName === 'A' && window.innerWidth <= 768) {
          menuToggle.setAttribute('aria-expanded', 'false');
          nav.setAttribute('aria-expanded', 'false');
        }
      });
    }
  })();
})();


