(function() {
  'use strict';

  const form = document.getElementById('quiz-form');
  if (!form) return;

  const quizId = form.dataset.quizId;
  const questionCards = Array.from(document.querySelectorAll('.quiz-card'));
  const totalQuestions = questionCards.length;
  const answerInputs = Array.from(form.querySelectorAll('input[name^="q"]:not([name="locked"])'));
  const lockRadios = Array.from(form.querySelectorAll('input[name="locked"]'));
  const progressText = document.getElementById('progress-text');
  const progressBar = document.getElementById('progress-bar');
  const autosaveStatus = document.getElementById('autosave-status');
  const reviewBtn = document.getElementById('review-btn');
  const reviewPanel = document.getElementById('review-panel');
  const reviewContent = document.getElementById('review-content');
  const editBtn = document.getElementById('edit-btn');
  const submitBtn = document.getElementById('submit-btn');

  // Progress tracking
  function updateProgress() {
    const answered = answerInputs.filter(input => input.value.trim() !== '').length;
    const percentage = totalQuestions > 0 ? (answered / totalQuestions) * 100 : 0;
    if (progressText) progressText.textContent = `${answered} / ${totalQuestions}`;
    if (progressBar) progressBar.style.width = `${percentage}%`;
  }

  // Autosave functionality
  let autosaveTimeout;
  function autosave() {
    clearTimeout(autosaveTimeout);
    if (autosaveStatus) {
      autosaveStatus.textContent = 'Saving...';
      autosaveStatus.style.color = '#888';
    }
    
    autosaveTimeout = setTimeout(async () => {
      const formData = new FormData(form);
      const data = {
        locked: formData.get('locked') || null,
        answers: {}
      };
      
      answerInputs.forEach(input => {
        const qNum = input.name.match(/q(\d+)/)[1];
        data.answers[qNum] = input.value;
      });
      
      try {
        const response = await fetch(`/quiz/${quizId}/autosave`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        
        if (response.ok) {
          if (autosaveStatus) {
            autosaveStatus.textContent = 'Saved';
            autosaveStatus.style.color = '#2e7d32';
            setTimeout(() => {
              if (autosaveStatus) autosaveStatus.textContent = '';
            }, 2000);
          }
        }
      } catch (e) {
        console.error('Autosave failed:', e);
        if (autosaveStatus) {
          autosaveStatus.textContent = 'Save failed';
          autosaveStatus.style.color = '#d32f2f';
        }
      }
    }, 2000);
  }

  // Review mode
  function showReview() {
    if (!reviewPanel || !reviewContent) return;
    
    const reviewItems = questionCards.map(card => {
      const qNum = card.dataset.questionNum;
      const qText = card.querySelector('.quiz-text').textContent.trim();
      const answerInput = form.querySelector(`input[name="q${qNum}"]`);
      const answer = answerInput ? answerInput.value.trim() : '';
      const isLocked = form.querySelector(`input[name="locked"][value="${card.dataset.questionId}"]`)?.checked;
      
      return `
        <div style="padding:12px;margin-bottom:12px;background:#2a2a2a;border-radius:6px;border:1px solid ${isLocked ? '#ffd700' : '#444'};">
          <div style="font-weight:bold;margin-bottom:4px;color:#ffd700;">Question ${qNum}${isLocked ? ' 🔒 (Locked)' : ''}</div>
          <div style="margin-bottom:8px;opacity:0.9;">${qText}</div>
          <div style="color:${answer ? '#fff' : '#888'};">
            <strong>Your answer:</strong> ${answer || '(not answered)'}
          </div>
        </div>
      `;
    }).join('');
    
    reviewContent.innerHTML = reviewItems;
    reviewPanel.style.display = 'block';
    form.querySelectorAll('.quiz-card').forEach(card => {
      card.style.opacity = '0.5';
      card.querySelectorAll('input').forEach(input => input.disabled = true);
    });
    if (reviewBtn) reviewBtn.style.display = 'none';
    if (submitBtn) submitBtn.style.display = 'none';
  }

  function hideReview() {
    if (!reviewPanel) return;
    reviewPanel.style.display = 'none';
    form.querySelectorAll('.quiz-card').forEach(card => {
      card.style.opacity = '1';
      card.querySelectorAll('input').forEach(input => input.disabled = false);
    });
    if (reviewBtn) reviewBtn.style.display = 'inline-block';
    if (submitBtn) submitBtn.style.display = 'inline-block';
  }

  // Keyboard navigation
  function setupKeyboardNav() {
    answerInputs.forEach((input, idx) => {
      input.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowDown' || e.key === 'Enter') {
          e.preventDefault();
          const next = answerInputs[idx + 1];
          if (next) {
            next.focus();
            next.select();
          } else {
            // Focus submit button if on last question
            if (submitBtn) submitBtn.focus();
          }
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          const prev = answerInputs[idx - 1];
          if (prev) {
            prev.focus();
            prev.select();
          }
        }
      });
    });
    
    // Ctrl/Cmd + Enter to submit
    form.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        if (submitBtn && !submitBtn.disabled) {
          submitBtn.click();
        }
      }
    });
  }

  // Event listeners
  answerInputs.forEach(input => {
    input.addEventListener('input', () => {
      updateProgress();
      autosave();
    });
  });

  lockRadios.forEach(radio => {
    radio.addEventListener('change', () => {
      autosave();
    });
  });

  if (reviewBtn) {
    reviewBtn.addEventListener('click', showReview);
  }

  if (editBtn) {
    editBtn.addEventListener('click', hideReview);
  }

  // Initial progress update
  updateProgress();

  // Setup keyboard navigation
  setupKeyboardNav();

  // Show autosave enabled message
  if (autosaveStatus) {
    autosaveStatus.textContent = 'Autosave enabled';
    autosaveStatus.style.color = '#2e7d32';
    setTimeout(() => {
      if (autosaveStatus) autosaveStatus.textContent = '';
    }, 3000);
  }
})();

