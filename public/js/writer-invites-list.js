(function(){
  document.addEventListener('click', function(e){
    var btn = e.target.closest('.copy');
    if (!btn) return;
    var link = btn.getAttribute('data-link');
    if (!link) return;
    navigator.clipboard.writeText(link).then(function(){
      var old = btn.textContent; btn.textContent = 'Copied';
      setTimeout(function(){ btn.textContent = old; }, 800);
    }).catch(function(){});
  });
})();




