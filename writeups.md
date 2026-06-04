---
layout: single
title: "Writeups"
permalink: /writeups/
---

<div class="writeups-filters">
  <input type="text" id="writeup-search" placeholder="Buscar..." class="search-input">
  <select id="difficulty-filter" class="filter-select">
    <option value="">Dificultad</option>
    <option value="fácil">Fácil</option>
    <option value="medio">Medio</option>
    <option value="difícil">Difícil</option>
  </select>
  <select id="os-filter" class="filter-select">
    <option value="">Sistema</option>
    <option value="linux">Linux</option>
    <option value="windows">Windows</option>
  </select>
</div>

<div class="writeups-list" id="writeups-list">
{% for writeup in site.writeups reversed %}
  <article class="writeup-card"
       data-title="{{ writeup.title | downcase }}"
       data-tags="{{ writeup.tags | join: ' ' | downcase }}"
       data-difficulty="{{ writeup.difficulty | downcase }}"
       data-os="{{ writeup.operating_system | downcase }}">
    <div class="writeup-card__header">
      <h2 class="writeup-card__title">
        <a href="{{ writeup.url | relative_url }}">{{ writeup.title | remove: " - Writeup" }}</a>
      </h2>
    </div>
    <div class="writeup-card__meta">
      <div class="writeup-card__tags">
        {% for tag in writeup.tags %}
          {% unless tag == "HTB" or tag == writeup.difficulty or tag == writeup.operating_system %}
        <span class="writeup-card__tag">{{ tag }}</span>
          {% endunless %}
        {% endfor %}
      </div>
      <div class="writeup-card__info-line">
        <span class="writeup-card__meta-info">{{ writeup.difficulty }} · {{ writeup.operating_system }} · HackTheBox</span>
        <time class="writeup-card__date" datetime="{{ writeup.date | date_to_xmlschema }}">{{ writeup.date | date: "%d/%m/%Y" }}</time>
      </div>
    </div>
  </article>
{% endfor %}
</div>

<div class="no-results" id="no-results" style="display: none;">
  <p>No se encontraron writeups con los filtros seleccionados.</p>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
  var searchInput = document.getElementById('writeup-search');
  var difficultyFilter = document.getElementById('difficulty-filter');
  var osFilter = document.getElementById('os-filter');
  var writeupCards = document.querySelectorAll('.writeup-card');
  var noResults = document.getElementById('no-results');

  function filterWriteups() {
    var searchTerm = searchInput.value.toLowerCase();
    var difficulty = difficultyFilter.value.toLowerCase();
    var os = osFilter.value.toLowerCase();
    var visibleCount = 0;

    writeupCards.forEach(function(card) {
      var title = card.dataset.title;
      var tags = card.dataset.tags || '';
      var itemDifficulty = card.dataset.difficulty || '';
      var itemOs = card.dataset.os || '';

      var matchesSearch = !searchTerm || title.indexOf(searchTerm) !== -1 || tags.indexOf(searchTerm) !== -1;
      var matchesDifficulty = !difficulty || itemDifficulty === difficulty;
      var matchesOs = !os || itemOs.indexOf(os) !== -1;

      if (matchesSearch && matchesDifficulty && matchesOs) {
        card.style.display = '';
        visibleCount++;
      } else {
        card.style.display = 'none';
      }
    });

    noResults.style.display = visibleCount === 0 ? 'block' : 'none';
  }

  searchInput.addEventListener('input', filterWriteups);
  difficultyFilter.addEventListener('change', filterWriteups);
  osFilter.addEventListener('change', filterWriteups);
});
</script>
