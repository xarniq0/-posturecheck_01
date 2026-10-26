const form = document.querySelector('#check-form');
const urlInput = document.querySelector('#url-input');
const submitButton = document.querySelector('#submit-button');
const errorMessage = document.querySelector('#error-message');
const loading = document.querySelector('#loading');
const results = document.querySelector('#results');
let busy = false;
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function statusLabel(status) {
  return ({present:'Observed', not_present:'Not present', not_applicable:'Not applicable', unknown:'Could not check'})[status] || 'Could not check';
}
function groupedChecks(checks) {
  const groups = [['Needs review', checks.filter(c => c.status === 'not_present' && c.severity === 'review')], ['Informational gaps', checks.filter(c => c.status === 'not_present' && c.severity !== 'review')], ['Could not be completed', checks.filter(c => c.status === 'unknown')], ['Observed or not applicable', checks.filter(c => ['present','not_applicable'].includes(c.status))]];
  return groups.filter(([, items]) => items.length).map(([title, items]) => `<section class="finding-group"><div class="group-heading"><h3>${title}</h3><span>${items.length}</span></div><div class="finding-list">${items.map(c => `<article class="finding ${c.status}"><div class="finding-top"><div><span class="category">${escapeHtml(c.category)}</span><h4>${escapeHtml(c.title)}</h4></div><span class="status-pill ${escapeHtml(c.status)}">${statusLabel(c.status)}</span></div><div class="evidence"><strong>Evidence</strong><p>${escapeHtml(c.evidence)}</p></div>${c.impact ? `<div class="finding-info"><div><strong>Potential impact</strong><p>${escapeHtml(c.impact)}</p></div><div><strong>Suggested next step</strong><p>${escapeHtml(c.remediation || 'Review this signal in the context of your site.')}</p></div></div>` : ''}<div class="confidence">Confidence <span>${escapeHtml(c.confidence)}</span></div></article>`).join('')}</div></section>`).join('');
}
function renderReport(report) {
  const s = report.summary;
  const score = s.score === null ? '—' : `${s.score}<small>/100</small>`;
  const note = s.score === null ? 'Not enough applicable checks completed to calculate a summary.' : `${s.completed} of ${s.total} checks completed. Unknown and not-applicable results are excluded from the weighted summary.`;
  results.innerHTML = `<div class="results-header"><div><div class="eyebrow"><span class="eyebrow-dot"></span> ASSESSMENT REPORT</div><h2>Review of <span>${escapeHtml(report.target)}</span></h2><p class="assessed">Assessed ${escapeHtml(new Date(report.assessed_at).toLocaleString())}</p></div><button class="secondary" id="download-report" type="button">↓ Download report</button></div><div class="summary-card"><div class="score-ring" aria-label="Weighted summary ${s.score === null ? 'not available' : s.score + ' out of 100'}"><span>${score}</span></div><div class="summary-copy"><span class="summary-label">POSTURE SUMMARY</span><h3>${escapeHtml(s.label)}</h3><p>${escapeHtml(note)}</p><small>This is a narrow snapshot of observed signals, not a guarantee about the website.</small></div><div class="checks-done"><strong>${s.completed}</strong><span>completed checks</span></div></div>${groupedChecks(report.checks)}<section class="ai-card"><div class="ai-card-heading"><span class="ai-mark" aria-hidden="true">✦</span><div><h3>AI security improvement ideas</h3><p>Get prioritized defensive suggestions based on this report.</p></div></div><button type="button" class="ai-button" id="ask-ai">Get AI suggestions <span aria-hidden="true">→</span></button><p class="ai-disclosure">Uses an external AI service. The current report is sent for this request only; the checker does not save it.</p><div id="ai-advice" class="ai-advice" role="status" aria-live="polite" hidden></div></section><div class="report-limit"><strong>Keep in mind</strong><p>${escapeHtml(report.limitations)}</p></div><div class="again"><button type="button" id="another-check" class="secondary">Run another check <span aria-hidden="true">↻</span></button></div>`;
  results.hidden = false;
  const ring = results.querySelector(".score-ring"); if (s.score !== null) ring.style.setProperty("--score", s.score);
  document.querySelector('#download-report').addEventListener('click', () => downloadReport(report));
  document.querySelector('#ask-ai').addEventListener('click', () => requestAdvice(report));
  document.querySelector('#another-check').addEventListener('click', () => { results.hidden = true; urlInput.focus(); window.scrollTo({top:0,behavior:'smooth'}); });
  results.focus?.();
}

async function requestAdvice(report) {
  const button = document.querySelector('#ask-ai'), output = document.querySelector('#ai-advice');
  if (!button || button.disabled) return;
  button.disabled = true; button.textContent = 'Preparing suggestions…'; output.hidden = false; output.classList.add('pending');
  output.textContent = 'Reviewing the observed findings and preparing practical recommendations…';
  try {
    const response = await fetch('/api/advice', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({report})});
    const data = await response.json(); if (!response.ok) throw new Error(data.error || 'AI advice could not be generated.');
    output.classList.remove('pending'); output.textContent = data.advice;
  } catch (error) { output.classList.remove('pending'); output.textContent = error.message || 'AI advice is temporarily unavailable. Please try again.'; }
  finally { button.disabled = false; button.textContent = 'Get AI suggestions →'; }
}

function downloadReport(report) {
  const safeReport = {target:report.target, assessed_at:report.assessed_at, summary:report.summary, checks:report.checks.map(({id,title,category,status,evidence,confidence,impact,remediation}) => ({id,title,category,status,evidence,confidence,impact,remediation})), limitations:report.limitations};
  const blob = new Blob([JSON.stringify(safeReport,null,2)], {type:'application/json'});
  const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = 'website-posture-report.json'; link.click(); URL.revokeObjectURL(link.href);
}
form.addEventListener('submit', async event => {
  event.preventDefault();
  if (busy) return;
  errorMessage.hidden = true; errorMessage.textContent = '';
  let parsed;
  try { parsed = new URL(urlInput.value.trim()); } catch { errorMessage.textContent = 'Enter a valid public website URL, such as https://example.com.'; errorMessage.hidden = false; urlInput.focus(); return; }
  if (!['http:','https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) { errorMessage.textContent = 'Use a public http:// or https:// URL without a username or password.'; errorMessage.hidden = false; urlInput.focus(); return; }
  busy = true; submitButton.disabled = true; submitButton.querySelector('.button-text').textContent = 'Checking…'; loading.hidden = false; results.hidden = true;
  try {
    const response = await fetch('/api/check', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:urlInput.value.trim()})});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'The check could not be completed.');
    renderReport(data);
  } catch (error) { errorMessage.textContent = error.message || 'A network error interrupted the check. Please try again.'; errorMessage.hidden = false; }
  finally { busy = false; submitButton.disabled = false; submitButton.querySelector('.button-text').textContent = 'Run passive check'; loading.hidden = true; }
});
