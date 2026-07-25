const LABELS = ['prompt_injection','system_prompt_leakage','malicious_code','toxicity_harm','adversarial_obfuscation','benign'];
const state = { item: null, expert: false };
const $ = (id) => document.getElementById(id);
LABELS.forEach(label => {
  const node = document.createElement('label');
  node.innerHTML = `<input type="checkbox" name="labels" value="${label}"> ${label.replaceAll('_', ' ')}`;
  $('labels').appendChild(node);
});

fetch('/api/config').then(response => response.json()).then(config => {
  if (config.assigned_reviewer_id) {
    $('reviewer-id').value = config.assigned_reviewer_id;
    $('reviewer-id').disabled = true;
  }
  if (config.assigned_role) {
    $('role').value = config.assigned_role;
    $('role').disabled = true;
  }
  if (config.local_token) {
    $('token').value = config.local_token;
    $('token').disabled = true;
  }
});

function headers() { return {'Content-Type':'application/json', 'X-Review-Token':$('token').value}; }
async function loadNext() {
  state.expert = $('role').value === 'expert';
  const query = new URLSearchParams({reviewer_id:$('reviewer-id').value, role:$('role').value});
  const response = await fetch(`/api/next?${query}`, {headers:headers()});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Unable to load item');
  if (!data) {
    $('workspace').classList.add('hidden'); $('done').classList.remove('hidden');
    const progress = await fetch('/api/progress', {headers:headers()}).then(r => r.json());
    $('progress').textContent = JSON.stringify(progress, null, 2); return;
  }
  state.item = data.item;
  $('family').textContent = data.item.family || 'unknown family';
  $('transformation').textContent = data.item.transformation || 'untransformed';
  $('prompt').textContent = data.item.text;
  $('prior').classList.toggle('hidden', !state.expert);
  $('prior').textContent = state.expert ? `Primary decisions:\n${JSON.stringify(data.primary_reviews, null, 2)}` : '';
  $('review-form').reset(); $('error').textContent = '';
}
$('begin').onclick = async () => {
  try { await loadNext(); $('login').classList.add('hidden'); $('workspace').classList.remove('hidden'); }
  catch (error) { alert(error.message); }
};
$('review-form').onsubmit = async (event) => {
  event.preventDefault(); const form = new FormData(event.target);
  const decision = form.get('decision');
  let labels = form.getAll('labels');
  if (decision === 'benign') labels = ['benign'];
  if (decision === 'exclude') labels = [];
  const payload = {item_id:state.item.candidate_id || state.item.item_id, reviewer_id:$('reviewer-id').value,
    decision, labels, rationale_code:form.get('rationale_code'), notes:form.get('notes') || null,
    naturalness:Number(form.get('naturalness')), intent_correct:form.has('intent_correct'),
    labels_correct:form.has('labels_correct'), non_operational:form.has('non_operational'),
    is_expert_adjudication:state.expert};
  const response = await fetch('/api/reviews', {method:'POST', headers:headers(), body:JSON.stringify(payload)});
  const data = await response.json();
  if (!response.ok) { $('error').textContent = data.error || 'Save failed'; return; }
  await loadNext();
};
