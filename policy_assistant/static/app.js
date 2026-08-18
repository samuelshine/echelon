const state = {
  documents: [],
  selected: new Set(),
  messages: [],
  busy: false,
  sources: new Map(),
};

const elements = {
  documentList: document.querySelector("#documentList"),
  selectAll: document.querySelector("#selectAll"),
  fileInput: document.querySelector("#fileInput"),
  uploadZone: document.querySelector("#uploadZone"),
  form: document.querySelector("#chatForm"),
  input: document.querySelector("#questionInput"),
  send: document.querySelector("#sendButton"),
  welcome: document.querySelector("#welcome"),
  stream: document.querySelector("#messageStream"),
  conversation: document.querySelector("#conversation"),
  contextLabel: document.querySelector("#contextLabel"),
  modeLabel: document.querySelector("#modeLabel"),
  newChat: document.querySelector("#newChat"),
  library: document.querySelector("#library"),
  scrim: document.querySelector("#scrim"),
  sourcePanel: document.querySelector("#sourcePanel"),
  sourceDetails: document.querySelector("#sourceDetails"),
  toastStack: document.querySelector("#toastStack"),
};

async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try { message = (await response.json()).error || message; } catch (_) {}
    throw new Error(message);
  }
  if (response.status === 204) return null;
  return response.json();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function icon(name) {
  const paths = {
    file: '<path d="M7 3h7l4 4v14H7z"/><path d="M14 3v5h5M10 13h5M10 17h5"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 14h10l1-14M10 11v6m4-6v6"/>',
    bot: '<path d="M6 8.5 12 5l6 3.5v8L12 20l-6-3.5v-8Z"/><path d="M9 11h6M9 14h4"/>',
  };
  return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name]}</svg>`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function toast(message, type = "info") {
  const node = document.createElement("div");
  node.className = `toast ${type}`;
  node.textContent = message;
  elements.toastStack.append(node);
  setTimeout(() => node.remove(), 4200);
}

async function loadSystem() {
  try {
    const [health, listing] = await Promise.all([api("/api/health"), api("/api/documents")]);
    elements.modeLabel.textContent = health.llm_mode === "llm" ? `Grounded · ${health.model}` : "Grounded · Demo mode";
    state.documents = listing.documents;
    state.selected = new Set(state.documents.map((doc) => doc.id));
    renderDocuments();
  } catch (error) {
    elements.modeLabel.textContent = "Service unavailable";
    elements.documentList.innerHTML = '<div class="empty-library">Could not load policies.</div>';
    toast(error.message, "error");
  }
}

function renderDocuments() {
  if (!state.documents.length) {
    elements.documentList.innerHTML = '<div class="empty-library">No policies yet. Add your first document below.</div>';
  } else {
    elements.documentList.innerHTML = state.documents.map((doc) => {
      const selected = state.selected.has(doc.id);
      return `
        <div class="document-item ${selected ? "selected" : ""}" data-document-id="${escapeHtml(doc.id)}" role="checkbox" aria-checked="${selected}" tabindex="0">
          <span class="doc-check">${icon(selected ? "check" : "file")}</span>
          <span class="doc-copy"><strong title="${escapeHtml(doc.name)}">${escapeHtml(doc.name)}</strong><small>${doc.chunk_count} passages · ${formatBytes(doc.size_bytes)}</small></span>
          <button class="delete-doc" data-delete-id="${escapeHtml(doc.id)}" aria-label="Delete ${escapeHtml(doc.name)}">${icon("trash")}</button>
        </div>`;
    }).join("");
  }
  const allSelected = state.documents.length > 0 && state.selected.size === state.documents.length;
  elements.selectAll.textContent = allSelected ? "Clear" : "Select all";
  elements.contextLabel.textContent = state.selected.size
    ? `${state.selected.size} ${state.selected.size === 1 ? "policy" : "policies"} in context`
    : "Select at least one policy";
  updateSendState();
}

function toggleDocument(id) {
  if (state.selected.has(id)) state.selected.delete(id);
  else state.selected.add(id);
  renderDocuments();
}

elements.documentList.addEventListener("click", async (event) => {
  const deleteButton = event.target.closest("[data-delete-id]");
  if (deleteButton) {
    event.stopPropagation();
    const id = deleteButton.dataset.deleteId;
    const doc = state.documents.find((item) => item.id === id);
    if (!doc || !window.confirm(`Remove “${doc.name}” from this policy library?`)) return;
    try {
      await api(`/api/documents/${encodeURIComponent(id)}`, { method: "DELETE" });
      state.documents = state.documents.filter((item) => item.id !== id);
      state.selected.delete(id);
      renderDocuments();
      toast("Policy removed.");
    } catch (error) { toast(error.message, "error"); }
    return;
  }
  const item = event.target.closest("[data-document-id]");
  if (item) toggleDocument(item.dataset.documentId);
});

elements.documentList.addEventListener("keydown", (event) => {
  if ((event.key === "Enter" || event.key === " ") && event.target.matches("[data-document-id]")) {
    event.preventDefault();
    toggleDocument(event.target.dataset.documentId);
  }
});

elements.selectAll.addEventListener("click", () => {
  if (state.selected.size === state.documents.length) state.selected.clear();
  else state.selected = new Set(state.documents.map((doc) => doc.id));
  renderDocuments();
});

async function uploadFiles(files) {
  for (const file of files) {
    const body = new FormData();
    body.append("file", file);
    elements.contextLabel.textContent = `Indexing ${file.name}…`;
    try {
      const result = await api("/api/documents", { method: "POST", body });
      if (!state.documents.some((doc) => doc.id === result.document.id)) state.documents.unshift(result.document);
      state.selected.add(result.document.id);
      toast(result.created ? `${file.name} is ready to search.` : `${file.name} is already indexed.`);
    } catch (error) { toast(`${file.name}: ${error.message}`, "error"); }
  }
  elements.fileInput.value = "";
  renderDocuments();
}

elements.fileInput.addEventListener("change", () => uploadFiles([...elements.fileInput.files]));
["dragenter", "dragover"].forEach((name) => elements.uploadZone.addEventListener(name, (event) => {
  event.preventDefault(); elements.uploadZone.classList.add("dragging");
}));
["dragleave", "drop"].forEach((name) => elements.uploadZone.addEventListener(name, (event) => {
  event.preventDefault(); elements.uploadZone.classList.remove("dragging");
}));
elements.uploadZone.addEventListener("drop", (event) => uploadFiles([...event.dataTransfer.files]));

function updateSendState() {
  elements.send.disabled = state.busy || !elements.input.value.trim() || state.selected.size === 0;
}

function resizeInput() {
  elements.input.style.height = "auto";
  elements.input.style.height = `${Math.min(elements.input.scrollHeight, 140)}px`;
  updateSendState();
}

elements.input.addEventListener("input", resizeInput);
elements.input.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    if (!elements.send.disabled) elements.form.requestSubmit();
  }
});

function renderAnswer(text, sources, messageId) {
  let html = escapeHtml(text);
  html = html.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/_([^_]+)_/g, "<em>$1</em>");
  html = html.replace(/\[(\d+)]/g, (_, index) => {
    const source = sources[Number(index) - 1];
    return source ? `<button class="citation-button" data-source-key="${messageId}:${index}" title="Open source ${index}">[${index}]</button>` : `[${index}]`;
  });
  const lines = html.split("\n");
  let inList = false;
  const output = [];
  for (const line of lines) {
    if (line.startsWith("- ")) {
      if (!inList) { output.push("<ul>"); inList = true; }
      output.push(`<li>${line.slice(2)}</li>`);
    } else {
      if (inList) { output.push("</ul>"); inList = false; }
      if (line.trim()) output.push(`<p>${line}</p>`);
    }
  }
  if (inList) output.push("</ul>");
  return output.join("");
}

function addUserMessage(text) {
  const message = document.createElement("article");
  message.className = "message user";
  message.innerHTML = `<div class="message-avatar">YOU</div><div class="message-body">${escapeHtml(text)}</div>`;
  elements.stream.append(message);
}

function addTyping() {
  const message = document.createElement("article");
  message.className = "message assistant";
  message.id = "typingMessage";
  message.innerHTML = `<div class="message-avatar">${icon("bot")}</div><div class="message-body"><div class="message-role">Policy assistant</div><div class="typing"><span></span><span></span><span></span></div></div>`;
  elements.stream.append(message);
}

function addAssistantMessage(result) {
  const messageId = `msg${Date.now()}`;
  result.sources.forEach((source, index) => state.sources.set(`${messageId}:${index + 1}`, source));
  const message = document.createElement("article");
  message.className = "message assistant";
  const sourceChips = result.sources.map((source, index) =>
    `<button class="source-chip" data-source-key="${messageId}:${index + 1}"><b>[${index + 1}]</b>${escapeHtml(source.document_name)} · ${escapeHtml(source.section)}</button>`
  ).join("");
  message.innerHTML = `
    <div class="message-avatar">${icon("bot")}</div>
    <div class="message-body">
      <div class="message-role">Policy assistant</div>
      <div class="answer-copy">${renderAnswer(result.answer, result.sources, messageId)}</div>
      ${sourceChips ? `<div class="source-strip">${sourceChips}</div>` : ""}
      <div class="answer-meta"><span class="mode-chip">${result.mode === "llm" ? "LLM grounded" : "Extractive demo"}</span><span>${result.latency_ms} ms</span><span>${escapeHtml(result.model)}</span></div>
    </div>`;
  elements.stream.append(message);
}

async function submitQuestion(question) {
  const text = question.trim();
  if (!text || state.busy || !state.selected.size) return;
  state.busy = true;
  elements.welcome.hidden = true;
  elements.stream.classList.add("active");
  addUserMessage(text);
  addTyping();
  // History sent with the *next* question is state.messages.slice(-7, -1), so
  // pushing here (before the excluded last slot) never affects this request's
  // own scan -- it only affects future turns. That is exactly why a turn that
  // gets rejected must be un-pushed on failure: left in place, a blocked
  // injection attempt (or anything else the safety cascade rejected) keeps
  // riding along as history and can trip the same rule on every later message
  // in the conversation, with no visible reason why.
  const pushedIndex = state.messages.push({ role: "user", content: text }) - 1;
  elements.input.value = "";
  resizeInput();
  scrollBottom();
  try {
    const result = await api("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: text,
        document_ids: [...state.selected],
        history: state.messages.slice(-7, -1),
      }),
    });
    document.querySelector("#typingMessage")?.remove();
    addAssistantMessage(result);
    state.messages.push({ role: "assistant", content: result.answer });
  } catch (error) {
    document.querySelector("#typingMessage")?.remove();
    addAssistantMessage({ answer: `I couldn't complete that request. ${error.message}`, sources: [], mode: "error", model: "—", latency_ms: 0 });
    state.messages.splice(pushedIndex, 1);
  } finally {
    state.busy = false;
    updateSendState();
    scrollBottom();
  }
}

function scrollBottom() {
  requestAnimationFrame(() => elements.conversation.scrollTo({ top: elements.conversation.scrollHeight, behavior: "smooth" }));
}

elements.form.addEventListener("submit", (event) => { event.preventDefault(); submitQuestion(elements.input.value); });
document.querySelectorAll("[data-question]").forEach((button) => button.addEventListener("click", () => submitQuestion(button.dataset.question)));

function resetChat() {
  state.messages = [];
  state.sources.clear();
  elements.stream.innerHTML = "";
  elements.stream.classList.remove("active");
  elements.welcome.hidden = false;
  elements.input.focus();
  closeLibrary();
}
elements.newChat.addEventListener("click", resetChat);
document.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); resetChat(); }
});

function openSource(key) {
  const source = state.sources.get(key);
  if (!source) return;
  elements.sourceDetails.innerHTML = `
    <div class="source-document">${escapeHtml(source.document_name)}</div>
    <div class="source-location">${escapeHtml(source.section)}${source.page ? ` · Page ${source.page}` : ""}</div>
    <div class="source-excerpt">${escapeHtml(source.excerpt)}</div>
    <div class="relevance"><span>Retrieved passage</span><span>${Math.round(source.score * 100)}% relevance</span></div>`;
  elements.sourcePanel.hidden = false;
  document.body.style.overflow = "hidden";
}
elements.stream.addEventListener("click", (event) => {
  const trigger = event.target.closest("[data-source-key]");
  if (trigger) openSource(trigger.dataset.sourceKey);
});
document.querySelectorAll("[data-close-source]").forEach((button) => button.addEventListener("click", () => {
  elements.sourcePanel.hidden = true; document.body.style.overflow = "";
}));

function openLibrary() { elements.library.classList.add("open"); elements.scrim.classList.add("open"); }
function closeLibrary() { elements.library.classList.remove("open"); elements.scrim.classList.remove("open"); }
document.querySelector("#openLibrary").addEventListener("click", openLibrary);
document.querySelector("#closeLibrary").addEventListener("click", closeLibrary);
elements.scrim.addEventListener("click", closeLibrary);

loadSystem();
