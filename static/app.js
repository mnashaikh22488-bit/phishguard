/**
 * PhishGuard frontend – link/email checks, reports, stats, quiz, AI chat
 */

const API = {
  checkLink: "/api/check-link",
  checkEmail: "/api/check-email",
  report: "/api/report",
  chat: "/api/chat",
  stats: "/api/stats",
};

// ---------- Helpers ----------
function $(sel) {
  return document.querySelector(sel);
}

function riskClass(classification) {
  if (classification === "HIGH RISK") return "risk-high";
  if (classification === "SUSPICIOUS") return "risk-mid";
  return "risk-low";
}

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

// ---------- Stats ----------
async function loadStats() {
  try {
    const s = await fetch(API.stats).then((r) => r.json());
    $("#statLinks").textContent = (s.links_checked || 0).toLocaleString();
    $("#statEmails").textContent = (s.emails_checked || 0).toLocaleString();
    $("#statReports").textContent = (s.reports_submitted || 0).toLocaleString();
    $("#statHighRisk").textContent = (s.high_risk_detections || 0).toLocaleString();
  } catch (_) {
    /* ignore */
  }
}

// ---------- Link checker ----------
$("#analyzeLinkBtn").addEventListener("click", async () => {
  const url = $("#linkInput").value.trim();
  const box = $("#linkResult");
  if (!url) {
    box.classList.remove("hidden");
    box.innerHTML = "<p>Please paste a URL to analyze.</p>";
    return;
  }
  box.classList.remove("hidden");
  box.innerHTML = "<p class='msg typing'>Analyzing structure…</p>";
  try {
    const data = await postJSON(API.checkLink, { url });
    const items = (data.indicators || []).map((i) => `<li>${escapeHtml(i)}</li>`).join("");
    box.innerHTML = `
      <span class="risk-badge ${riskClass(data.classification)}">${escapeHtml(data.classification)}</span>
      <p><strong>Risk Score:</strong> ${data.score}/100</p>
      <p><strong>Why was this flagged?</strong></p>
      <ul>${items}</ul>
      <p class="disclaimer">${escapeHtml(data.disclaimer || "")}</p>
    `;
    loadStats();
  } catch (e) {
    box.innerHTML = `<p>Error: ${escapeHtml(e.message)}</p>`;
  }
});

// ---------- Email checker ----------
$("#analyzeEmailBtn").addEventListener("click", async () => {
  const text = $("#emailInput").value.trim();
  const box = $("#emailResult");
  if (!text) {
    box.classList.remove("hidden");
    box.innerHTML = "<p>Please paste a message to analyze.</p>";
    return;
  }
  box.classList.remove("hidden");
  box.innerHTML = "<p class='msg typing'>Analyzing patterns…</p>";
  try {
    const data = await postJSON(API.checkEmail, { text });
    const items = (data.indicators || [])
      .map((i) => `<li>⚠ ${escapeHtml(i)}</li>`)
      .join("");
    box.innerHTML = `
      <span class="risk-badge ${riskClass(data.classification)}">${escapeHtml(data.classification)} — ${data.score}/100</span>
      <p><strong>Detected indicators</strong></p>
      <ul>${items}</ul>
      <p class="disclaimer">${escapeHtml(data.explanation || "")}</p>
    `;
    loadStats();
  } catch (e) {
    box.innerHTML = `<p>Error: ${escapeHtml(e.message)}</p>`;
  }
});

// ---------- Report ----------
$("#reportForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const report_type = $("#reportType").value;
  const content = $("#reportContent").value.trim();
  const reason = $("#reportReason").value.trim();
  const box = $("#reportMsg");
  box.classList.remove("hidden");
  try {
    const data = await postJSON(API.report, { report_type, content, reason });
    box.innerHTML = `<p class="success-msg">✓ ${escapeHtml(data.message || "Report submitted successfully.")}</p>`;
    $("#reportForm").reset();
    loadStats();
  } catch (err) {
    box.innerHTML = `<p>Error: ${escapeHtml(err.message)}</p>`;
  }
});

// ---------- Quiz ----------
$("#quizOptions").addEventListener("click", (e) => {
  const btn = e.target.closest("button");
  if (!btn || btn.disabled) return;
  const correct = btn.dataset.correct === "true";
  const feedback = $("#quizFeedback");
  const buttons = $("#quizOptions").querySelectorAll("button");
  buttons.forEach((b) => {
    b.disabled = true;
    if (b.dataset.correct === "true") b.classList.add("correct");
  });
  if (!correct) btn.classList.add("wrong");
  feedback.classList.remove("hidden");
  feedback.textContent = correct
    ? "Correct! Always verify through an official channel and never share OTPs."
    : "Not quite. The safe choice is B — ignore and verify through the official channel.";
  feedback.style.color = correct ? "var(--ok)" : "var(--warn)";
});

// ---------- Chat (shared logic for main panel + floating window) ----------
const WELCOME =
  "Hi! I’m PhishGuard AI. I can help you understand suspicious links, phishing emails, scams, and online safety.";

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function appendMessage(container, role, text) {
  const div = document.createElement("div");
  div.className = `msg ${role}`;
  div.textContent = text;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return div;
}

function initChat(messagesEl, inputEl, sendBtn, clearBtn, promptsEl) {
  if (!messagesEl.dataset.ready) {
    appendMessage(messagesEl, "ai", WELCOME);
    messagesEl.dataset.ready = "1";
  }

  async function send() {
    const text = inputEl.value.trim();
    if (!text) return;
    inputEl.value = "";
    appendMessage(messagesEl, "user", text);
    const typing = appendMessage(messagesEl, "ai typing", "Thinking…");
    try {
      const data = await postJSON(API.chat, { message: text });
      typing.remove();
      appendMessage(messagesEl, "ai", data.reply || "No response.");
    } catch (err) {
      typing.remove();
      appendMessage(messagesEl, "ai", "Sorry, something went wrong. Please try again.");
    }
  }

  sendBtn.addEventListener("click", send);
  inputEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  });

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      messagesEl.innerHTML = "";
      messagesEl.dataset.ready = "";
      appendMessage(messagesEl, "ai", WELCOME);
      messagesEl.dataset.ready = "1";
    });
  }

  if (promptsEl) {
    promptsEl.addEventListener("click", (e) => {
      const chip = e.target.closest(".chip");
      if (!chip) return;
      inputEl.value = chip.textContent;
      send();
    });
  }
}

// Main AI section
initChat(
  $("#chatMessagesMain"),
  $("#chatInputMain"),
  $("#sendChatMain"),
  $("#clearChatMain"),
  $("#quickPromptsMain")
);

// Floating chat
initChat(
  $("#chatMessagesFloat"),
  $("#chatInputFloat"),
  $("#sendChatFloat"),
  $("#clearChatFloat"),
  $("#quickPromptsFloat")
);

function openChat() {
  $("#chatWindow").classList.remove("hidden");
}

function closeChat() {
  $("#chatWindow").classList.add("hidden");
}

$("#fabChat").addEventListener("click", () => {
  const win = $("#chatWindow");
  win.classList.toggle("hidden");
});
$("#closeChat").addEventListener("click", closeChat);
$("#openChatBtn").addEventListener("click", openChat);
$("#heroChatBtn").addEventListener("click", openChat);

// Mobile nav
$("#navToggle").addEventListener("click", () => {
  $("#navLinks").classList.toggle("open");
});
$("#navLinks").addEventListener("click", (e) => {
  if (e.target.tagName === "A") $("#navLinks").classList.remove("open");
});

// Boot
loadStats();