const $ = (id) => document.getElementById(id);

async function request(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

function showResult(element, html) {
  element.innerHTML = html;
  element.classList.remove("hidden");
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[char]));
}

async function refreshEvents() {
  const body = $("eventsBody");
  try {
    const { events } = await request("/api/events");
    if (!events.length) {
      body.innerHTML = '<tr><td colspan="6" class="empty">No activity yet. Generate a test link first.</td></tr>';
      return;
    }
    body.innerHTML = events.map(event => `
      <tr>
        <td>${escapeHtml(new Date(event.timestamp).toLocaleString())}</td>
        <td>${escapeHtml(event.campaignLabel || String(event.campaignId || "").slice(0, 8))}</td>
        <td>${escapeHtml(event.method)}</td>
        <td>${escapeHtml(event.classification)}</td>
        <td>${escapeHtml(event.confidence || "Not assessed")}</td>
        <td title="${escapeHtml(event.reason || "No reason stored")}" class="reason">${escapeHtml(event.reason || "Older event: no explanation stored")}</td>
      </tr>`).join("");
  } catch (error) {
    body.innerHTML = `<tr><td colspan="6" class="empty">${escapeHtml(error.message)}</td></tr>`;
  }
}

$("createCampaign").addEventListener("click", async () => {
  const button = $("createCampaign");
  button.disabled = true;
  try {
    const data = await request("/api/campaigns", {
      method: "POST",
      body: JSON.stringify({ label: $("campaignLabel").value })
    });
    showResult($("linkResult"), `<strong>Your controlled test link:</strong><br><a href="${escapeHtml(data.trackingUrl)}" target="_blank" rel="noopener">${escapeHtml(data.trackingUrl)}</a><br><br>Use only with your own test account. Opening it records a visit; no credentials are requested.`);
    await refreshEvents();
  } catch (error) {
    showResult($("linkResult"), escapeHtml(error.message));
  } finally {
    button.disabled = false;
  }
});

$("analyzeUrl").addEventListener("click", async () => {
  try {
    const data = await request("/api/analyze-url", {
      method: "POST",
      body: JSON.stringify({ url: $("urlInput").value })
    });
    const indicators = data.indicators.map(item => `<li>${escapeHtml(item)}</li>`).join("");
    showResult($("analysisResult"), `<strong>Risk: ${escapeHtml(data.risk)} (${data.score}/100)</strong><ul>${indicators}</ul><small>This is a heuristic assessment, not a guarantee that a URL is safe or malicious.</small>`);
  } catch (error) {
    showResult($("analysisResult"), escapeHtml(error.message));
  }
});

$("refresh").addEventListener("click", refreshEvents);
refreshEvents();
