// RDA_BOTS/pii_sanitizer_bot/frontend/app.js

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

const jsonInput = $("#jsonInput");
const methodSel = $("#method");
const beforeDiv = $("#before");
const afterDiv = $("#after");
const auditDiv = $("#audit");
const btnSanitize = $("#btnSanitize");
const btnSample = $("#btnSample");
const btnDownloadJson = $("#btnDownloadJson");
const btnDownloadCsv = $("#btnDownloadCsv");
const fileInput = $("#fileInput");

let lastSanitized = null; // cache last result for downloads

btnSample.addEventListener("click", () => {
  const sample = [
    {
      name: "Alice Johnson",
      email: "alice@example.com",
      note: "Ship to 221B Baker Street, London NW1 6XE. Call at +1 415-555-2671. Card 4111-1111-1111-1111.",
      address: "742 Evergreen Terrace, Springfield, IL 62704",
      ssn: "123-45-6789",
    },
    {
      full_name: "John Doe",
      email: "john123@gmail.com",
      note: "Meet at 1600 Pennsylvania Ave NW, Washington, DC 20500. SSN 987-65-4320.",
      phone: "(212) 555-7890",
      misc: "No PII here",
    },
  ];
  jsonInput.value = JSON.stringify(sample, null, 2);
});

fileInput.addEventListener("change", async (e) => {
  const file = e.target.files?.[0];
  if (!file) return;
  const text = await file.text();
  jsonInput.value = text;
});

btnSanitize.addEventListener("click", async () => {
  clearOutputs();
  let rows;
  try {
    rows = JSON.parse(jsonInput.value || "[]");
    if (!Array.isArray(rows))
      throw new Error("Input must be a JSON array of objects");
  } catch (err) {
    alert("Invalid JSON: " + err.message);
    return;
  }

  const method = methodSel.value || undefined;
  const body = {
    input_data: rows,
    query_params: method
      ? { method, return_audit: true }
      : { return_audit: true },
  };

  try {
    const res = await fetch("/api/sanitize", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data?.error || res.statusText);

    renderTable(beforeDiv, rows);
    renderTable(afterDiv, data.data || []);
    renderAudit(auditDiv, data.audit || []);
    lastSanitized = data.data || [];
    btnDownloadJson.disabled = !lastSanitized.length;
    btnDownloadCsv.disabled = !lastSanitized.length;
  } catch (err) {
    alert("Sanitize failed: " + err.message);
  }
});

btnDownloadJson.addEventListener("click", () => {
  if (!lastSanitized) return;
  downloadBlob(
    JSON.stringify(lastSanitized, null, 2),
    "sanitized_output.json",
    "application/json"
  );
});

btnDownloadCsv.addEventListener("click", () => {
  if (!lastSanitized) return;
  const csv = toCsv(lastSanitized);
  downloadBlob(csv, "sanitized_output.csv", "text/csv");
});

// ---------- helpers ----------

function clearOutputs() {
  beforeDiv.innerHTML = "";
  afterDiv.innerHTML = "";
  auditDiv.innerHTML = "";
  btnDownloadJson.disabled = true;
  btnDownloadCsv.disabled = true;
}

function renderTable(container, rows) {
  if (!rows.length) {
    container.innerHTML = "<div class='empty'>No rows</div>";
    return;
  }
  const cols = Array.from(
    rows.reduce((set, r) => {
      Object.keys(r || {}).forEach((k) => set.add(k));
      return set;
    }, new Set())
  );

  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const trh = document.createElement("tr");
  cols.forEach((c) => {
    const th = document.createElement("th");
    th.textContent = c;
    trh.appendChild(th);
  });
  thead.appendChild(trh);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  rows.forEach((r) => {
    const tr = document.createElement("tr");
    cols.forEach((c) => {
      const td = document.createElement("td");
      const val = r && r[c] !== undefined ? r[c] : "";
      td.textContent =
        typeof val === "object" ? JSON.stringify(val) : String(val);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);

  container.innerHTML = "";
  container.appendChild(table);
}

function renderAudit(container, auditRows) {
  // auditRows: list per row -> list of events
  const flat = [];
  auditRows.forEach((events, rowIdx) => {
    (events || []).forEach((evt) => flat.push({ row: rowIdx + 1, ...evt }));
  });

  if (!flat.length) {
    container.innerHTML = "<div class='empty'>No audit events</div>";
    return;
  }

  const cols = [
    "row",
    "column",
    "type",
    "action",
    "original_preview",
    "replacement_preview",
  ];
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const trh = document.createElement("tr");
  cols.forEach((c) => {
    const th = document.createElement("th");
    th.textContent = c;
    trh.appendChild(th);
  });
  thead.appendChild(trh);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  flat.forEach((e) => {
    const tr = document.createElement("tr");
    cols.forEach((c) => {
      const td = document.createElement("td");
      td.textContent = e[c] ?? "";
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);

  container.innerHTML = "";
  container.appendChild(table);
}

function downloadBlob(text, filename, type) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// very small CSV helper (no quotes escaping for nested commas in objects)
function toCsv(rows) {
  const cols = Array.from(
    rows.reduce((set, r) => {
      Object.keys(r || {}).forEach((k) => set.add(k));
      return set;
    }, new Set())
  );
  const header = cols.join(",");
  const lines = rows.map((r) =>
    cols
      .map((c) => {
        const v = r && r[c] !== undefined ? r[c] : "";
        const s = typeof v === "object" ? JSON.stringify(v) : String(v);
        // basic escaping
        const needs = s.includes(",") || s.includes('"') || s.includes("\n");
        return needs ? `"${s.replace(/"/g, '""')}"` : s;
      })
      .join(",")
  );
  return [header, ...lines].join("\n");
}
