// ─── SHARED UTILITIES ───────────────────────────────────────────

const NVDAPI = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CISAAPI = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

// Set active nav link
function setActiveNav() {
  const page = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav-link').forEach(link => {
    const href = link.getAttribute('href');
    if (href === page || (page === '' && href === 'index.html')) {
      link.classList.add('active');
    }
  });
}

// Format date
function fmtDate(str) {
  if (!str) return '—';
  return new Date(str).toLocaleDateString('it-IT', { day: '2-digit', month: 'short', year: 'numeric' });
}

// Format CVSS score to severity
function cvssToSeverity(score) {
  if (score === null || score === undefined) return 'NONE';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0)    return 'LOW';
  return 'NONE';
}

// Get CVSS score from NVD CVE item
function getCVSS(cve) {
  const m = cve.metrics;
  if (!m) return null;
  if (m.cvssMetricV31?.length) return m.cvssMetricV31[0].cvssData.baseScore;
  if (m.cvssMetricV30?.length) return m.cvssMetricV30[0].cvssData.baseScore;
  if (m.cvssMetricV2?.length)  return m.cvssMetricV2[0].cvssData.baseScore;
  return null;
}

// Score bar color
function scoreColor(score) {
  if (score >= 9.0) return 'var(--critical)';
  if (score >= 7.0) return 'var(--high)';
  if (score >= 4.0) return 'var(--yellow)';
  return 'var(--green)';
}

// Truncate description
function truncate(str, n = 120) {
  if (!str) return '—';
  return str.length > n ? str.slice(0, n) + '…' : str;
}

// Get description from NVD CVE item
function getDesc(cve) {
  const d = cve.descriptions?.find(x => x.lang === 'en');
  return d?.value || 'No description available.';
}

// Render navbar
function renderNavbar(activePage) {
  const nav = document.getElementById('navbar');
  if (!nav) return;
  nav.innerHTML = `
    <a class="nav-brand" href="index.html">
      <div class="nav-brand-icon">SX</div>
      <span class="nav-brand-text">SECUR<span>EX</span></span>
    </a>
    <nav class="nav-links">
      <a class="nav-link ${activePage==='dashboard'?'active':''}" href="index.html">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        Dashboard
      </a>
      <a class="nav-link ${activePage==='cve'?'active':''}" href="cve.html">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        CVE Explorer
      </a>
      <a class="nav-link ${activePage==='about'?'active':''}" href="about.html">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        About
      </a>
    </nav>
    <div class="nav-right">
      <div class="status-pill">
        <div class="status-dot"></div>
        <span>NVD Live</span>
      </div>
    </div>
  `;
}

// Render footer
function renderFooter() {
  const f = document.getElementById('footer');
  if (!f) return;
  f.innerHTML = `
    <span>SECUREX — Jacopo Coniglio · Security Engineer</span>
    <span>Data: NIST NVD · CISA KEV · ${new Date().getFullYear()}</span>
  `;
}
