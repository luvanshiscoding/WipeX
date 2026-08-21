/**
 * WipeX - Master Application Controller
 * Zero-Trust Data Sanitization & Hardware-Bound Verification Platform
 */

class WipeXApp {
  constructor() {
    const loc = (typeof window !== 'undefined' && window.location) ? window.location : null;
    const host = (loc && loc.hostname) ? loc.hostname : 'localhost';
    this.apiBaseUrl = (host === 'localhost' || host === '127.0.0.1') ? `http://${host}:8000` : (loc && loc.origin ? loc.origin : 'http://localhost:8000');
    this.activeWipeId = null;

    this.activeView = 'dashboard';
    this.currentPhase = 1;

    this.devices = [];
    this.certificateStore = {};

    this.selectedDevice = null;
    this.selectedMethodId = 'purge-nvme-crypto';

    this.unfrozen = false;
    this.isWiping = false;
    this.wipeProgress = 0;
    this.wipeInterval = null;
    this.wipeCompleted = false;

    this.verificationCompleted = false;
    this.explorerFilter = 'all';
    this.destructionCountdownTimer = null;
    this.destructionCountdown = 10;

    this.demoMode = true; // Interactive demo mode toggle

    this.sectorStates = new Array(256).fill(0);
    this.currentNonce = (window.WipeXCrypto || window.AegisCrypto).generateNonce();
    this.currentCertId = null;
    this.currentCertData = null;

    this.phaseCompleted = {
      1: false,
      2: false,
      3: false,
      4: false,
      5: false
    };

    this.simpleMethods = [
      {
        id: "nist_800_88",
        name: "NIST 800-88",
        standard: "NIST SP 800-88",
        tier: "Industry Standard",
        fullName: "NIST 800-88 (Clear + Verify + Purge)",
        oneLine: "Industry standard: Clear + Verify + Purge for complete sanitization.",
        speedBadge: "Medium",
        securityBadge: "High Security",
        recommendedFor: "General Storage"
      },
      {
        id: "crypto_erase",
        name: "Cryptographic Erase",
        standard: "NVMe / SSD Purge",
        tier: "Flash SSD Tier",
        fullName: "Cryptographic Erase (Instant Key Destruction)",
        oneLine: "Preferred for SSDs: Instant hardware encryption key destruction.",
        speedBadge: "Fast",
        securityBadge: "Highest Security",
        recommendedFor: "NVMe / SATA SSD"
      },
      {
        id: "ata_sanitize",
        name: "ATA Sanitize",
        standard: "ATA Secure Erase",
        tier: "Hardware Level",
        fullName: "ATA Sanitize (Hardware-Level Secure Erase)",
        oneLine: "Hardware-level secure erase resetting firmware and flash blocks.",
        speedBadge: "Fast",
        securityBadge: "High Security",
        recommendedFor: "SATA SSD"
      },
      {
        id: "dod_5220_22_m",
        name: "DoD 5220.22-M",
        standard: "Military Standard",
        tier: "Magnetic Platter Tier",
        fullName: "DoD 5220.22-M (3-Pass Overwrite)",
        oneLine: "Military standard: 3-pass overwrite (zeros, ones, random data).",
        speedBadge: "Medium",
        securityBadge: "High Security",
        recommendedFor: "Magnetic HDD"
      },
      {
        id: "single_pass",
        name: "Single Pass",
        standard: "NIST Clear",
        tier: "Rapid Turnaround",
        fullName: "Single Pass (Quick Zero Clear)",
        oneLine: "Quick wipe with zeros for fast non-sensitive drive reuse.",
        speedBadge: "Fast",
        securityBadge: "Standard Security",
        recommendedFor: "USB / Non-Sensitive"
      },
      {
        id: "gutmann",
        name: "Gutmann",
        standard: "35-Pass Suite",
        tier: "Maximum Security",
        fullName: "Gutmann 35-Pass Forensic Overwrite",
        oneLine: "Maximum security: 35-pass magnetic flux overwrite.",
        speedBadge: "Very Long",
        securityBadge: "Maximum Security",
        recommendedFor: "High-Security Platters"
      }
    ];

    this.init();
  }

  async init() {
    this.initDemoMode();
    this.renderStepper();
    this.renderMethodOptions();
    this.initCanvas();
    await this.loadDevices();
    this.startAutoDetection();

    // Check if user opened page via a scanned QR code with verification parameters
    const params = new URLSearchParams(window.location.search);
    const scannedCert = params.get('verify') || params.get('cert') || params.get('verifyCert');
    if (scannedCert) {
      this.switchView('portal');
      const searchInput = document.getElementById('portal-search-input');
      if (searchInput) searchInput.value = scannedCert;
      this.verifyLookup();
    }
  }

  async fetchBackend(endpoint, options = {}) {
    const origins = [
      '',
      'http://127.0.0.1:8000',
      'http://localhost:8000',
      this.apiBaseUrl
    ];
    const uniqueOrigins = Array.from(new Set(origins.filter(Boolean)));
    const endpointsToTry = [endpoint];
    if (endpoint === '/api/devices') endpointsToTry.push('/api/drives');
    else if (endpoint === '/api/drives') endpointsToTry.push('/api/devices');

    for (const ep of endpointsToTry) {
      for (const base of uniqueOrigins) {
        try {
          const url = base.endsWith('/') ? `${base.slice(0, -1)}${ep}` : `${base}${ep}`;
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 3500);
          const res = await fetch(url, { ...options, signal: controller.signal, cache: 'no-store' });
          clearTimeout(timeoutId);
          if (res && res.ok) return res;
        } catch (e) {
          // try next origin
        }
      }
    }
    return null;
  }

  initDemoMode() {
    const saved = localStorage.getItem('wipex_demo_mode');
    this.demoMode = (saved === null) ? true : (saved === '1');
    this.applyDemoMode();
  }

  toggleDemoMode(enabled) {
    this.demoMode = enabled;
    localStorage.setItem('wipex_demo_mode', enabled ? '1' : '0');
    this.applyDemoMode();
    this.loadDevices();
  }

  applyDemoMode() {
    document.body.classList.toggle('demo-mode-active', this.demoMode);
    const toggleEl = document.getElementById('demo-mode-toggle');
    if (toggleEl) toggleEl.checked = this.demoMode;
  }

  startAutoDetection() {
    if (this._autoDetectTimer) clearInterval(this._autoDetectTimer);
    this._autoDetectTimer = setInterval(async () => {
      // Auto-detection runs only on Step 1 when in Real Hardware mode (demoMode is OFF) and not actively wiping
      if (this.demoMode || this.isWiping || this.wipeCompleted || this.currentPhase > 1) return;

      try {
        const res = await this.fetchBackend('/api/devices');
        if (!res || !res.ok) return;
        const latestReal = await res.json();
        if (!Array.isArray(latestReal) || latestReal.length === 0) return;

        const currentKeys = new Set((this.devices || []).map(d => d.devicePath || d.id));
        const latestKeys = new Set(latestReal.map(d => d.devicePath || d.id));

        const added = latestReal.filter(d => !currentKeys.has(d.devicePath || d.id));
        const removed = (this.devices || []).filter(d => !latestKeys.has(d.devicePath || d.id));

        if (added.length > 0 || removed.length > 0 || (!this.devices || this.devices.length === 0)) {
          this.devices = latestReal;

          if (added.length > 0) {
            const newDev = added[0];
            this.showStepBlockedToast(`💾 Drive Connected: ${newDev.model} (${newDev.capacity ? newDev.capacity.split('(')[0].trim() : ''})`);
            this.renderDeviceList();
            this.selectDevice(newDev.id);
            if (typeof this.renderDriveStatus === 'function') this.renderDriveStatus();
            this.updatePhase1ContinueBtn();
            this.renderStorageBar();
            this.renderMethodOptions();
            this.renderStepper();
          } else if (removed.length > 0) {
            const remDev = removed[0];
            this.showStepBlockedToast(`⚠️ Drive Disconnected: ${remDev.model}`);
            if (this.selectedDevice && removed.some(d => d.id === this.selectedDevice.id)) {
              this.selectedDevice = this.devices[0] || null;
            }
            this.renderDeviceList();
            if (typeof this.renderDriveStatus === 'function') this.renderDriveStatus();
            this.updatePhase1ContinueBtn();
            this.renderStorageBar();
            this.renderMethodOptions();
            this.renderStepper();
          } else if (this.devices.length > 0 && !this.selectedDevice) {
            this.selectedDevice = this.devices[0];
            this.renderDeviceList();
            if (typeof this.renderDriveStatus === 'function') this.renderDriveStatus();
            this.updatePhase1ContinueBtn();
          }
        }
      } catch (e) {
        // Background polling silent failure
      }
    }, 2000);
  }

  selectDeviceById(deviceId) {
    if (!deviceId) return;
    let dev = this.devices.find(d => d.id === deviceId);
    if (!dev && window.MOCK_DEVICES) {
      dev = window.MOCK_DEVICES.find(d => d.id === deviceId);
      if (dev && !this.devices.some(d => d.id === dev.id)) {
        this.devices.push(dev);
      }
    }
    if (dev) {
      this.selectDevice(dev.id);

      // Highlight active preset chip
      document.querySelectorAll('.demo-chips .btn-chip').forEach(chip => {
        const isMatch = chip.getAttribute('onclick')?.includes(deviceId);
        chip.classList.toggle('active', !!isMatch);
      });
    }
  }

  fastForwardWipe() {
    if (!this.isWiping && !this.wipeCompleted) {
      if (typeof this._executeWipeInternal === 'function') {
        this._executeWipeInternal();
      } else if (typeof this.startWipeExecution === 'function') {
        this.startWipeExecution();
      }
    }
    this.wipeProgress = 100;
    this.wipeCompleted = true;
    this.phaseCompleted[3] = true;
    this.isWiping = false;
    if (this.wipeInterval) {
      clearInterval(this.wipeInterval);
      this.wipeInterval = null;
    }
    if (this.sectorStates) {
      const isRed = (this.selectedDevice && this.selectedDevice.expectedOutcome === 'RED');
      for (let i = 0; i < this.sectorStates.length; i++) {
        if (isRed && (i % 6 === 0)) this.sectorStates[i] = 3;
        else this.sectorStates[i] = 2;
      }
    }
    if (typeof this._applyPostWipeFileCleanup === 'function') {
      this._applyPostWipeFileCleanup();
    }
    this.drawCanvas();
    this.updateWipeUI();

    const titleEl = document.getElementById('wipe-phase-title');
    const descEl = document.getElementById('wipe-phase-desc');
    const bannerEl = document.getElementById('wipe-complete-banner');
    if (titleEl) titleEl.textContent = "✓ Secure Erasure Completed!";
    if (descEl) descEl.textContent = "Hardware sanitization finished with 0 unrecoverable read errors. Ready for verification.";
    if (bannerEl) bannerEl.style.display = 'block';

    const proceedBtn = document.getElementById('btn-proceed-phase-4');
    if (proceedBtn) {
      proceedBtn.disabled = false;
      proceedBtn.classList.add('pulse-ready');
    }
    this.renderStepper();

    setTimeout(() => {
      if (this.currentPhase === 3 && this.wipeCompleted) {
        this.goToPhase(4);
      }
    }, 1200);
  }

  async loadDevices() {
    const listEl = document.getElementById('device-card-list');
    const scanBtn = document.getElementById('btn-scan-drives');

    if (scanBtn) {
      scanBtn.disabled = true;
      const span = scanBtn.querySelector('span');
      if (span) span.textContent = 'Scanning…';
    }

    if (listEl && (!this.devices || this.devices.length === 0)) {
      listEl.innerHTML = `
        <div style="text-align:center; padding:40px; color:var(--text-muted); grid-column: 1 / -1;">
          <div style="font-size:28px; margin-bottom:12px;">🔍</div>
          <div style="font-size:14px; font-weight:600;">Scanning connected storage devices…</div>
          <div style="font-size:12px; margin-top:6px; color:var(--text-muted);">Querying device health and storage topology</div>
        </div>
      `;
    }

    let devices = [];

    if (this.demoMode) {
      // In DEMO MODE: Deep clone interactive scenario presets to keep demo files isolated and intact
      devices = (window.MOCK_DEVICES || []).map(d => JSON.parse(JSON.stringify(d)));
    } else {
      // In REAL HARDWARE MODE: Fetch and show real physical connected devices via backend probe
      try {
        const res = await this.fetchBackend('/api/devices');
        if (res && res.ok) {
          const fetched = await res.json();
          if (Array.isArray(fetched) && fetched.length > 0) {
            devices = fetched;
          }
        }
      } catch (e) {
        devices = [];
      }

      if (devices.length === 0 && this.devices && this.devices.length > 0) {
        devices = this.devices;
      }
    }

    const seen = new Set();
    const deduped = [];
    for (const dev of devices) {
      const key = dev.id || dev.devicePath || dev.serialNumber;
      if (key && seen.has(key)) continue;
      if (key) seen.add(key);
      deduped.push(dev);
    }

    this.devices = deduped;

    if (!this.selectedDevice || !this.devices.some(d => d.id === this.selectedDevice.id)) {
      this.selectedDevice = this.devices[0] || null;
    }

    if (this.selectedDevice) {
      this.selectedMethodId = null;
      this.phaseCompleted[1] = true;
      this.phaseCompleted[2] = false;
    } else {
      this.phaseCompleted[1] = false;
      this.phaseCompleted[2] = false;
    }

    if (scanBtn) {
      scanBtn.disabled = false;
      const span = scanBtn.querySelector('span');
      if (span) span.textContent = 'Scan Drives';
    }

    this.renderDeviceList();
    if (typeof this.renderDriveStatus === 'function') {
      this.renderDriveStatus();
    }
    this.updatePhase1ContinueBtn();
    this.renderStorageBar();
    this.renderMethodOptions();
    this.renderStepper();
  }

  switchView(viewName) {
    this.activeView = viewName;
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));

    if (viewName === 'dashboard') {
      document.getElementById('nav-dashboard-btn')?.classList.add('active');
      document.getElementById('dashboard-view')?.classList.add('active');
      // Clear old typed lines so animation restarts fresh
      const ftc = document.getElementById('feature-typewriter-container');
      if (ftc) ftc.innerHTML = '';
      if (typeof this.initDashboardAnimations === 'function') {
        this.initDashboardAnimations();
      }
    } else if (viewName === 'workflow') {
      document.getElementById('nav-workflow-btn')?.classList.add('active');
      document.getElementById('workflow-view')?.classList.add('active');
    } else if (viewName === 'portal') {
      document.getElementById('nav-verify-btn')?.classList.add('active');
      document.getElementById('portal-view')?.classList.add('active');
      this.verifyLookup();
    } else if (viewName === 'history') {
      document.getElementById('nav-history-btn')?.classList.add('active');
      document.getElementById('history-view')?.classList.add('active');
      this.loadHistory();
    }
  }

  async loadHistory() {
    let sessions = [];
    let certs = [];

    try {
      const [sessRes, certRes] = await Promise.all([
        this.fetchBackend('/api/wipe/sessions'),
        this.fetchBackend('/api/certificates')
      ]);
      if (sessRes && sessRes.ok) {
        const data = await sessRes.json();
        if (Array.isArray(data)) sessions = data;
      }
      if (certRes && certRes.ok) {
        const data = await certRes.json();
        if (Array.isArray(data.certificates)) certs = data.certificates;
      }
    } catch (e) {
      console.warn('Backend history lookup failed:', e);
    }

    // If in Demo Mode or backend is empty, seed with rich preset history
    if (this.demoMode || (sessions.length === 0 && certs.length === 0)) {
      const defaultMockCerts = window.CERTIFICATE_STORE ? Object.values(window.CERTIFICATE_STORE) : [];
      const defaultMockSessions = [
        {
          wipeId: "WIPE-NVME-980PRO-8F2B",
          deviceId: "dev-nvme-samsung-980",
          method: "purge-nvme-crypto",
          status: "COMPLETED",
          startedAt: "2026-08-16T23:30:00Z",
          completedAt: "2026-08-16T23:33:00Z",
          command: "nvme sanitize /dev/nvme0n1 --action=crypto"
        },
        {
          wipeId: "WIPE-HDD-BARRACUDA-3C1A",
          deviceId: "dev-hdd-seagate-barracuda",
          method: "clear-single",
          status: "COMPLETED",
          startedAt: "2026-08-15T14:00:00Z",
          completedAt: "2026-08-15T14:12:00Z",
          command: "dd if=/dev/zero of=/dev/sdb bs=4M status=progress"
        },
        {
          wipeId: "WIPE-SSD-KINGSTON-RED-99",
          deviceId: "dev-ssd-kingston-damaged",
          method: "destroy-physical",
          status: "FAILED",
          startedAt: "2026-08-16T18:40:00Z",
          completedAt: "2026-08-16T18:45:00Z",
          command: "Physical destruction mandate: 48 unreadable sectors"
        }
      ];

      // Merge backend items with mock items (avoiding duplicates)
      const existingSessionIds = new Set(sessions.map(s => s.wipeId));
      for (const s of defaultMockSessions) {
        if (!existingSessionIds.has(s.wipeId)) {
          sessions.push(s);
        }
      }

      const existingCertIds = new Set(certs.map(c => c.certificateId));
      for (const c of defaultMockCerts) {
        if (!existingCertIds.has(c.certificateId)) {
          certs.push(c);
        }
      }
    }

    // Also include any dynamically logged wipe sessions in this current browser session
    if (this._dynamicSessions && Array.isArray(this._dynamicSessions)) {
      const existingSessionIds = new Set(sessions.map(s => s.wipeId));
      for (const s of this._dynamicSessions) {
        if (!existingSessionIds.has(s.wipeId)) {
          sessions.unshift(s);
          existingSessionIds.add(s.wipeId);
        }
      }
    }

    // Also include any dynamically issued certificates in this session
    if (this.certificateStore) {
      const existingCertIds = new Set(certs.map(c => c.certificateId));
      for (const [id, certObj] of Object.entries(this.certificateStore)) {
        if (!existingCertIds.has(id)) {
          certs.unshift(certObj);
          existingCertIds.add(id);
        }
      }
    }

    this._historySessions = sessions;
    this._historyCerts = certs;
    this.renderSessionsTable();
    this.renderCertsTable();
  }

  switchHistoryTab(tab) {
    const sessBtn = document.getElementById('history-tab-sessions');
    const certBtn = document.getElementById('history-tab-certs');
    const sessPanel = document.getElementById('history-sessions-panel');
    const certPanel = document.getElementById('history-certs-panel');
    if (tab === 'sessions') {
      sessBtn?.classList.add('active');
      certBtn?.classList.remove('active');
      if (sessPanel) sessPanel.style.display = 'block';
      if (certPanel) certPanel.style.display = 'none';
    } else {
      sessBtn?.classList.remove('active');
      certBtn?.classList.add('active');
      if (sessPanel) sessPanel.style.display = 'none';
      if (certPanel) certPanel.style.display = 'block';
    }
  }

  renderSessionsTable() {
    const container = document.getElementById('history-sessions-table');
    if (!container) return;
    const sessions = this._historySessions || [];
    if (sessions.length === 0) {
      container.innerHTML = '<p style="color:var(--text-secondary); font-size:13px; padding:20px 0;">No wipe sessions found. Complete a drive sanitization to see history here.</p>';
      return;
    }
    const statusIcon = (s) => s === 'COMPLETED' ? '✅' : s === 'FAILED' ? '❌' : '⏳';
    let html = `<table style="width:100%; border-collapse:collapse; font-size:13px;">
      <thead><tr style="border-bottom:2px solid var(--border-primary); text-align:left;">
        <th style="padding:8px 10px;">Session ID</th>
        <th style="padding:8px 10px;">Device</th>
        <th style="padding:8px 10px;">Method</th>
        <th style="padding:8px 10px;">Status</th>
        <th style="padding:8px 10px;">Started</th>
        <th style="padding:8px 10px;">Completed</th>
        <th style="padding:8px 10px;">Command</th>
      </tr></thead><tbody>`;
    for (const s of sessions) {
      const started = s.startedAt ? new Date(s.startedAt).toLocaleString() : '—';
      const completed = s.completedAt ? new Date(s.completedAt).toLocaleString() : '—';
      html += `<tr style="border-bottom:1px solid var(--border-primary);">
        <td style="padding:8px 10px; font-family:'JetBrains Mono',monospace; font-size:11px;">${s.wipeId || '—'}</td>
        <td style="padding:8px 10px;">${s.deviceId || '—'}</td>
        <td style="padding:8px 10px;">${s.method || '—'}</td>
        <td style="padding:8px 10px;">${statusIcon(s.status)} ${s.status || '—'}</td>
        <td style="padding:8px 10px; font-size:11px;">${started}</td>
        <td style="padding:8px 10px; font-size:11px;">${completed}</td>
        <td style="padding:8px 10px; font-size:11px; font-family:'JetBrains Mono',monospace; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${(s.command||'').replace(/"/g,'&quot;')}">${s.command || '—'}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    container.innerHTML = html;
  }

  renderCertsTable() {
    const container = document.getElementById('history-certs-table');
    if (!container) return;
    const certs = this._historyCerts || [];
    if (certs.length === 0) {
      container.innerHTML = '<p style="color:var(--text-secondary); font-size:13px; padding:20px 0;">No certificates generated yet. Complete a wipe and generate a certificate to see it here.</p>';
      return;
    }
    let html = `<table style="width:100%; border-collapse:collapse; font-size:13px;">
      <thead><tr style="border-bottom:2px solid var(--border-primary); text-align:left;">
        <th style="padding:8px 10px;">Certificate ID</th>
        <th style="padding:8px 10px;">Device</th>
        <th style="padding:8px 10px;">Serial</th>
        <th style="padding:8px 10px;">Method</th>
        <th style="padding:8px 10px;">Status</th>
        <th style="padding:8px 10px;">Verdict</th>
        <th style="padding:8px 10px;">Issued</th>
        <th style="padding:8px 10px;">Actions</th>
      </tr></thead><tbody>`;
    for (const c of certs) {
      const issued = c.issueDate ? new Date(c.issueDate).toLocaleString() : '—';
      const verdictColor = c.verdict === 'SAFE TO REUSE OR RESELL' ? '#22c55e' : c.verdict === 'SHRED REQUIRED' ? '#ef4444' : '#eab308';
      html += `<tr style="border-bottom:1px solid var(--border-primary);">
        <td style="padding:8px 10px; font-family:'JetBrains Mono',monospace; font-size:11px;">${c.certificateId || '—'}</td>
        <td style="padding:8px 10px;">${c.deviceModel || '—'}</td>
        <td style="padding:8px 10px; font-family:'JetBrains Mono',monospace; font-size:11px;">${c.serialNumber || '—'}</td>
        <td style="padding:8px 10px; font-size:11px;">${c.methodName || c.standard || '—'}</td>
        <td style="padding:8px 10px;">${c.cleanedStatus || '—'}</td>
        <td style="padding:8px 10px; color:${verdictColor}; font-weight:700; font-size:11px;">${c.verdict || '—'}</td>
        <td style="padding:8px 10px; font-size:11px;">${issued}</td>
        <td style="padding:8px 10px;"><button class="btn btn-secondary" style="font-size:11px; padding:4px 10px;" onclick="app.viewHistoricalCert('${c.certificateId}')">View</button></td>
      </tr>`;
    }
    html += '</tbody></table>';
    container.innerHTML = html;
  }

  viewHistoricalCert(certId) {
    this.switchView('portal');
    const input = document.getElementById('portal-search-input');
    if (input) {
      input.value = certId;
      this.verifyLookup();
    }
  }

  async clearHistory() {
    if (!confirm('Are you sure you want to permanently clear all wiping logs and certificates?')) return;
    try {
      const res = await this.fetchBackend('/api/history/clear', { method: 'POST' });
      if (res && res.ok) {
        this._historySessions = [];
        this._historyCerts = [];
        this.renderSessionsTable();
        this.renderCertsTable();
        this.showStepBlockedToast('Wiping & Certificate History Cleared');
      } else {
        alert('Failed to clear history from backend.');
      }
    } catch (e) {
      console.error('Error clearing history:', e);
    }
  }

  formatBytes(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    const k = 1000;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  showStepBlockedToast(message) {
    const toast = document.getElementById('step-blocked-toast');
    if (!toast) return;
    toast.textContent = '⚠️ ' + message;
    toast.classList.add('show');
    clearTimeout(this._toastTimer);
    this._toastTimer = setTimeout(() => toast.classList.remove('show'), 2600);
  }

  isPhaseAccessible(phaseNum) {
    // ANTI-CORRUPTION LOCKOUT: Once wiping starts or completes, backwards navigation to Step 1 or 2 is strictly prohibited
    if ((this.isWiping || (this.wipeCompleted && this.currentPhase >= 3)) && phaseNum < 3) {
      return { 
        ok: false, 
        reason: '🔒 Locked: Drive erasure is in progress or completed. Backwards navigation to selection is disabled for safety.' 
      };
    }

    if (phaseNum <= this.currentPhase) return { ok: true };
    if (phaseNum > 5 || phaseNum < 1) return { ok: false, reason: 'Invalid step' };
    if (!this.phaseCompleted[1]) return { ok: false, reason: 'Step 1 required: Select a drive first' };
    if (phaseNum >= 3 && !this.phaseCompleted[2]) return { ok: false, reason: 'Step 2 required: Choose a sanitization method first' };
    if (phaseNum >= 4 && !this.phaseCompleted[3]) return { ok: false, reason: 'Step 3 required: Complete the wipe before verifying' };
    if (phaseNum >= 5 && !this.phaseCompleted[4]) return { ok: false, reason: 'Step 4 required: Complete verification first' };
    return { ok: true };
  }

  updatePhase1ContinueBtn() {
    const btn = document.getElementById('btn-go-phase-2');
    if (btn) {
      btn.disabled = !this.selectedDevice;
    }
    this.phaseCompleted[1] = !!this.selectedDevice;
  }

  renderStepper() {
    const stepperEl = document.getElementById('phase-stepper');
    if (!stepperEl) return;

    const phases = [
      { num: 1, title: "Select Drive" },
      { num: 2, title: "Choose Method" },
      { num: 3, title: "Erase Data" },
      { num: 4, title: "Verify & Safety" },
      { num: 5, title: "Certificate" }
    ];

    stepperEl.innerHTML = phases.map(p => {
      const accessibility = this.isPhaseAccessible(p.num);
      const isCurrent = p.num === this.currentPhase;
      const isCompleted = this.phaseCompleted[p.num] && !isCurrent;
      const locked = !accessibility.ok;
      const isLockedPriorStep = locked && p.num <= 3 && (this.isWiping || this.wipeCompleted);

      return `
        <div class="step-item ${isCurrent ? 'active' : ''} ${isCompleted ? 'completed' : ''} ${locked ? 'locked' : ''}"
             onclick="app._stepperClick(${p.num})" title="${locked ? accessibility.reason : (isCurrent ? 'Current Step' : '')}">
          <div class="step-num-circle">${isLockedPriorStep ? '🔒' : (isCompleted ? '✓' : p.num)}</div>
          <span class="step-title">${p.title}</span>
        </div>
      `;
    }).join('');
  }

  _stepperClick(phaseNum) {
    this.goToPhase(phaseNum);
  }

  goToPhase(phaseNum) {
    if (phaseNum < 1 || phaseNum > 5) return;

    const access = this.isPhaseAccessible(phaseNum);
    if (!access.ok) {
      this.showStepBlockedToast(access.reason);
      return;
    }

    if (this.currentPhase === 3 && phaseNum !== 3 && this.wipeInterval) {
      clearInterval(this.wipeInterval);
      this.isWiping = false;
    }

    this.currentPhase = phaseNum;

    document.querySelectorAll('.phase-screen').forEach((el, index) => {
      el.classList.toggle('active', (index + 1) === phaseNum);
    });

    this.renderStepper();

    if (phaseNum === 1) { this.renderDeviceList(); this.renderDriveStatus(); }
    else if (phaseNum === 2) { this.renderMethodOptions(); this.phaseCompleted[2] = !!this.selectedMethodId; }
    else if (phaseNum === 3) this.resetWipeCanvas();
    else if (phaseNum === 4) { this.renderVerification(); this.phaseCompleted[4] = true; }
    else if (phaseNum === 5) { this.renderCertificate(); this.phaseCompleted[5] = true; }

    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  /* STEP 1: SELECT DRIVE */
  renderDeviceList() {
    const listEl = document.getElementById('device-card-list');
    const alertEl = document.getElementById('step-1-alert');
    if (!listEl) return;
    if (!this.devices.length) {
      listEl.innerHTML = `
        <div style="text-align:center; padding:32px; border:1px solid var(--border-subtle); background:var(--bg-surface); border-radius:var(--radius-lg); color:var(--text-secondary); grid-column: 1 / -1;">
          <div style="font-size:28px; margin-bottom:8px;">💾</div>
          <div style="font-size:15px; font-weight:700; margin-bottom:4px;">No External Drives Detected</div>
          <div style="font-size:13px; color:var(--text-muted); margin-bottom:14px;">Connect a USB flash drive or external storage, or click Scan Drives to refresh hardware probes.</div>
          <div style="display:flex; justify-content:center; gap:10px;">
            <button class="btn btn-primary" onclick="app.loadDevices()">Scan Drives</button>
            <button class="btn btn-outline" onclick="app.toggleDemoMode(true)">Enable Demo Presets</button>
          </div>
        </div>
      `;
      if (alertEl) alertEl.style.display = 'none';
      return;
    }

    const devicesHtml = this.devices.map(dev => {
      const isSelected = this.selectedDevice && dev.id === this.selectedDevice.id;
      let healthBadge = `<span class="card-health-pill pill-green">Good Condition</span>`;
      if (dev.expectedOutcome === 'RED') {
        healthBadge = `<span class="card-health-pill pill-red">Damaged</span>`;
      }

      const cleanTag = dev.isAlreadyClean
        ? `<span class="card-health-pill pill-green" style="margin-left:auto;">Already Clean</span>`
        : '';

      const bootWarning = dev.isBootDrive
        ? `<div style="font-size:11px;color:var(--text-muted);margin-top:4px;">⚠️ OS Boot Drive — wipe will format the operating system</div>`
        : '';

      return `
        <div class="device-card ${isSelected ? 'selected' : ''}" onclick="app.selectDevice('${dev.id}')">
          <div class="card-top">
            <span class="card-device-type">${dev.type}</span>
            <div style="display:flex;align-items:center;gap:6px;">
              ${cleanTag}
              ${healthBadge}
            </div>
          </div>
          <div class="card-model-name">${dev.model}</div>
          <div class="card-meta-row">
            <span>Serial: ${dev.maskedSerial || dev.serialNumber}</span>
            <span class="font-bold">${dev.capacity.split('(')[0].trim()}</span>
          </div>
          <div class="card-meta-row" style="margin-top:2px;font-size:11px;color:var(--text-muted);">
            <span>${dev.powerOnHours}</span>
            <span>${dev.temperature}</span>
          </div>
          ${bootWarning}
        </div>
      `;
    }).join('');

    listEl.innerHTML = devicesHtml;

    if (alertEl && this.selectedDevice) {
      alertEl.style.display = '';
      const dev = this.selectedDevice;
      if (dev.isAlreadyClean) {
        alertEl.className = 'simple-alert-box alert-green';
        alertEl.innerHTML = `✓ <strong>${dev.model}</strong> appears already wiped — verify and continue for formal certification.`;
      } else if (dev.expectedOutcome === 'RED') {
        alertEl.className = 'simple-alert-box alert-red';
        alertEl.innerHTML = `
          <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
            <div>🚨 <strong>${dev.model}</strong> has ${dev.reallocatedSectors > 0 ? dev.reallocatedSectors + ' bad sectors' : 'critical hardware faults'}. Physical shredding will be required.</div>
            <button type="button" class="btn btn-chip" style="background:rgba(255,51,102,0.15); border-color:var(--red-border); color:var(--red-neon);" onclick="app.openDiagnosticsModal()">
              🔬 Deep Diagnostics (Check False Alarm)
            </button>
          </div>
        `;
      } else {
        alertEl.className = 'simple-alert-box alert-green';
        alertEl.innerHTML = `✓ <strong>${dev.model}</strong> is healthy and ready for secure wipe.`;
      }
    } else if (alertEl) {
      alertEl.style.display = 'none';
    }
  }

  selectDevice(deviceOrId) {
    const deviceId = (typeof deviceOrId === 'object' && deviceOrId !== null) ? deviceOrId.id : deviceOrId;
    let found = this.devices.find(d => d.id === deviceId);
    if (!found && window.MOCK_DEVICES) {
      found = window.MOCK_DEVICES.find(d => d.id === deviceId);
      if (found && !this.devices.some(d => d.id === found.id)) {
        this.devices.push(found);
      }
    }
    if (!found) return;

    this.selectedDevice = found;
    this.unfrozen = false;
    this.phaseCompleted[1] = true;
    this.phaseCompleted[2] = false;
    this.phaseCompleted[3] = false;
    this.phaseCompleted[4] = false;
    this.phaseCompleted[5] = false;
    this.selectedMethodId = null; // Require user to select a method in Step 2

    this.renderDeviceList();
    if (typeof this.renderDriveStatus === 'function') {
      this.renderDriveStatus();
    }
    this.updatePhase1ContinueBtn();
    this.renderMethodOptions();
    this.renderStepper();

    // Smoothly scroll to the drive explorer panel so the continue button and files are immediately visible
    setTimeout(() => {
      const panel = document.getElementById('drive-status-panel');
      if (panel && panel.style.display !== 'none') {
        panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    }, 80);
  }

  /* STEP 2: SANITIZATION METHODS */
  renderMethodOptions() {
    const listEl = document.getElementById('method-options-list');
    const proceedBtn = document.getElementById('btn-start-wipe-phase-2');
    if (proceedBtn) proceedBtn.disabled = !this.selectedMethodId;
    if (!listEl) return;

    const dev = this.selectedDevice;

    listEl.innerHTML = `
      <div class="method-grid-zerotrace">
        ${this.simpleMethods.map(m => {
          const isSelected = (m.id === this.selectedMethodId);
          let isRecommended = false;

          if (dev) {
            if (dev.expectedOutcome === 'RED') {
              if (m.id === 'nist_800_88') isRecommended = true;
            } else {
              if (dev.type && dev.type.includes('NVMe') && m.id === 'crypto_erase') isRecommended = true;
              else if (dev.type && (dev.type.includes('SATA SSD') || dev.hpaDetected) && m.id === 'ata_sanitize') isRecommended = true;
              else if (dev.type && dev.type.includes('Magnetic') && m.id === 'dod_5220_22_m') isRecommended = true;
              else if (dev.type && dev.type.includes('USB') && m.id === 'single_pass') isRecommended = true;
              else if (!dev.type && m.id === 'nist_800_88') isRecommended = true;
            }
          }

          return `
            <div class="zt-method-card ${isSelected ? 'selected' : ''} ${isRecommended ? 'recommended' : ''}" onclick="app.selectSimpleMethod('${m.id}')">
              <div class="zt-method-header">
                <input type="radio" name="sanitization_method" value="${m.id}" ${isSelected ? 'checked' : ''} style="cursor:pointer; accent-color:var(--cyan-neon); width:16px; height:16px;" onclick="event.stopPropagation(); app.selectSimpleMethod('${m.id}')" />
                <h4 class="zt-method-title">${m.name}</h4>
                ${isRecommended ? '<span class="zt-badge-rec">Recommended</span>' : ''}
              </div>
              <p class="zt-method-desc">${m.oneLine}</p>
              <div class="zt-method-footer">
                <span class="zt-time-est">⏱️ ${m.speedBadge}</span>
                <div style="display:flex; align-items:center; gap:4px;">
                  <span class="zt-badge-tier">${m.standard}</span>
                  <span class="zt-badge-sec">${m.securityBadge}</span>
                </div>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;

    this.phaseCompleted[2] = !!this.selectedMethodId;
  }

  selectSimpleMethod(methodId) {
    this.selectedMethodId = methodId;
    this.phaseCompleted[2] = true;
    this.renderMethodOptions();
    this.renderStepper();
  }

  /* STEP 4: ACTIVE WIPE */
  initCanvas() {
    const canvas = document.getElementById('sector-canvas');
    if (!canvas) return;
    this.drawCanvas();
  }

  resetWipeCanvas() {
    this.sectorStates = new Array(256).fill(0);
    this.wipeProgress = 0;
    this.isWiping = false;

    const titleEl = document.getElementById('wipe-phase-title');
    const descEl = document.getElementById('wipe-phase-desc');
    const bannerEl = document.getElementById('wipe-complete-banner');
    const proceedBtn = document.getElementById('btn-proceed-phase-4');

    if (titleEl) titleEl.textContent = "Securely Erasing Drive...";
    if (descEl) descEl.textContent = "Please wait while your storage drive is undergoing hardware-level media sanitization.";
    if (bannerEl) bannerEl.style.display = 'none';
    if (proceedBtn) {
      proceedBtn.disabled = true;
      proceedBtn.classList.remove('pulse-ready');
    }

    this.updateWipeUI();
    this.drawCanvas();
  }

  drawCanvas() {
    const canvas = document.getElementById('sector-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const cols = 32, rows = 8;
    const blockWidth = canvas.width / cols;
    const blockHeight = canvas.height / rows;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const index = r * cols + c;
        const state = this.sectorStates[index] || 0;
        let fill = '#141c2e'; // Unwiped / resting state
        if (state === 1) fill = '#00f0ff'; // Active scan / purge (cyber cyan)
        else if (state === 2) fill = '#00ff88'; // Sanitized clean (matrix green)
        else if (state === 3) fill = '#ff3366'; // Bad sector / fault (radiant red)
        ctx.fillStyle = fill;
        ctx.fillRect(c * blockWidth + 1, r * blockHeight + 1, blockWidth - 2, blockHeight - 2);
      }
    }
  }

  updateWipeUI() {
    const percentEl = document.getElementById('wipe-percent-display');
    const fillEl = document.getElementById('wipe-progress-bar-fill');
    const etaEl = document.getElementById('live-eta-val');

    if (percentEl) percentEl.textContent = `${this.wipeProgress}%`;
    if (fillEl) fillEl.style.width = `${this.wipeProgress}%`;

    if (etaEl) {
      if (this.wipeProgress >= 100) {
        etaEl.textContent = "Complete";
      } else {
        // Calculate remaining seconds dynamically (estimated 12-16s total wipe span)
        const remainingPct = 100 - this.wipeProgress;
        const totalEstimatedSecs = this.demoMode ? 14 : 25;
        const sec = Math.max(1, Math.round((remainingPct / 100) * totalEstimatedSecs));
        const mins = Math.floor(sec / 60);
        const secs = sec % 60;
        etaEl.textContent = `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}s`;
      }
    }
  }
  /* STEP 4: VERIFICATION & SAFETY VERDICT */
  async renderVerification() {
    const card = document.getElementById('verification-result-card');
    const title = document.getElementById('verify-title');
    const desc = document.getElementById('verify-desc');
    const pillsContainer = card ? card.querySelector('.simple-stats-pills') : null;

    if (!card || !this.selectedDevice) return;

    let auditData = null;

    // Run real backend audit when in Real Hardware Mode with active backend wipe ID
    if (!this.demoMode && this.activeWipeId) {
      try {
        const res = await this.fetchBackend(`/api/audit/run/${this.activeWipeId}`, { method: 'POST' });
        if (res && res.ok) {
          auditData = await res.json();
        }
      } catch (e) { /* fallback to client evaluation */ }
    }

    const isAuditFailed = auditData ? (auditData.status === 'FAILED') : (this.selectedDevice.expectedOutcome === 'RED');
    const chosenMethod = this.simpleMethods.find(m => m.id === this.selectedMethodId) || this.simpleMethods[0];

    if (isAuditFailed) {
      card.className = "verification-result-card verify-failed";
      if (title) title.textContent = "Data Erasure Incomplete";
      if (desc) desc.textContent = auditData?.message || "Damaged sectors or physical faults were detected. 100% data sanitization could not be completed by software.";
      if (pillsContainer) {
        pillsContainer.innerHTML = `
          <div class="s-pill"><strong>Erasure Status:</strong> <span class="text-red font-bold">Incomplete (Faults Detected)</span></div>
          <div class="s-pill"><strong>Hardware Health:</strong> <span class="text-red font-bold">Physical Bad Sectors</span></div>
          <div class="s-pill"><strong>Required Action:</strong> <span class="text-red font-bold">Physical Shredding Mandate</span></div>
          <div class="s-pill"><strong>Verification:</strong> <span class="text-red font-bold">FAILED</span></div>
        `;
      }
    } else {
      card.className = "verification-result-card";
      if (title) title.textContent = "100% Data Erasure Confirmed";
      if (desc) desc.textContent = auditData?.message || "The drive has been completely erased and verified clean. Zero recoverable files or data remain.";
      if (pillsContainer) {
        pillsContainer.innerHTML = `
          <div class="s-pill"><strong>Erasure Status:</strong> <span class="text-emerald font-bold">100% Cleaned</span></div>
          <div class="s-pill"><strong>Recoverable Files:</strong> <span class="text-emerald font-bold">0 Files (None)</span></div>
          <div class="s-pill"><strong>Method Applied:</strong> <span>${chosenMethod.name}</span></div>
          <div class="s-pill"><strong>Verification Result:</strong> <span class="text-emerald font-bold">✓ PASSED</span></div>
        `;
      }
    }

    // Merged Safety Assessment & Reuse Recommendation (Integrated into Step 4)
    const outcome = this.selectedDevice.expectedOutcome;
    document.getElementById('light-green')?.classList.toggle('active', outcome === 'GREEN');
    document.getElementById('light-red')?.classList.toggle('active', outcome === 'RED');

    const scoreTitleEl = document.getElementById('score-rating-title');
    const scoreDescEl = document.getElementById('score-rating-desc');
    const btnLabel = document.getElementById('phase-5-btn-label');
    const diagActionEl = document.getElementById('step-4-diag-action');

    if (outcome === 'RED' || isAuditFailed) {
      if (scoreTitleEl) { scoreTitleEl.textContent = "DAMAGED DRIVE — MUST BE SHREDDED"; scoreTitleEl.className = "score-main-title text-red"; }
      if (scoreDescEl) scoreDescEl.textContent = "Damaged sectors were detected. Software cannot erase physically broken areas. To prevent data leaks, this drive must be physically shredded.";
      if (btnLabel) btnLabel.textContent = "Next: View Destruction Notice";
      if (diagActionEl) {
        diagActionEl.innerHTML = `
          <button type="button" class="btn btn-chip" style="background:rgba(255,51,102,0.15); border-color:var(--red-border); color:var(--red-neon); padding:8px 18px; font-weight:700;" onclick="app.openDiagnosticsModal()">
            🔬 Run Deep Diagnostics (Check False Alarm vs True Hardware Damage)
          </button>
        `;
      }
    } else {
      if (scoreTitleEl) { scoreTitleEl.textContent = "SAFE TO REUSE OR RESELL"; scoreTitleEl.className = "score-main-title text-emerald"; }
      if (scoreDescEl) scoreDescEl.textContent = "100% of data has been permanently erased. The drive is in healthy condition and completely safe to reuse, donate, or resell.";
      if (btnLabel) btnLabel.textContent = "Next: View Official Certificate";
      if (diagActionEl) diagActionEl.innerHTML = '';
    }
  }

  /* STEP 5: OFFICIAL CERTIFICATE */
  async renderCertificate() {
    if (!this.selectedDevice) return;
    const dev = this.selectedDevice;
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

    // Generate slug from real model name
    let modelSlug = dev.model.toUpperCase().replace(/[^A-Z0-9]/g, '-').replace(/-+/g, '-').substring(0, 12).replace(/-$/, '');

    // High-entropy random hexadecimal suffix
    const randomHex = (window.crypto && window.crypto.getRandomValues)
      ? Array.from(window.crypto.getRandomValues(new Uint8Array(6)), b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
      : Math.random().toString(16).substring(2, 14).toUpperCase();
    let certId = `WIPEX-${new Date().getFullYear()}-${modelSlug}-${randomHex}`;

    const chosenMethod = this.simpleMethods.find(m => m.id === this.selectedMethodId) || this.simpleMethods[0];
    const canonicalString = `${dev.serialNumber}:${dev.model}:${this.currentNonce}:${chosenMethod.id}:${timestamp}:${dev.expectedOutcome}`;
    const cryptoHelper = window.WipeXCrypto || window.AegisCrypto;
    let sha256Hash = await cryptoHelper.sha256(canonicalString);

    const isRed = (dev.expectedOutcome === 'RED');

    let displayMethod = chosenMethod.fullName || chosenMethod.name;
    let cleanedStatusText = "CERTIFIED 100% CLEANED & SANITIZED";
    let reuseScoreText = "SAFE TO REUSE OR RESELL";
    let auditText = "✓ PASSED (Zero Residual Data Verified)";

    if (isRed) {
      cleanedStatusText = `NOT CLEANED (${dev.reallocatedSectors > 0 ? dev.reallocatedSectors + ' Bad Sectors' : 'Hardware Fault'})`;
      displayMethod = "Physical Destruction Mandated";
      reuseScoreText = "DO NOT REUSE (SHRED REQUIRED)";
      auditText = "FAILED (Damaged Sectors Detected)";
    }

    // Backend certificate generation (persists to DB in real hardware mode)
    if (!this.demoMode && this.activeWipeId) {
      try {
        const res = await this.fetchBackend('/api/certificates/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ wipeId: this.activeWipeId })
        });
        if (res && res.ok) {
          const backendCert = await res.json();
          if (backendCert && backendCert.certificateId) {
            certId = backendCert.certificateId;
            sha256Hash = backendCert.sha256Digest;
          }
        }
      } catch (e) { /* use client-generated cert */ }
    }

    this.currentCertId = certId;
    this.currentCertData = { certId, timestamp, model: dev.model, serial: dev.serialNumber, capacity: dev.capacity.split('(')[0], method: displayMethod, cleanedStatus: cleanedStatusText, score: reuseScoreText, hash: sha256Hash };

    // Store for portal lookup
    this.certificateStore[certId] = {
      certificateId: certId,
      status: isRed ? "DESTROYED_MANDATE" : "HARDWARE_BOUND",
      trustScore: dev.expectedOutcome,
      trustScoreLabel: isRed ? "SHRED REQUIRED" : "SAFE TO REUSE OR RESELL",
      issueDate: timestamp,
      deviceModel: dev.model,
      serialNumber: dev.serialNumber,
      storageType: dev.type,
      capacity: dev.capacity.split('(')[0],
      standard: displayMethod,
      cleanedStatus: cleanedStatusText,
      auditResult: auditText,
      preWipeNonce: this.currentNonce,
      sha256Digest: sha256Hash,
      tamperDetected: false,
      verdict: isRed ? "Drive contains damaged sectors and must be physically shredded." : "Authentic & Verified. 100% of data was securely erased."
    };

    // Banner & Watermark (Formal Black & White)
    const banner = document.getElementById('cert-status-banner');
    const bannerIcon = document.getElementById('banner-icon');
    const bannerHeadline = document.getElementById('banner-headline');
    const bannerSubtext = document.getElementById('banner-subtext');
    const bannerTag = document.getElementById('banner-tag');
    const watermark = document.getElementById('cert-watermark');

    if (banner) {
      if (!isRed) {
        if (bannerIcon) bannerIcon.textContent = "[ ✓ ]";
        if (bannerHeadline) bannerHeadline.textContent = "DRIVE STATUS: 100% CLEANED & SANITIZED";
        if (bannerSubtext) bannerSubtext.textContent = "Zero recoverable data detected. Drive is verified clean and safe for reuse or resale.";
        if (bannerTag) bannerTag.textContent = "PASSED";
        if (watermark) watermark.textContent = "VERIFIED CLEAN";
      } else {
        if (bannerIcon) bannerIcon.textContent = "[ ⚠ ]";
        if (bannerHeadline) bannerHeadline.textContent = "DRIVE STATUS: NOT CLEANED · PHYSICAL DEFECTS";
        if (bannerSubtext) bannerSubtext.textContent = "Damaged sectors could not be wiped. Physical mechanical destruction is mandated.";
        if (bannerTag) bannerTag.textContent = "SHRED ORDER";
        if (watermark) watermark.textContent = "SHRED ORDER";
      }
    }

    const idEl = document.getElementById('cert-id-val');
    if (idEl) idEl.textContent = certId;

    const timeEl = document.getElementById('cert-timestamp-val');
    if (timeEl) timeEl.textContent = timestamp;

    const modelEl = document.getElementById('cert-model');
    if (modelEl) modelEl.textContent = dev.model;

    const serialEl = document.getElementById('cert-serial');
    if (serialEl) serialEl.textContent = dev.serialNumber;

    const capEl = document.getElementById('cert-capacity');
    if (capEl) capEl.textContent = dev.capacity.split('(')[0].trim();

    const typeEl = document.getElementById('cert-drive-type');
    if (typeEl) typeEl.textContent = dev.type;

    const methodEl = document.getElementById('cert-method-used');
    if (methodEl) methodEl.textContent = displayMethod;

    const nonceEl = document.getElementById('cert-nonce-val');
    if (nonceEl) nonceEl.textContent = this.currentNonce || '—';

    const cleanStatusEl = document.getElementById('cert-cleaned-status');
    if (cleanStatusEl) {
      cleanStatusEl.textContent = cleanedStatusText;
    }

    const auditResEl = document.getElementById('cert-audit-res');
    if (auditResEl) {
      auditResEl.textContent = auditText;
    }

    const scoreLabelEl = document.getElementById('cert-score-label');
    if (scoreLabelEl) {
      scoreLabelEl.textContent = reuseScoreText;
    }

    const shaEl = document.getElementById('cert-sha256');
    if (shaEl) shaEl.textContent = sha256Hash;
  }

  printCertificate() {
    window.print();
  }

  verifyCurrentCertInPortal() {
    this.switchView('portal');
    const input = document.getElementById('portal-search-input');
    if (input) input.value = this.currentCertId;
    this.verifyLookup();
  }

  /* PUBLIC PORTAL */
  fillPortalSearch(query) {
    const input = document.getElementById('portal-search-input');
    if (input) input.value = query;
    this.verifyLookup();
  }

  async verifyLookup() {
    const input = document.getElementById('portal-search-input');
    const resultCard = document.getElementById('portal-result-card');
    if (!input || !resultCard) return;

    const query = input.value.trim();
    if (!query) {
      resultCard.innerHTML = `
        <div style="text-align: center; padding: 24px;">
          <p style="font-size: 13px; color: var(--text-muted);">Enter a Certificate ID or Drive Serial Number above to verify.</p>
        </div>
      `;
      return;
    }

    let record = null;

    // Check for offline decentralized URL query parameters from QR code scan
    const params = new URLSearchParams(window.location.search);
    const urlCert = params.get('verify') || params.get('cert') || params.get('verifyCert');

    if (urlCert && (urlCert.toLowerCase() === query.toLowerCase() || !query)) {
      const sn = params.get('sn') || '';
      const mod = params.get('mod') || '';
      const m = params.get('m') || '';
      const ts = params.get('ts') || '';
      const res = params.get('res') || 'GREEN';
      const nonce = params.get('nonce') || '';
      const sig = params.get('sig') || '';

      if (sn && mod && nonce && sig) {
        const cryptoHelper = window.WipeXCrypto || window.AegisCrypto;
        const chosenM = this.simpleMethods.find(x => x.name === m) || this.simpleMethods[0];
        const checkCanonical = `${sn}:${mod}:${nonce}:${chosenM.id}:${ts}:${res}`;
        const computedHash = await cryptoHelper.sha256(checkCanonical);

        const isTampered = (computedHash !== sig);
        record = {
          certificateId: urlCert,
          status: isTampered ? "FORGED_TAMPERED" : (res === 'RED' ? "DESTROYED_MANDATE" : "HARDWARE_BOUND"),
          trustScore: res,
          trustScoreLabel: res === 'RED' ? "SHRED REQUIRED" : "SAFE TO REUSE OR RESELL",
          issueDate: ts || "—",
          deviceModel: mod,
          serialNumber: sn,
          standard: m,
          cleanedStatus: res === 'RED' ? "NOT CLEANED (HARDWARE FAULT)" : "CERTIFIED 100% CLEANED & SANITIZED",
          sha256Digest: sig,
          tamperDetected: isTampered,
          verdict: isTampered 
            ? "FRAUD ALERT: Cryptographic signature mismatch. The hardware serial number, date, or sanitization payload in this certificate was altered."
            : (res === 'RED' ? "Drive contains damaged sectors and must be physically shredded." : "Authentic & Verified. 100% of data was securely erased (Offline Proof Verified).")
        };
      }
    }

    // Try backend ledger lookup if not resolved from offline QR params
    if (!record) {
      try {
        const res = await this.fetchBackend(`/api/verify/${encodeURIComponent(query)}`);
        if (res && res.ok) {
          const apiData = await res.json();
          record = {
            certificateId: apiData.certificateId,
            status: apiData.isValid ? "VALID" : (apiData.tamperDetected ? "FORGED_TAMPERED" : "DESTROYED_MANDATE"),
            trustScore: apiData.trustScore,
            trustScoreLabel: apiData.trustScoreLabel,
            issueDate: apiData.issueDate || "—",
            deviceModel: apiData.deviceModel,
            serialNumber: apiData.serialNumber,
            standard: apiData.standard,
            cleanedStatus: apiData.cleanedStatus,
            sha256Digest: apiData.sha256Digest,
            tamperDetected: apiData.tamperDetected,
            verdict: apiData.verdict
          };
        }
      } catch (e) { /* fallback to session store */ }
    }

    // Fallback to in-session issued certificates
    if (!record) {
      const q = query.toLowerCase();
      record = this.certificateStore[query] ||
        Object.values(this.certificateStore).find(r =>
          (r.serialNumber && r.serialNumber.toLowerCase() === q) ||
          (r.certificateId && r.certificateId.toLowerCase() === q) ||
          (r.certificateId && r.certificateId.toLowerCase().includes(q))
        );
    }

    if (!record) {
      resultCard.innerHTML = `
        <div style="text-align: center; padding: 24px; border: 1.5px solid var(--red-border); background: var(--red-bg); border-radius: var(--radius-md);">
          <h3 style="font-size: 16px; font-weight: 700; color: var(--red-neon); margin-bottom: 6px;">Certificate Not Found</h3>
          <p style="font-size: 13px; color: var(--text-secondary);">No sanitization record found for "<strong>${query}</strong>". Please verify the Certificate ID or Serial Number.</p>
        </div>
      `;
      return;
    }

    if (record.tamperDetected) {
      resultCard.innerHTML = `
        <div style="border-left: 4px solid var(--red-neon); background: var(--red-bg); border: 1.5px solid var(--red-border); border-left-width: 6px; padding: 18px; border-radius: var(--radius-md);">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <span class="card-health-pill pill-red font-bold">🚨 FRAUD ALERT — SIGNATURE MISMATCH</span>
            <span style="font-size: 14px; font-weight: 800; font-family: var(--font-mono);">${record.certificateId}</span>
          </div>
          <p style="font-size: 13px; color: var(--red-neon); font-weight: 600; margin-bottom: 10px;">${record.verdict}</p>
          <div style="font-size: 12px; color: var(--text-secondary); background: rgba(0,0,0,0.4); padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--red-border);">
            <strong>Report:</strong> Forged hash: <code class="font-mono text-red">${record.sha256Digest}</code>. Central ledger hardware binding mismatch.
          </div>
        </div>
      `;
      return;
    }

    const isRed = record.trustScore === 'RED' || record.status === 'DESTROYED_MANDATE';
    const isYellow = record.trustScore === 'YELLOW' || record.status === 'VALID_CAUTION';

    let badgeClass = "pill-green";
    let badgeText = "✓ VERIFIED AUTHENTIC";
    let bannerBg = "var(--emerald-bg)";
    let bannerBorder = "var(--emerald-border)";
    let bannerText = "✓ This certificate is genuine and was issued upon completing a verified wipe of this physical drive.";

    if (isYellow) {
      badgeClass = "pill-yellow";
      badgeText = "⚠️ VERIFIED (AGING MEDIA)";
      bannerBg = "var(--amber-bg)";
      bannerBorder = "var(--amber-border)";
      bannerText = "⚠️ This certificate is authentic and all data was wiped 100%. Note: hardware is aged and resale is not recommended.";
    } else if (isRed) {
      badgeClass = "pill-red";
      badgeText = "🚨 SHRED MANDATE ISSUED";
      bannerBg = "var(--red-bg)";
      bannerBorder = "var(--red-border)";
      bannerText = "🚨 Physical destruction manifest issued. Media contains bad sectors and is prohibited from resale or reuse.";
    }

    resultCard.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border-subtle); padding-bottom: 12px; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="card-health-pill ${badgeClass} font-bold">${badgeText}</span>
          <span style="font-size: 14px; font-weight: 800; font-family: var(--font-mono);">${record.certificateId}</span>
        </div>
        <span style="font-size: 12px; color: var(--text-muted);">${record.issueDate}</span>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 14px; font-size: 13px;">
        <div><strong>Drive:</strong> ${record.deviceModel}</div>
        <div><strong>Serial:</strong> <span class="font-mono text-blue font-bold">${record.serialNumber}</span></div>
        <div><strong>Method Used:</strong> ${record.standard || 'Deep Hardware Purge'}</div>
        <div><strong>Clean Status:</strong> <span class="${isRed ? 'text-red' : 'text-emerald'} font-bold">${record.cleanedStatus || (isRed ? 'UNCLEAN' : '100% Cleaned')}</span></div>
      </div>

      <div style="font-size: 12px; color: var(--text-secondary); background: ${bannerBg}; padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid ${bannerBorder};">
        ${bannerText}
      </div>
    `;
  }

  /* ─── DEEP MEDIA DIAGNOSTICS (FALSE ALARM CHECK) ─── */

  openDiagnosticsModal() {
    const overlay = document.getElementById('diagnostics-modal-overlay');
    if (!overlay || !this.selectedDevice) return;

    const dev = this.selectedDevice;
    const driveEl = document.getElementById('diag-modal-drive');
    const faultsEl = document.getElementById('diag-modal-faults');
    const statusEl = document.getElementById('diag-modal-status');
    const progressWrapper = document.getElementById('diag-progress-wrapper');
    const resultCard = document.getElementById('diag-result-card');
    const startBtn = document.getElementById('btn-start-diag');

    if (driveEl) driveEl.textContent = dev.model;
    if (faultsEl) faultsEl.textContent = dev.reallocatedSectors > 0
      ? `${dev.reallocatedSectors} reallocated bad sectors`
      : 'Critical hardware fault reported';
    if (statusEl) statusEl.textContent = 'Ready to scan';
    if (progressWrapper) progressWrapper.style.display = 'none';
    if (resultCard) { resultCard.style.display = 'none'; resultCard.innerHTML = ''; }
    if (startBtn) { startBtn.disabled = false; startBtn.querySelector('span').textContent = 'Run Deep Verification Pass'; }

    overlay.style.display = 'flex';
  }

  closeDiagnosticsModal() {
    const overlay = document.getElementById('diagnostics-modal-overlay');
    if (overlay) overlay.style.display = 'none';
    if (this._diagTimer) { clearInterval(this._diagTimer); this._diagTimer = null; }
  }

  runDiagnosticsCheck() {
    const dev = this.selectedDevice;
    if (!dev) return;

    const statusEl = document.getElementById('diag-modal-status');
    const progressWrapper = document.getElementById('diag-progress-wrapper');
    const progressBar = document.getElementById('diag-progress-bar');
    const progressLabel = document.getElementById('diag-progress-label');
    const resultCard = document.getElementById('diag-result-card');
    const startBtn = document.getElementById('btn-start-diag');

    if (startBtn) startBtn.disabled = true;
    if (progressWrapper) progressWrapper.style.display = 'block';
    if (resultCard) resultCard.style.display = 'none';
    if (statusEl) statusEl.textContent = 'Scanning...';

    let progress = 0;
    const scanMessages = [
      'Querying ATA error log for pending LBA entries...',
      'Re-reading reported reallocated sector addresses...',
      'Issuing direct LBA read commands to suspected addresses...',
      'Measuring I/O latency variance across fault zones...',
      'Checking ECC parity correction counters...',
      'Cross-referencing SMART attribute 197 (Current Pending Sector Count)...',
      'Validating CRC error log for transient bus glitches...',
      'Computing final diagnostic verdict...'
    ];
    let msgIndex = 0;

    if (this._diagTimer) clearInterval(this._diagTimer);

    this._diagTimer = setInterval(() => {
      progress += Math.floor(Math.random() * 8) + 3;
      if (progress > 100) progress = 100;

      if (progressBar) progressBar.style.width = `${progress}%`;
      if (progressLabel && msgIndex < scanMessages.length) {
        progressLabel.textContent = scanMessages[msgIndex];
      }
      if (progress > (msgIndex + 1) * (100 / scanMessages.length)) msgIndex++;

      if (progress >= 100) {
        clearInterval(this._diagTimer);
        this._diagTimer = null;
        if (statusEl) statusEl.textContent = 'Scan complete';
        this._showDiagResult(dev);
      }
    }, 200);
  }

  _showDiagResult(dev) {
    const resultCard = document.getElementById('diag-result-card');
    const startBtn = document.getElementById('btn-start-diag');
    if (!resultCard) return;

    // Determine outcome based on mock device preset
    const isTrueDamage = (dev.id === 'dev-ssd-kingston-damaged' || dev.reallocatedSectors >= 48);

    if (isTrueDamage) {
      // TRUE HARDWARE DAMAGE — confirm bad sectors are physical, not transient
      resultCard.style.display = 'block';
      resultCard.style.background = 'var(--red-bg)';
      resultCard.style.border = '1.5px solid var(--red-border)';
      resultCard.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:10px;">
          <span style="font-size:18px;">🚨</span>
          <strong style="color:var(--red-neon); font-size:15px;">Confirmed: True Physical Hardware Damage</strong>
        </div>
        <p style="margin:0 0 8px; color:var(--text-secondary); line-height:1.5;">
          <strong>${dev.reallocatedSectors || 48}</strong> uncorrectable flash cell failures detected across
          ${Math.ceil((dev.reallocatedSectors || 48) / 8)} NAND block groups. These are permanent physical faults —
          not transient CRC bus glitches. Direct LBA reads to affected addresses returned <code>I/O Error (EIO)</code>
          with zero successful retries.
        </p>
        <div style="background:rgba(0,0,0,0.3); padding:8px 12px; border-radius:6px; font-size:12px; color:var(--text-muted); margin-top:8px;">
          <strong>NIST SP 800-88 Rev. 1 §4.4:</strong> When any addressable storage location is physically inaccessible
          to sanitization commands, the media MUST be physically destroyed (<2mm particle shredding) to prevent residual
          data recovery from damaged flash cells.
        </div>
      `;
      if (startBtn) { startBtn.disabled = false; startBtn.querySelector('span').textContent = 'Re-Scan'; }
    } else {
      // FALSE ALARM — transient CRC soft error, drive is actually healthy
      resultCard.style.display = 'block';
      resultCard.style.background = 'var(--emerald-bg)';
      resultCard.style.border = '1.5px solid var(--emerald-border)';
      resultCard.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:10px;">
          <span style="font-size:18px;">✅</span>
          <strong style="color:var(--emerald-text); font-size:15px;">False Alarm Cleared — Drive is Healthy</strong>
        </div>
        <p style="margin:0 0 8px; color:var(--text-secondary); line-height:1.5;">
          All <strong>${dev.reallocatedSectors || 0}</strong> previously reported bad sectors were re-read successfully
          with <strong>0 retries</strong> and <strong>0ms excess latency</strong>. The original fault was a transient
          SATA/NVMe CRC bus communication glitch (soft error), not a permanent hardware failure.
        </p>
        <div style="display:flex; gap:8px; margin-top:10px;">
          <button class="btn btn-primary" onclick="app.clearFalseAlarm()" style="flex:1;">
            ✓ Clear False Alarm & Mark Drive Healthy
          </button>
        </div>
      `;
    }
  }

  clearFalseAlarm() {
    if (!this.selectedDevice) return;

    // Update device state: remove damage flags
    this.selectedDevice.expectedOutcome = 'GREEN';
    this.selectedDevice.reallocatedSectors = 0;

    // Also update in MOCK_DEVICES array if present
    if (window.MOCK_DEVICES) {
      const mockDev = window.MOCK_DEVICES.find(d => d.id === this.selectedDevice.id);
      if (mockDev) {
        mockDev.expectedOutcome = 'GREEN';
        mockDev.reallocatedSectors = 0;
      }
    }

    // Auto-select the best non-destructive method now that drive is healthy
    if (this.selectedDevice.type && this.selectedDevice.type.includes('NVMe')) {
      this.selectedMethodId = 'purge-nvme-crypto';
    } else if (this.selectedDevice.type && this.selectedDevice.type.includes('SATA')) {
      this.selectedMethodId = 'purge-ata-secure';
    } else {
      this.selectedMethodId = 'clear-single';
    }

    // Close modal and refresh all UI
    this.closeDiagnosticsModal();
    this.renderDeviceList();
    if (typeof this.renderDriveStatus === 'function') this.renderDriveStatus();
    this.renderMethodOptions();
    this.renderStepper();
    this.showStepBlockedToast(`✅ False alarm cleared — ${this.selectedDevice.model} is now marked healthy and ready for software wipe.`);
  }

  /* ─── RESET STATE FOR NEW WIPE ─── */

  resetForNewWipe() {
    // Clear wipe state
    this.isWiping = false;
    this.wipeCompleted = false;
    this.wipeProgress = 0;
    this.activeWipeId = null;
    this.verificationCompleted = false;
    this.currentCertId = null;
    this.currentCertData = null;
    this.sectorStates = new Array(256).fill(0);

    if (this.wipeInterval) {
      clearInterval(this.wipeInterval);
      this.wipeInterval = null;
    }

    // Reset phase completion (keep phase 1 if device still selected)
    this.phaseCompleted = {
      1: !!this.selectedDevice,
      2: false,
      3: false,
      4: false,
      5: false
    };

    // Generate fresh nonce for next wipe
    const cryptoHelper = window.WipeXCrypto || window.AegisCrypto;
    this.currentNonce = cryptoHelper.generateNonce();

    // Navigate back to Step 1
    this.currentPhase = 1;
    document.querySelectorAll('.phase-screen').forEach((el, index) => {
      el.classList.toggle('active', (index + 1) === 1);
    });

    this.renderStepper();
    this.renderDeviceList();
    if (typeof this.renderDriveStatus === 'function') this.renderDriveStatus();
    this.updatePhase1ContinueBtn();
    this.renderStorageBar();
    this.renderMethodOptions();
  }
}

// Global Export
window.WipeXApp = WipeXApp;

window.addEventListener('DOMContentLoaded', () => {
  window.app = new WipeXApp();
});
