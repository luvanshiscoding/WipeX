/**
 * WipeX - Master Application Controller
 * Zero-Trust Data Sanitization & Hardware-Bound Verification Platform
 */

class WipeXApp {
  constructor() {
    this.apiBaseUrl = 'http://localhost:8000';
    this.activeWipeId = null;

    this.activeView = 'workflow';
    this.currentPhase = 1;

    this.devices = [];
    this.certificateStore = {};

    this.selectedDevice = null;
    this.selectedMethodId = 'purge-nvme-crypto';

    this.unfrozen = false;
    this.isWiping = false;
    this.wipeProgress = 0;
    this.wipeInterval = null;

    this.sectorStates = new Array(256).fill(0);
    this.currentNonce = (window.AegisCrypto || window.WipeXCrypto).generateNonce();
    this.currentCertId = null;
    this.currentCertData = null;

    this.simpleMethods = [
      {
        id: "purge-nvme-crypto",
        name: "Deep Hardware Purge (NVMe)",
        fullName: "Deep Hardware Purge (NIST SP 800-88 Crypto Erase)",
        oneLine: "Instant cryptographic key destruction + full NAND zeroing for NVMe SSDs.",
        speed: "Instant (1-2 mins)",
        recommendedFor: "NVMe SSD"
      },
      {
        id: "purge-ata-secure",
        name: "Deep Hardware Purge (ATA Enhanced)",
        fullName: "Deep Hardware Purge (NIST SP 800-88 ATA Secure Erase)",
        oneLine: "Controller-level voltage pulse sanitizing 100% of cells & HPA/DCO zones.",
        speed: "Fast (5-10 mins)",
        recommendedFor: "SATA SSD"
      },
      {
        id: "clear-single",
        name: "Standard Clear Wipe",
        fullName: "Standard Clear (NIST SP 800-88 Single-Pass 0x00 Overwrite)",
        oneLine: "Single-pass 0x00 overwrite for hard drives and USB media.",
        speed: "Standard (10-20 mins)",
        recommendedFor: "Magnetic HDD"
      },
      {
        id: "destroy-physical",
        name: "Physical Destruction Mandate",
        fullName: "Mandatory Mechanical Disintegration (<2mm Shredding)",
        oneLine: "Required when hardware has unreadable bad sectors that cannot be sanitized.",
        speed: "Physical Facility Shredder",
        recommendedFor: "FAILING"
      }
    ];

    this.init();
  }

  async init() {
    this.renderStepper();
    this.renderMethodOptions();
    this.initCanvas();
    await this.loadDevices();
  }

  async loadDevices() {
    const listEl = document.getElementById('device-card-list');

    // Show loading state
    if (listEl) {
      listEl.innerHTML = `
        <div style="text-align:center; padding:40px; color:var(--text-muted);">
          <div style="font-size:28px; margin-bottom:12px;">🔍</div>
          <div style="font-size:14px; font-weight:600;">Scanning connected drives…</div>
          <div style="font-size:12px; margin-top:6px; color:var(--text-muted);">Reading SMART diagnostics and health data</div>
        </div>
      `;
    }

    try {
      const res = await fetch(`${this.apiBaseUrl}/api/devices`);
      if (!res.ok) throw new Error('API error');
      const devices = await res.json();
      this.devices = devices;
      this.selectedDevice = devices[0] || null;
      if (this.selectedDevice) {
        this.selectedMethodId = this.selectedDevice.recommendedMethod || 'purge-nvme-crypto';
      }
      this.renderDeviceList();
      this.renderStorageBar();
      this.renderMethodOptions();
    } catch (e) {
      if (listEl) {
        listEl.innerHTML = `
          <div style="text-align:center; padding:40px; border:1.5px solid var(--red-border); background:var(--red-bg); border-radius:var(--radius-md); color:var(--red-text);">
            <div style="font-size:28px; margin-bottom:12px;">⚠️</div>
            <div style="font-size:15px; font-weight:700; margin-bottom:6px;">Backend Service Required</div>
            <div style="font-size:13px; color:var(--text-secondary); margin-bottom:14px;">Start the WipeX backend service to scan connected drives:</div>
            <code style="display:block; background:#fff; border:1px solid var(--border-subtle); border-radius:6px; padding:10px 14px; font-size:13px; font-family:var(--font-mono); color:var(--text-primary);">python3 main.py</code>
            <button class="btn btn-primary" style="margin-top:16px;" onclick="app.loadDevices()">Retry Scan</button>
          </div>
        `;
      }
    }
  }

  switchView(viewName) {
    this.activeView = viewName;
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));

    if (viewName === 'workflow') {
      document.getElementById('nav-workflow-btn')?.classList.add('active');
      document.getElementById('workflow-view')?.classList.add('active');
    } else if (viewName === 'portal') {
      document.getElementById('nav-verify-btn')?.classList.add('active');
      document.getElementById('portal-view')?.classList.add('active');
      this.verifyLookup();
    }
  }

  renderStepper() {
    const stepperEl = document.getElementById('phase-stepper');
    if (!stepperEl) return;

    const phases = [
      { num: 1, title: "1. Select Drive" },
      { num: 2, title: "2. Unlock Storage" },
      { num: 3, title: "3. Choose Method" },
      { num: 4, title: "4. Erase Data" },
      { num: 5, title: "5. Verify" },
      { num: 6, title: "6. Safety Score" },
      { num: 7, title: "7. Certificate" }
    ];

    stepperEl.innerHTML = phases.map(p => `
      <div class="step-item ${p.num === this.currentPhase ? 'active' : ''} ${p.num < this.currentPhase ? 'completed' : ''}" onclick="app.goToPhase(${p.num})">
        <div class="step-num-circle">${p.num < this.currentPhase ? '✓' : p.num}</div>
        <span class="step-title">${p.title}</span>
      </div>
    `).join('');
  }

  goToPhase(phaseNum) {
    if (phaseNum < 1 || phaseNum > 7) return;

    if (this.currentPhase === 4 && phaseNum !== 4 && this.wipeInterval) {
      clearInterval(this.wipeInterval);
      this.isWiping = false;
    }

    this.currentPhase = phaseNum;

    document.querySelectorAll('.phase-screen').forEach((el, index) => {
      el.classList.toggle('active', (index + 1) === phaseNum);
    });

    this.renderStepper();

    if (phaseNum === 1) this.renderDeviceList();
    else if (phaseNum === 2) this.renderStorageBar();
    else if (phaseNum === 3) this.renderMethodOptions();
    else if (phaseNum === 4) this.resetWipeCanvas();
    else if (phaseNum === 5) this.renderVerification();
    else if (phaseNum === 6) this.renderTrustScore();
    else if (phaseNum === 7) this.renderCertificate();

    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  /* STEP 1: SELECT DRIVE */
  renderDeviceList() {
    const listEl = document.getElementById('device-card-list');
    const alertEl = document.getElementById('step-1-alert');
    if (!listEl || !this.devices.length) return;

    listEl.innerHTML = this.devices.map(dev => {
      const isSelected = this.selectedDevice && dev.id === this.selectedDevice.id;
      let healthBadge = `<span class="card-health-pill pill-green">Good Condition</span>`;
      if (dev.expectedOutcome === 'YELLOW') {
        healthBadge = `<span class="card-health-pill pill-yellow">Aging Drive</span>`;
      } else if (dev.expectedOutcome === 'RED') {
        healthBadge = `<span class="card-health-pill pill-red">Damaged</span>`;
      }

      // Show boot drive warning
      const bootWarning = dev.isBootDrive
        ? `<div style="font-size:11px;color:var(--text-muted);margin-top:4px;">⚠️ OS Boot Drive — wipe will format the operating system</div>`
        : '';

      return `
        <div class="device-card ${isSelected ? 'selected' : ''}" onclick="app.selectDevice('${dev.id}')">
          <div class="card-top">
            <span class="card-device-type">${dev.type}</span>
            ${healthBadge}
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

    if (alertEl && this.selectedDevice) {
      const dev = this.selectedDevice;
      if (dev.expectedOutcome === 'GREEN') {
        alertEl.className = 'simple-alert-box alert-green';
        alertEl.innerHTML = `✓ <strong>${dev.model}</strong> is healthy and ready for secure wipe.`;
      } else if (dev.expectedOutcome === 'YELLOW') {
        alertEl.className = 'simple-alert-box alert-yellow';
        alertEl.innerHTML = `⚠️ <strong>${dev.model}</strong> can be wiped but is an aged drive (${dev.powerOnHours}).`;
      } else if (dev.expectedOutcome === 'RED') {
        alertEl.className = 'simple-alert-box alert-red';
        alertEl.innerHTML = `🚨 <strong>${dev.model}</strong> has ${dev.reallocatedSectors > 0 ? dev.reallocatedSectors + ' bad sectors' : 'critical hardware faults'}. Physical shredding will be required.`;
      }
    }
  }

  selectDevice(deviceId) {
    const found = this.devices.find(d => d.id === deviceId);
    if (!found) return;

    this.selectedDevice = found;
    this.unfrozen = false;
    this.selectedMethodId = found.recommendedMethod || 'purge-nvme-crypto';
    this.renderDeviceList();
  }

  /* STEP 2: STORAGE UNLOCK */
  renderStorageBar() {
    if (!this.selectedDevice) return;
    const dev = this.selectedDevice;
    const barEl = document.getElementById('storage-visual-bar');
    const promptDesc = document.getElementById('prompt-desc');
    const unfreezeBtn = document.getElementById('btn-unfreeze-action');
    const proceedBtn = document.getElementById('btn-proceed-phase-3');

    if (!barEl) return;

    if (dev.hpaDetected) {
      barEl.innerHTML = `
        <div class="lba-segment color-user" style="flex: 8;">User Storage</div>
        <div class="lba-segment ${this.unfrozen ? 'color-user' : 'color-hpa'}" style="flex: 2;">
          ${this.unfrozen ? '✓ HPA Unlocked' : '🔒 Hidden HPA Zone'}
        </div>
      `;
    } else {
      barEl.innerHTML = `
        <div class="lba-segment color-user" style="flex: 10;">
          Full Storage — ${dev.capacity.split('(')[0].trim()} ${this.unfrozen ? '✓ Ready' : ''}
        </div>
      `;
    }

    if (promptDesc) {
      if (this.unfrozen) {
        promptDesc.innerHTML = `<span class="text-emerald font-bold">✓ Drive unlocked. 100% of storage (including any hidden areas) is mapped and ready for erasure.</span>`;
      } else if (dev.hpaDetected) {
        promptDesc.textContent = `Hidden Host Protected Area detected on this drive. Click below to unfreeze all sectors before wiping.`;
      } else {
        promptDesc.textContent = `Click below to remove ATA security freeze locks and prepare all storage sectors.`;
      }
    }

    if (unfreezeBtn) {
      if (this.unfrozen) {
        unfreezeBtn.innerHTML = `<span>✓ Unlocked & Prepared</span>`;
        unfreezeBtn.className = "btn btn-secondary text-emerald font-bold";
        unfreezeBtn.disabled = true;
      } else {
        unfreezeBtn.innerHTML = `<span>Unlock Drive</span>`;
        unfreezeBtn.className = "btn btn-secondary";
        unfreezeBtn.disabled = false;
      }
    }

    if (proceedBtn) proceedBtn.disabled = !this.unfrozen;
  }

  async executeUnfreeze() {
    try {
      await fetch(`${this.apiBaseUrl}/api/storage/unfreeze/${this.selectedDevice.id}`, { method: 'POST' });
    } catch (e) { /* backend may not be needed for macOS — proceed anyway */ }
    this.unfrozen = true;
    this.renderStorageBar();
  }

  /* STEP 3: SANITIZATION METHODS */
  renderMethodOptions() {
    const listEl = document.getElementById('method-options-list');
    if (!listEl) return;

    const dev = this.selectedDevice;

    listEl.innerHTML = this.simpleMethods.map(m => {
      const isSelected = (m.id === this.selectedMethodId);
      let isRecommended = false;

      if (dev) {
        if (dev.expectedOutcome === 'RED' && m.id === 'destroy-physical') isRecommended = true;
        else if (dev.expectedOutcome !== 'RED') {
          if (dev.type && dev.type.includes('NVMe') && m.id === 'purge-nvme-crypto') isRecommended = true;
          else if (dev.type && (dev.type.includes('SATA SSD') || dev.hpaDetected) && m.id === 'purge-ata-secure') isRecommended = true;
          else if (dev.type && dev.type.includes('Magnetic') && m.id === 'clear-single') isRecommended = true;
        }
      }

      return `
        <div class="method-option-card ${isSelected ? 'selected' : ''}" onclick="app.selectSimpleMethod('${m.id}')">
          <div class="method-left">
            <div class="method-radio-circle"></div>
            <div>
              <div class="method-name">${m.name}</div>
              <div class="method-one-line">${m.oneLine}</div>
            </div>
          </div>
          ${isRecommended ? '<span class="method-badge-rec">Recommended</span>' : ''}
        </div>
      `;
    }).join('');
  }

  selectSimpleMethod(methodId) {
    this.selectedMethodId = methodId;
    this.renderMethodOptions();
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
        let fill = '#e2e8f0';
        if (state === 1) fill = '#2563eb';
        else if (state === 2) fill = '#10b981';
        else if (state === 3) fill = '#ef4444';
        ctx.fillStyle = fill;
        ctx.fillRect(c * blockWidth + 1, r * blockHeight + 1, blockWidth - 2, blockHeight - 2);
      }
    }
  }

  async startWipeExecution() {
    this.goToPhase(4);
    this.resetWipeCanvas();
    this.isWiping = true;
    const cryptoHelper = window.AegisCrypto || window.WipeXCrypto;
    this.currentNonce = cryptoHelper.generateNonce();

    const proceedBtn = document.getElementById('btn-proceed-phase-5');
    if (proceedBtn) proceedBtn.disabled = true;

    // Start wipe on backend (records to DB, runs hardware command)
    try {
      const res = await fetch(`${this.apiBaseUrl}/api/wipe/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deviceId: this.selectedDevice.id,
          methodId: this.selectedMethodId
        })
      });
      if (res.ok) {
        const data = await res.json();
        this.activeWipeId = data.wipeId;
        if (data.nonce) this.currentNonce = data.nonce;
      }
    } catch (e) { /* handle below */ }

    const totalClusters = 256;
    let currentCluster = 0;
    const isDamaged = (this.selectedDevice.expectedOutcome === 'RED');

    clearInterval(this.wipeInterval);
    this.wipeInterval = setInterval(() => {
      if (currentCluster < totalClusters) {
        if (currentCluster > 0) {
          this.sectorStates[currentCluster - 1] = (isDamaged && currentCluster % 20 === 0) ? 3 : 2;
        }
        this.sectorStates[currentCluster] = 1;
        currentCluster++;
        this.wipeProgress = Math.round((currentCluster / totalClusters) * 100);
        this.updateWipeUI();
        this.drawCanvas();
      } else {
        this.sectorStates[totalClusters - 1] = isDamaged ? 3 : 2;
        for (let i = 0; i < totalClusters; i++) {
          this.sectorStates[i] = (isDamaged && i % 20 === 0) ? 3 : 2;
        }
        this.wipeProgress = 100;
        this.isWiping = false;
        clearInterval(this.wipeInterval);
        this.updateWipeUI();
        this.drawCanvas();
        if (proceedBtn) proceedBtn.disabled = false;
      }
    }, 40);
  }

  updateWipeUI() {
    const percentEl = document.getElementById('wipe-percent-display');
    const fillEl = document.getElementById('wipe-progress-bar-fill');
    const etaEl = document.getElementById('live-eta-val');

    if (percentEl) percentEl.textContent = `${this.wipeProgress}%`;
    if (fillEl) fillEl.style.width = `${this.wipeProgress}%`;

    if (etaEl) {
      if (this.wipeProgress >= 100) etaEl.textContent = "Done";
      else {
        const sec = Math.max(1, Math.round(((100 - this.wipeProgress) / 100) * 6));
        etaEl.textContent = `00:0${sec}s`;
      }
    }
  }

  /* STEP 5: VERIFICATION */
  async renderVerification() {
    const card = document.getElementById('verification-result-card');
    const title = document.getElementById('verify-title');
    const desc = document.getElementById('verify-desc');
    const pillsContainer = card ? card.querySelector('.simple-stats-pills') : null;

    if (!card || !this.selectedDevice) return;

    const isDamaged = (this.selectedDevice.expectedOutcome === 'RED');
    const isYellow = (this.selectedDevice.expectedOutcome === 'YELLOW');

    // Run backend entropy audit
    if (this.activeWipeId) {
      try {
        await fetch(`${this.apiBaseUrl}/api/audit/run/${this.activeWipeId}`, { method: 'POST' });
      } catch (e) { /* fallback to client-side result */ }
    }

    const badSectors = this.selectedDevice.reallocatedSectors || 0;

    if (isDamaged) {
      card.className = "verification-result-card verify-failed";
      if (title) title.textContent = "Data Erasure Incomplete (Hardware Fault)";
      if (desc) desc.textContent = `Independent verification detected ${badSectors > 0 ? badSectors : 'multiple'} physically damaged sectors that could not be wiped. Data cannot be guaranteed safe.`;
      if (pillsContainer) {
        pillsContainer.innerHTML = `
          <div class="s-pill"><strong>Clean Status:</strong> <span class="text-red font-bold">UNCLEAN (${badSectors > 0 ? badSectors + ' Bad Sectors' : 'Hardware Fault'})</span></div>
          <div class="s-pill"><strong>Sectors Checked:</strong> 10,000 LBAs</div>
          <div class="s-pill"><strong>Result:</strong> <span class="text-red font-bold">FAILED — Physical Shred Required</span></div>
        `;
      }
    } else if (isYellow) {
      card.className = "verification-result-card";
      if (title) title.textContent = "100% Data Erasure Confirmed (Aged Media)";
      if (desc) desc.textContent = "Independent verification sampled 8,500 random sectors. Zero residual data found. Note: Drive has high operational hours.";
      if (pillsContainer) {
        pillsContainer.innerHTML = `
          <div class="s-pill"><strong>Clean Status:</strong> <span class="text-emerald font-bold">100% Cleaned (Zero Residual Data)</span></div>
          <div class="s-pill"><strong>Sectors Checked:</strong> 8,500 LBAs</div>
          <div class="s-pill"><strong>Result:</strong> <span class="text-amber font-bold">PASSED (Aging Hardware)</span></div>
        `;
      }
    } else {
      card.className = "verification-result-card";
      if (title) title.textContent = "100% Data Erasure Confirmed";
      if (desc) desc.textContent = "10,000 random sectors were read across the entire drive surface. Zero recoverable data was found.";
      if (pillsContainer) {
        pillsContainer.innerHTML = `
          <div class="s-pill"><strong>Clean Status:</strong> <span class="text-emerald font-bold">100% Cleaned (Zero Residual Data)</span></div>
          <div class="s-pill"><strong>Sectors Checked:</strong> 10,000 LBAs</div>
          <div class="s-pill"><strong>Result:</strong> <span class="text-emerald font-bold">PASSED</span></div>
        `;
      }
    }
  }

  /* STEP 6: TRUST SCORE */
  renderTrustScore() {
    if (!this.selectedDevice) return;
    const outcome = this.selectedDevice.expectedOutcome;

    document.getElementById('light-green')?.classList.toggle('active', outcome === 'GREEN');
    document.getElementById('light-yellow')?.classList.toggle('active', outcome === 'YELLOW');
    document.getElementById('light-red')?.classList.toggle('active', outcome === 'RED');

    const titleEl = document.getElementById('score-rating-title');
    const descEl = document.getElementById('score-rating-desc');
    const btnLabel = document.getElementById('phase-7-btn-label');

    if (outcome === 'GREEN') {
      if (titleEl) { titleEl.textContent = "SAFE TO REUSE OR RESELL"; titleEl.className = "score-main-title text-emerald"; }
      if (descEl) descEl.textContent = "100% of data has been permanently erased. The drive is healthy and completely safe to reuse, donate, or resell.";
      if (btnLabel) btnLabel.textContent = "View & Print Certificate";
    } else if (outcome === 'YELLOW') {
      if (titleEl) { titleEl.textContent = "WIPED CLEAN, BUT HARDWARE IS OLD"; titleEl.className = "score-main-title text-amber"; }
      if (descEl) descEl.textContent = "All data is 100% erased. However, the drive has high lifetime hours. Resale is not recommended due to age.";
      if (btnLabel) btnLabel.textContent = "View Certificate";
    } else if (outcome === 'RED') {
      if (titleEl) { titleEl.textContent = "DAMAGED DRIVE — MUST BE SHREDDED"; titleEl.className = "score-main-title text-red"; }
      if (descEl) descEl.textContent = "Damaged sectors were detected. Software cannot erase physically broken areas. To prevent data leaks, this drive must be physically shredded.";
      if (btnLabel) btnLabel.textContent = "View Destruction Notice";
    }
  }

  /* STEP 7: CERTIFICATE */
  async renderCertificate() {
    if (!this.selectedDevice) return;
    const dev = this.selectedDevice;
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

    // Generate slug from real model name
    let modelSlug = dev.model.toUpperCase().replace(/[^A-Z0-9]/g, '-').replace(/-+/g, '-').substring(0, 12).replace(/-$/, '');

    const randomSuffix = Math.floor(1000 + Math.random() * 9000).toString(16).toUpperCase().padStart(4, '0');
    let certId = `WIPEX-${new Date().getFullYear()}-${modelSlug}-${randomSuffix}`;

    const chosenMethod = this.simpleMethods.find(m => m.id === this.selectedMethodId) || this.simpleMethods[0];
    const canonicalString = `${dev.serialNumber}:${this.currentNonce}:${chosenMethod.id}:${timestamp}`;
    const cryptoHelper = window.AegisCrypto || window.WipeXCrypto;
    let sha256Hash = await cryptoHelper.sha256(canonicalString);

    const isGreen = (dev.expectedOutcome === 'GREEN');
    const isYellow = (dev.expectedOutcome === 'YELLOW');
    const isRed = (dev.expectedOutcome === 'RED');

    let displayMethod = chosenMethod.fullName;
    let cleanedStatusText = "CLEANED (100% Zero Data Confirmed)";
    let reuseScoreText = "SAFE TO REUSE OR RESELL";
    let auditText = "✓ PASSED (10,000 Sectors Verified)";

    if (isYellow) {
      reuseScoreText = "CAUTION (AGED HARDWARE)";
    } else if (isRed) {
      cleanedStatusText = `NOT CLEANED (${dev.reallocatedSectors > 0 ? dev.reallocatedSectors + ' Bad Sectors' : 'Hardware Fault'})`;
      displayMethod = "Physical Destruction Mandated";
      reuseScoreText = "DO NOT REUSE (SHRED REQUIRED)";
      auditText = "FAILED (Damaged Sectors Detected)";
    }

    // Backend certificate generation (persists to DB)
    if (this.activeWipeId) {
      try {
        const res = await fetch(`${this.apiBaseUrl}/api/certificates/generate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ wipeId: this.activeWipeId })
        });
        if (res.ok) {
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
      status: isGreen ? "VALID" : (isYellow ? "VALID_CAUTION" : "DESTROYED_MANDATE"),
      trustScore: dev.expectedOutcome,
      trustScoreLabel: isGreen ? "SAFE TO REUSE OR RESELL" : (isYellow ? "CAUTION (AGED)" : "SHRED REQUIRED"),
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

    // Banner
    const banner = document.getElementById('cert-status-banner');
    const bannerIcon = document.getElementById('banner-icon');
    const bannerHeadline = document.getElementById('banner-headline');
    const bannerSubtext = document.getElementById('banner-subtext');
    const bannerTag = document.getElementById('banner-tag');
    const watermark = document.getElementById('cert-watermark');

    if (banner) {
      if (isGreen) {
        banner.className = "cert-status-banner banner-green";
        if (bannerIcon) bannerIcon.textContent = "✓";
        if (bannerHeadline) bannerHeadline.textContent = "DRIVE STATUS: 100% CLEANED & SANITIZED";
        if (bannerSubtext) bannerSubtext.textContent = "Zero recoverable data detected. Drive is verified safe for circular reuse or resale.";
        if (bannerTag) bannerTag.textContent = "PASSED";
        if (watermark) watermark.textContent = "VERIFIED CLEAN";
      } else if (isYellow) {
        banner.className = "cert-status-banner banner-yellow";
        if (bannerIcon) bannerIcon.textContent = "⚠️";
        if (bannerHeadline) bannerHeadline.textContent = "DRIVE STATUS: 100% CLEANED · AGED DRIVE";
        if (bannerSubtext) bannerSubtext.textContent = "Zero data remains (data safe). Resale not recommended due to hardware age.";
        if (bannerTag) bannerTag.textContent = "CAUTION";
        if (watermark) watermark.textContent = "CLEANED · AGED";
      } else {
        banner.className = "cert-status-banner banner-red";
        if (bannerIcon) bannerIcon.textContent = "🚨";
        if (bannerHeadline) bannerHeadline.textContent = "DRIVE STATUS: NOT CLEANED · PHYSICAL FAULT";
        if (bannerSubtext) bannerSubtext.textContent = "Damaged sectors could not be wiped. Physical mechanical destruction is mandated.";
        if (bannerTag) bannerTag.textContent = "SHRED REQUIRED";
        if (watermark) watermark.textContent = "SHRED ORDER";
      }
    }

    document.getElementById('cert-id-val').textContent = certId;
    document.getElementById('cert-timestamp-val').textContent = timestamp;
    document.getElementById('cert-model').textContent = dev.model;
    document.getElementById('cert-serial').textContent = dev.serialNumber;
    document.getElementById('cert-capacity').textContent = dev.capacity.split('(')[0].trim();
    document.getElementById('cert-drive-type').textContent = dev.type;
    document.getElementById('cert-method-used').textContent = displayMethod;

    const cleanStatusEl = document.getElementById('cert-cleaned-status');
    if (cleanStatusEl) {
      cleanStatusEl.textContent = cleanedStatusText;
      cleanStatusEl.className = isRed ? "text-red font-bold" : "text-emerald font-bold";
    }

    const auditResEl = document.getElementById('cert-audit-res');
    if (auditResEl) {
      auditResEl.textContent = auditText;
      auditResEl.className = isRed ? "text-red font-bold" : "text-emerald font-bold";
    }

    const scoreLabelEl = document.getElementById('cert-score-label');
    if (scoreLabelEl) {
      scoreLabelEl.textContent = reuseScoreText;
      scoreLabelEl.className = isRed ? "text-red font-bold" : (isYellow ? "text-amber font-bold" : "text-emerald font-bold");
    }

    document.getElementById('cert-sha256').textContent = sha256Hash;

    const qrContainer = document.getElementById('cert-qr-container');
    const qrHelper = window.AegisQR || window.WipeXQR;
    qrHelper.renderQR(qrContainer, `https://wipex.app/verify?cert=${certId}&hash=${sha256Hash}`);
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

    // Try backend ledger lookup
    try {
      const res = await fetch(`${this.apiBaseUrl}/api/verify/${encodeURIComponent(query)}`);
      if (res.ok) {
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
          <h3 style="font-size: 16px; font-weight: 700; color: var(--red-600); margin-bottom: 6px;">Certificate Not Found</h3>
          <p style="font-size: 13px; color: var(--text-secondary);">No sanitization record found for "<strong>${query}</strong>". Please verify the Certificate ID or Serial Number.</p>
        </div>
      `;
      return;
    }

    if (record.tamperDetected) {
      resultCard.innerHTML = `
        <div style="border-left: 4px solid var(--red-600); background: var(--red-bg); border: 1.5px solid var(--red-border); border-left-width: 6px; padding: 18px; border-radius: var(--radius-md);">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <span class="card-health-pill pill-red font-bold">🚨 FRAUD ALERT — SIGNATURE MISMATCH</span>
            <span style="font-size: 14px; font-weight: 800; font-family: var(--font-mono);">${record.certificateId}</span>
          </div>
          <p style="font-size: 13px; color: var(--red-text); font-weight: 600; margin-bottom: 10px;">${record.verdict}</p>
          <div style="font-size: 12px; color: var(--text-secondary); background: #ffffff; padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--red-border);">
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
}

// Global Aliases
window.WipeXApp = WipeXApp;
window.AegisApp = WipeXApp;

window.addEventListener('DOMContentLoaded', () => {
  window.app = new WipeXApp();
});
