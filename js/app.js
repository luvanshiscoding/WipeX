/**
 * Aegis Wipe - Master Application Controller
 * Clean, Simple, Non-Technical & User-Friendly
 */

class AegisApp {
  constructor() {
    this.activeView = 'workflow';
    this.currentPhase = 1;
    
    this.devices = window.MOCK_DEVICES || [];
    this.certificateStore = window.CERTIFICATE_STORE || {};
    
    this.selectedDevice = this.devices[0];
    this.selectedMethodId = 'purge-nvme-crypto';
    
    this.unfrozen = false;
    this.isWiping = false;
    this.wipeProgress = 0;
    this.wipeSpeed = 450;
    this.wipeInterval = null;
    
    this.sectorStates = new Array(256).fill(0);
    this.currentNonce = AegisCrypto.generateNonce();
    this.currentCertId = `AEGIS-2026-980PRO-8F2B`;
    this.currentCertData = null;

    this.simpleMethods = [
      {
        id: "clear-single",
        name: "Standard Clear Wipe",
        fullName: "Standard Clear (Single-Pass 0x00 Overwrite)",
        oneLine: "Quick single-pass erasure for everyday hard drives and USBs.",
        speed: "Fast (10-15 mins)",
        recommendedFor: "HDD"
      },
      {
        id: "purge-nvme-crypto",
        name: "Deep Hardware Purge (Recommended)",
        fullName: "Deep Hardware Purge (NIST SP 800-88 Crypto Erase)",
        oneLine: "Permanent hardware-level sanitization for SSDs and sensitive data.",
        speed: "Instant (1-2 mins)",
        recommendedFor: "NVMe SSD"
      },
      {
        id: "destroy-physical",
        name: "Physical Destruction",
        fullName: "Mandatory Mechanical Disintegration (<2mm)",
        oneLine: "Mandated only if the drive has physical damage that software cannot wipe.",
        speed: "Mechanical Shredder",
        recommendedFor: "FAILING"
      }
    ];

    this.init();
  }

  init() {
    this.renderStepper();
    this.renderDeviceList();
    this.renderStorageBar();
    this.renderMethodOptions();
    this.initCanvas();
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
    this.currentPhase = phaseNum;
    
    document.querySelectorAll('.phase-screen').forEach((el, index) => {
      el.classList.toggle('active', (index + 1) === phaseNum);
    });

    this.renderStepper();

    if (phaseNum === 2) {
      this.renderStorageBar();
    } else if (phaseNum === 3) {
      this.renderMethodOptions();
    } else if (phaseNum === 4) {
      this.resetWipeCanvas();
    } else if (phaseNum === 5) {
      this.renderVerification();
    } else if (phaseNum === 6) {
      this.renderTrustScore();
    } else if (phaseNum === 7) {
      this.renderCertificate();
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  /* STEP 1: SELECT DRIVE */
  renderDeviceList() {
    const listEl = document.getElementById('device-card-list');
    const alertEl = document.getElementById('step-1-alert');
    if (!listEl) return;

    listEl.innerHTML = this.devices.map(dev => {
      const isSelected = dev.id === this.selectedDevice.id;
      let healthBadge = `<span class="card-health-pill pill-green">Good Condition</span>`;
      if (dev.expectedOutcome === 'YELLOW') {
        healthBadge = `<span class="card-health-pill pill-yellow">Old / Aged</span>`;
      } else if (dev.expectedOutcome === 'RED') {
        healthBadge = `<span class="card-health-pill pill-red">Damaged</span>`;
      }

      return `
        <div class="device-card ${isSelected ? 'selected' : ''}" onclick="app.selectDevice('${dev.id}')">
          <div class="card-top">
            <span class="card-device-type">${dev.type}</span>
            ${healthBadge}
          </div>
          <div class="card-model-name">${dev.model}</div>
          <div class="card-meta-row">
            <span>Serial: ${dev.maskedSerial}</span>
            <span class="font-bold">${dev.capacity.split(' ')[0]} ${dev.capacity.split(' ')[1]}</span>
          </div>
        </div>
      `;
    }).join('');

    if (alertEl) {
      const dev = this.selectedDevice;
      if (dev.expectedOutcome === 'GREEN') {
        alertEl.className = 'simple-alert-box alert-green';
        alertEl.innerHTML = `✓ <strong>${dev.model}</strong> is in healthy condition. Ready for secure wipe.`;
      } else if (dev.expectedOutcome === 'YELLOW') {
        alertEl.className = 'simple-alert-box alert-yellow';
        alertEl.innerHTML = `⚠️ <strong>${dev.model}</strong> can be wiped cleanly, but is an older drive (${dev.powerOnHours}).`;
      } else if (dev.expectedOutcome === 'RED') {
        alertEl.className = 'simple-alert-box alert-red';
        alertEl.innerHTML = `🚨 <strong>${dev.model}</strong> has 48 bad sectors. Software cannot erase broken areas; physical shredding will be required.`;
      }
    }
  }

  selectDevice(deviceId) {
    const found = this.devices.find(d => d.id === deviceId);
    if (!found) return;

    this.selectedDevice = found;
    this.unfrozen = false;
    
    if (found.expectedOutcome === 'RED') {
      this.selectedMethodId = 'destroy-physical';
    } else if (found.type.includes('NVMe')) {
      this.selectedMethodId = 'purge-nvme-crypto';
    } else {
      this.selectedMethodId = 'clear-single';
    }

    this.renderDeviceList();
  }

  /* STEP 2: STORAGE UNLOCK */
  renderStorageBar() {
    const dev = this.selectedDevice;
    const barEl = document.getElementById('storage-visual-bar');
    const promptDesc = document.getElementById('prompt-desc');
    const proceedBtn = document.getElementById('btn-proceed-phase-3');

    if (!barEl) return;

    if (dev.hpaDetected) {
      barEl.innerHTML = `
        <div class="lba-segment color-user" style="flex: 8;">User Storage (480 GB)</div>
        <div class="lba-segment color-hpa" style="flex: 2;">Hidden HPA (${this.unfrozen ? 'Unlocked' : 'Locked 32GB'})</div>
      `;
    } else {
      barEl.innerHTML = `
        <div class="lba-segment color-user" style="flex: 10;">Full Drive Space (${dev.capacity.split('(')[0]}) — Ready</div>
      `;
    }

    if (promptDesc) {
      if (this.unfrozen) {
        promptDesc.innerHTML = `<span class="text-emerald font-bold">✓ Drive unlocked successfully. 100% of storage is ready to be wiped.</span>`;
      } else {
        promptDesc.textContent = `Click below to unlock all hidden storage areas before wiping.`;
      }
    }

    if (proceedBtn) {
      proceedBtn.disabled = !this.unfrozen;
    }
  }

  executeUnfreeze() {
    this.unfrozen = true;
    this.renderStorageBar();
  }

  /* STEP 3: SANITIZATION METHODS */
  renderMethodOptions() {
    const listEl = document.getElementById('method-options-list');
    if (!listEl) return;

    listEl.innerHTML = this.simpleMethods.map(m => {
      const isSelected = (m.id === this.selectedMethodId);
      const isRecommended = (
        (this.selectedDevice.expectedOutcome === 'RED' && m.id === 'destroy-physical') ||
        (this.selectedDevice.expectedOutcome !== 'RED' && m.id === 'purge-nvme-crypto' && this.selectedDevice.type.includes('NVMe')) ||
        (this.selectedDevice.expectedOutcome !== 'RED' && m.id === 'clear-single' && !this.selectedDevice.type.includes('NVMe'))
      );

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
    const cols = 32;
    const rows = 8;
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

  startWipeExecution() {
    this.goToPhase(4);
    this.resetWipeCanvas();
    this.isWiping = true;
    this.currentNonce = AegisCrypto.generateNonce();

    const proceedBtn = document.getElementById('btn-proceed-phase-5');
    if (proceedBtn) proceedBtn.disabled = true;

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

  speedUpWipe() {
    const totalClusters = 256;
    const isDamaged = (this.selectedDevice.expectedOutcome === 'RED');

    for (let i = 0; i < totalClusters; i++) {
      this.sectorStates[i] = (isDamaged && i % 20 === 0) ? 3 : 2;
    }

    this.wipeProgress = 100;
    this.isWiping = false;
    clearInterval(this.wipeInterval);
    this.updateWipeUI();
    this.drawCanvas();

    const proceedBtn = document.getElementById('btn-proceed-phase-5');
    if (proceedBtn) proceedBtn.disabled = false;
  }

  /* STEP 5: VERIFICATION */
  renderVerification() {
    const card = document.getElementById('verification-result-card');
    const title = document.getElementById('verify-title');
    const desc = document.getElementById('verify-desc');
    const isDamaged = (this.selectedDevice.expectedOutcome === 'RED');

    if (!card) return;

    if (isDamaged) {
      card.className = "verification-result-card verify-failed";
      if (title) title.textContent = "Data Erasure Incomplete (Hardware Fault)";
      if (desc) desc.textContent = "The verification check detected damaged sectors that could not be wiped. Data cannot be guaranteed safe.";
    } else {
      card.className = "verification-result-card";
      if (title) title.textContent = "100% Data Erasure Confirmed";
      if (desc) desc.textContent = "The independent verification check confirmed that all data has been permanently deleted. No files can be recovered.";
    }
  }

  /* STEP 6: TRUST SCORE */
  renderTrustScore() {
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
      if (descEl) descEl.textContent = "All data is 100% erased (no security risk). However, the drive has high lifetime hours. Resale is not recommended due to age.";
      if (btnLabel) btnLabel.textContent = "View Certificate";
    } else if (outcome === 'RED') {
      if (titleEl) { titleEl.textContent = "DAMAGED DRIVE — MUST BE SHREDDED"; titleEl.className = "score-main-title text-red"; }
      if (descEl) descEl.textContent = "48 damaged sectors detected. Software cannot erase damaged areas. To prevent data leaks, this drive must be physically shredded.";
      if (btnLabel) btnLabel.textContent = "View Destruction Notice";
    }
  }

  /* STEP 7: ENHANCED & READABLE CERTIFICATE */
  async renderCertificate() {
    const dev = this.selectedDevice;
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    const certId = `AEGIS-2026-${dev.model.toUpperCase().includes('NVME') ? '980PRO' : 'BARRACUDA'}-${Math.floor(1000 + Math.random() * 9000)}`;

    const chosenMethod = this.simpleMethods.find(m => m.id === this.selectedMethodId) || this.simpleMethods[1];
    const canonicalString = `${dev.serialNumber}:${this.currentNonce}:${chosenMethod.id}:${timestamp}`;
    const sha256Hash = await AegisCrypto.sha256(canonicalString);

    const isGreen = (dev.expectedOutcome === 'GREEN');
    const isYellow = (dev.expectedOutcome === 'YELLOW');
    const isRed = (dev.expectedOutcome === 'RED');

    // Method description
    let displayMethod = chosenMethod.fullName;
    let cleanedStatusText = "CLEANED (100% Zero Data Confirmed)";
    let reuseScoreText = "SAFE TO REUSE OR RESELL";
    let auditText = "✓ PASSED (10,000 Sectors Verified)";

    if (isYellow) {
      reuseScoreText = "CAUTION (AGED HARDWARE)";
    } else if (isRed) {
      cleanedStatusText = "NOT CLEANED (48 Bad Sectors)";
      displayMethod = "Physical Destruction Mandated";
      reuseScoreText = "DO NOT REUSE (SHRED REQUIRED)";
      auditText = "FAILED (Damaged Sectors Detected)";
    }

    this.currentCertId = certId;
    this.currentCertData = {
      certId,
      timestamp,
      model: dev.model,
      serial: dev.serialNumber,
      capacity: dev.capacity.split('(')[0],
      method: displayMethod,
      cleanedStatus: cleanedStatusText,
      score: reuseScoreText,
      hash: sha256Hash
    };

    // Store for verification lookup
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

    // Update Status Banner
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
        if (bannerSubtext) bannerSubtext.textContent = "48 bad sectors could not be wiped. Physical mechanical destruction is mandated.";
        if (bannerTag) bannerTag.textContent = "SHRED REQUIRED";
        if (watermark) watermark.textContent = "SHRED ORDER";
      }
    }

    // Populate Details Table
    document.getElementById('cert-id-val').textContent = certId;
    document.getElementById('cert-timestamp-val').textContent = timestamp;
    document.getElementById('cert-model').textContent = dev.model;
    document.getElementById('cert-serial').textContent = dev.serialNumber;
    document.getElementById('cert-capacity').textContent = dev.capacity.split('(')[0];
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
    AegisQR.renderQR(qrContainer, `https://aegiswipe.app/verify?cert=${certId}&hash=${sha256Hash}`);
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

  verifyLookup() {
    const input = document.getElementById('portal-search-input');
    const resultCard = document.getElementById('portal-result-card');
    if (!input || !resultCard) return;

    const query = input.value.trim();
    const record = this.certificateStore[query] || Object.values(this.certificateStore).find(r => r.serialNumber === query || r.certificateId.toLowerCase().includes(query.toLowerCase()));

    if (!record) {
      resultCard.innerHTML = `
        <div style="text-align: center; padding: 24px;">
          <h3 style="font-size: 16px; font-weight: 700; color: var(--red-600); margin-bottom: 6px;">Certificate Not Found</h3>
          <p style="font-size: 13px; color: var(--text-muted);">No wipe record found for "<strong>${query}</strong>".</p>
        </div>
      `;
      return;
    }

    if (record.tamperDetected) {
      resultCard.innerHTML = `
        <div style="border-left: 4px solid var(--red-600); padding-left: 16px;">
          <h2 style="font-size: 17px; font-weight: 800; color: var(--red-600); margin-bottom: 6px;">⚠️ Fake or Modified Certificate Detected</h2>
          <p style="font-size: 13px; margin-bottom: 8px;">The digital signature does not match our database. This certificate was modified or copied to a different drive.</p>
        </div>
      `;
      return;
    }

    resultCard.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border-subtle); padding-bottom: 12px; margin-bottom: 14px;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="card-health-pill pill-green font-bold">✓ VERIFIED AUTHENTIC</span>
          <span style="font-size: 14px; font-weight: 800;">${record.certificateId}</span>
        </div>
        <span style="font-size: 12px; color: var(--text-muted);">${record.issueDate}</span>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 14px; font-size: 13px;">
        <div><strong>Drive:</strong> ${record.deviceModel}</div>
        <div><strong>Serial:</strong> <span class="font-mono text-blue font-bold">${record.serialNumber}</span></div>
        <div><strong>Method Used:</strong> ${record.standard || 'Deep Hardware Purge'}</div>
        <div><strong>Clean Status:</strong> <span class="text-emerald font-bold">100% Cleaned (Zero Residual Data)</span></div>
      </div>

      <div style="font-size: 12px; color: var(--text-secondary); background: var(--emerald-bg); padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--emerald-border);">
        ✓ This certificate is genuine and was issued directly upon completing a verified wipe of this physical drive.
      </div>
    `;
  }
}

// Initialize
window.addEventListener('DOMContentLoaded', () => {
  window.app = new AegisApp();
});
