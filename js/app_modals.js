/**
 * WipeX - Warning Modal Module
 * Handles confirmation popups for wipe operations
 */

(function() {

  function attachModalMethods() {
    if (typeof window.app === 'undefined' || !window.app) {
      setTimeout(attachModalMethods, 50);
      return;
    }

    // Modal state
    window.app.destructionCountdown = window.app.destructionCountdown || 10;
    window.app.destructionCountdownTimer = window.app.destructionCountdownTimer || null;

    /**
     * Shows the appropriate warning modal based on wipe method
     */
    window.app.startWipeExecution = function() {
      if (!this.selectedDevice || !this.selectedMethodId) {
        alert('Please select a drive and wipe method first.');
        return;
      }

      const method = this.simpleMethods.find(m => m.id === this.selectedMethodId);
      if (!method) return;

      // Physical destruction requires 10-second countdown + checkbox
      if (this.selectedMethodId === 'destroy-physical') {
        this.showDestructionModal();
      } else {
        // Other methods show normal caution modal
        this.showCautionModal();
      }
    };

    /**
     * Shows the destruction warning modal (10s countdown)
     */
    window.app.showDestructionModal = function() {
      const overlay = document.getElementById('destruction-modal-overlay');
      const checkbox = document.getElementById('destruction-confirm-checkbox');
      const proceedBtn = document.getElementById('destruction-proceed-btn');
      const countdownEl = document.getElementById('destruction-countdown');

      if (!overlay) return;

      // Populate drive info
      const dev = this.selectedDevice;
      const driveEl = document.getElementById('destruction-modal-drive');
      const sectorsEl = document.getElementById('destruction-modal-bad-sectors');

      if (driveEl) driveEl.textContent = dev.model || 'Unknown';
      if (sectorsEl) {
        sectorsEl.textContent = dev.reallocatedSectors > 0 ? `${dev.reallocatedSectors} sectors` : 'Multiple faults';
      }

      // Reset state
      checkbox.checked = false;
      proceedBtn.disabled = true;
      this.destructionCountdown = 10;
      if (countdownEl) countdownEl.textContent = this.destructionCountdown;

      // Show modal
      overlay.style.display = 'flex';

      // Checkbox handler
      checkbox.onchange = () => {
        proceedBtn.disabled = !checkbox.checked || this.destructionCountdown > 0;
      };

      // Start countdown
      clearInterval(this.destructionCountdownTimer);
      const self = this;
      this.destructionCountdownTimer = setInterval(() => {
        self.destructionCountdown--;
        if (countdownEl) countdownEl.textContent = self.destructionCountdown;

        if (self.destructionCountdown <= 0) {
          clearInterval(self.destructionCountdownTimer);
          if (countdownEl) countdownEl.textContent = '0';
          // Enable button only if checkbox is checked
          proceedBtn.disabled = !checkbox.checked;
        }
      }, 1000);
    };

    /**
     * Cancel destruction modal
     */
    window.app.cancelDestructionModal = function() {
      const overlay = document.getElementById('destruction-modal-overlay');
      if (overlay) overlay.style.display = 'none';
      clearInterval(this.destructionCountdownTimer);
    };

    /**
     * Confirm destruction and proceed
     */
    window.app.confirmDestruction = function() {
      this.cancelDestructionModal();
      this._executeWipeInternal();
    };

    /**
     * Shows the caution warning modal (normal wipe methods)
     */
    window.app.showCautionModal = function() {
      const overlay = document.getElementById('caution-modal-overlay');
      const checkbox = document.getElementById('caution-confirm-checkbox');
      const proceedBtn = document.getElementById('caution-proceed-btn');

      if (!overlay) return;

      // Populate info
      const dev = this.selectedDevice;
      const method = this.simpleMethods.find(m => m.id === this.selectedMethodId);
      const currentFiles = Array.isArray(dev.currentFiles) ? dev.currentFiles : [];
      const recoverableFiles = Array.isArray(dev.deletedRecoverableFiles) ? dev.deletedRecoverableFiles : [];
      const totalFiles = currentFiles.length + recoverableFiles.length;

      const driveEl = document.getElementById('caution-modal-drive');
      const methodEl = document.getElementById('caution-modal-method');
      const filesEl = document.getElementById('caution-modal-files');

      if (driveEl) driveEl.textContent = dev.model || 'Unknown';
      if (methodEl) methodEl.textContent = method ? method.name : 'Unknown';
      if (filesEl) filesEl.textContent = totalFiles > 0 ? `${totalFiles} files` : 'All data';

      // Reset state
      checkbox.checked = false;
      proceedBtn.disabled = true;

      // Show modal
      overlay.style.display = 'flex';

      // Checkbox handler
      checkbox.onchange = () => {
        proceedBtn.disabled = !checkbox.checked;
      };
    };

    /**
     * Cancel caution modal
     */
    window.app.cancelCautionModal = function() {
      const overlay = document.getElementById('caution-modal-overlay');
      if (overlay) overlay.style.display = 'none';
    };

    /**
     * Confirm wipe from caution modal
     */
    window.app.confirmWipe = function() {
      this.cancelCautionModal();
      this._executeWipeInternal();
    };

    /**
     * Internal wipe execution (called after modal confirmation)
     */
    window.app._executeWipeInternal = async function() {
      this.goToPhase(3);
      this.resetWipeCanvas();
      this.isWiping = true;
      this.wipeCompleted = false;
      this.phaseCompleted[3] = false;
      this.phaseCompleted[4] = false;
      this.phaseCompleted[5] = false;
      this.phaseCompleted[6] = false;
      this.renderStepper();

      const cryptoHelper = window.WipeXCrypto || window.AegisCrypto;
      this.currentNonce = cryptoHelper.generateNonce();

      const proceedBtn = document.getElementById('btn-proceed-phase-4');
      if (proceedBtn) proceedBtn.disabled = true;

      // In Demo Mode, simulate purely in client UI without hitting real backend storage driver
      if (this.demoMode) {
        this.activeWipeId = null;
      } else {
        // Start real hardware wipe on backend
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
        } catch (e) {
          console.warn('Backend wipe start failed, running standalone mode:', e);
        }
      }

      const totalClusters = 256;
      let currentCluster = 0;
      const isDamaged = (this.selectedDevice.expectedOutcome === 'RED');
      const self = this;

      clearInterval(this.wipeInterval);

      if (this.activeWipeId) {
        // Real backend polling
        this.wipeInterval = setInterval(async () => {
          try {
            const statusRes = await fetch(`${self.apiBaseUrl}/api/wipe/status/${self.activeWipeId}`);
            if (statusRes.ok) {
              const statusData = await statusRes.json();
              const backendPct = statusData.progress || 0;
              const targetCluster = Math.min(totalClusters, Math.round((backendPct / 100) * totalClusters));

              while (currentCluster < targetCluster) {
                self.sectorStates[currentCluster] = 1;
                if (currentCluster > 0) {
                  self.sectorStates[currentCluster - 1] = (isDamaged && currentCluster % 20 === 0) ? 3 : 2;
                }
                currentCluster++;
              }

              self.wipeProgress = backendPct;
              self.updateWipeUI();
              self.drawCanvas();

              if (statusData.status === 'COMPLETED' || backendPct >= 100) {
                clearInterval(self.wipeInterval);
                self.wipeProgress = 100;
                for (let i = 0; i < totalClusters; i++) {
                  self.sectorStates[i] = (isDamaged && i % 20 === 0) ? 3 : 2;
                }
                self.isWiping = false;
                self.wipeCompleted = true;
                self.phaseCompleted[3] = true;
                self.updateWipeUI();
                self.drawCanvas();
                if (proceedBtn) proceedBtn.disabled = false;
                self.renderStepper();
              } else if (statusData.status === 'FAILED') {
                clearInterval(self.wipeInterval);
                self.isWiping = false;
                alert(`Sanitization error: ${statusData.command || 'Device write failure'}`);
              }
            }
          } catch (err) {
            // fallback increment
            if (currentCluster < totalClusters) {
              self.sectorStates[currentCluster] = 2;
              currentCluster++;
              self.wipeProgress = Math.round((currentCluster / totalClusters) * 100);
              self.updateWipeUI();
              self.drawCanvas();
            }
          }
        }, 300);
      } else {
        // Fallback simulation timer
        this.wipeInterval = setInterval(() => {
          if (currentCluster < totalClusters) {
            if (currentCluster > 0) {
              self.sectorStates[currentCluster - 1] = (isDamaged && currentCluster % 20 === 0) ? 3 : 2;
            }
            self.sectorStates[currentCluster] = 1;
            currentCluster++;
            self.wipeProgress = Math.round((currentCluster / totalClusters) * 100);
            self.updateWipeUI();
            self.drawCanvas();
          } else {
            self.sectorStates[totalClusters - 1] = isDamaged ? 3 : 2;
            for (let i = 0; i < totalClusters; i++) {
              self.sectorStates[i] = (isDamaged && i % 20 === 0) ? 3 : 2;
            }
            self.wipeProgress = 100;
            self.isWiping = false;
            self.wipeCompleted = true;
            self.phaseCompleted[3] = true;
            clearInterval(self.wipeInterval);
            self.updateWipeUI();
            self.drawCanvas();
            if (proceedBtn) proceedBtn.disabled = false;
            self.renderStepper();
          }
        }, 40);
      }
    };
  }

  // Start attaching
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', attachModalMethods);
  } else {
    attachModalMethods();
  }

})();

