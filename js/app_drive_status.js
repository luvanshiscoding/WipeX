/**
 * WipeX - Drive Status & File Explorer Module
 * Advanced macOS/Windows Finder-style UI for drive content visualization,
 * dynamic file addition, and selective file/folder shredding.
 */

(function() {
  'use strict';

  function parseSizeToBytes(sizeStr) {
    if (!sizeStr || sizeStr === '<dir>' || sizeStr === '—') return 4096;
    const match = sizeStr.toString().match(/([\d.]+)\s*([KMGTP]?B)/i);
    if (!match) return 1024 * 1024;
    const val = parseFloat(match[1]);
    const unit = match[2].toUpperCase();
    const multipliers = { 'B': 1, 'KB': 1000, 'MB': 1000000, 'GB': 1000000000, 'TB': 1000000000000 };
    return Math.round(val * (multipliers[unit] || 1000000));
  }

  function formatBytesLocal(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    const k = 1000;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function attachMethods() {
    const proto = (typeof WipeXApp !== 'undefined') ? WipeXApp.prototype : ((typeof window !== 'undefined' && window.app) ? window.app : null);
    if (!proto) {
      setTimeout(attachMethods, 20);
      return;
    }

    /**
     * Renders the complete drive status and capacity bar
     */
    proto.renderDriveStatus = function() {
      const panel = document.getElementById('drive-status-panel');
      if (!panel) return;

      const dev = this.selectedDevice;
      if (!dev) {
        panel.style.display = 'none';
        return;
      }
      panel.style.display = 'block';

      // Clean status badge
      const currentFiles = Array.isArray(dev.currentFiles) ? dev.currentFiles : [];
      const recoverableFiles = Array.isArray(dev.deletedRecoverableFiles) ? dev.deletedRecoverableFiles : [];
      const isClean = !!dev.isAlreadyClean && currentFiles.length === 0 && recoverableFiles.length === 0;
      
      const cleanBadge = document.getElementById('clean-status-badge');
      if (cleanBadge) {
        cleanBadge.textContent = isClean ? '✓ DRIVE IS CLEAN' : '⚠ CONTAINS DATA';
        cleanBadge.className = 'clean-status-badge ' + (isClean ? 'status-clean' : 'status-data');
      }

      // Capacity calculations
      let usedBytes = dev.capacityUsedBytes || 0;
      let totalBytes = dev.capacityBytes || (1000 * 1000 * 1000 * 1000);
      let pct = (totalBytes > 0) ? (usedBytes / totalBytes) * 100 : 0;
      if (pct > 100) pct = 100;
      dev.capacityUsedPct = pct;

      const capLabel = document.getElementById('capacity-values-label');
      const capBar = document.getElementById('capacity-bar-used');

      if (capLabel) {
        capLabel.textContent = `${this.formatBytes ? this.formatBytes(usedBytes) : formatBytesLocal(usedBytes)} / ${this.formatBytes ? this.formatBytes(totalBytes) : formatBytesLocal(totalBytes)} (${pct.toFixed(1)}%)`;
      }

      if (capBar) {
        capBar.style.width = `${Math.min(100, Math.max(0, pct))}%`;
        capBar.className = isClean ? 'capacity-bar-used clean' : 'capacity-bar-used';
      }

      // Address bar
      const addressDrive = document.getElementById('address-drive-name');
      if (addressDrive) {
        addressDrive.textContent = dev.model || 'This Storage Drive';
      }

      // Counts
      const totalCount = currentFiles.length + recoverableFiles.length;
      const sidebarAll = document.getElementById('sidebar-all-count');
      const sidebarActive = document.getElementById('sidebar-active-count');
      const sidebarRecoverable = document.getElementById('sidebar-recoverable-count');

      if (sidebarAll) sidebarAll.textContent = totalCount;
      if (sidebarActive) sidebarActive.textContent = currentFiles.length;
      if (sidebarRecoverable) sidebarRecoverable.textContent = recoverableFiles.length;

      const summaryTotal = document.getElementById('summary-total-files');
      const summaryActive = document.getElementById('summary-active-files');
      const summaryRecoverable = document.getElementById('summary-recoverable-files');

      if (summaryTotal) summaryTotal.textContent = totalCount;
      if (summaryActive) summaryActive.textContent = currentFiles.length;
      if (summaryRecoverable) summaryRecoverable.textContent = recoverableFiles.length;

      const bootDriveEl = document.getElementById('summary-boot-drive');
      if (bootDriveEl) {
        bootDriveEl.textContent = dev.isBootDrive ? 'Yes' : 'No';
        bootDriveEl.className = dev.isBootDrive ? 'summary-stat-value danger' : 'summary-stat-value success';
      }

      // File list & Targeted bar
      this.updateTargetedSelectionBar();
      this.renderFileExplorerList();
      this.renderSummaryActionBox();
    };

    /**
     * Alias for compatibility
     */
    proto.renderStorageBar = function() {
      if (typeof this.renderDriveStatus === 'function') {
        this.renderDriveStatus();
      }
    };

    proto.setWipeMode = function(mode) {
      this.wipeScope = (mode === 'selective') ? 'selective' : 'entire';

      const btnEntire = document.getElementById('btn-mode-entire-drive');
      const btnSelective = document.getElementById('btn-mode-selective-files');
      const selectiveControls = document.getElementById('selective-controls');

      if (btnEntire) btnEntire.classList.toggle('active', this.wipeScope === 'entire');
      if (btnSelective) btnSelective.classList.toggle('active', this.wipeScope === 'selective');
      if (selectiveControls) selectiveControls.style.display = (this.wipeScope === 'selective') ? 'flex' : 'none';

      if (this.wipeScope === 'entire') {
        if (this.selectedFileNames) this.selectedFileNames.clear();
      }

      this.updateTargetedSelectionBar();
      this.renderFileExplorerList();
      this.renderSummaryActionBox();
    };

    proto.toggleFileSelection = function(fileName, isChecked) {
      if (!this.selectedFileNames) this.selectedFileNames = new Set();
      if (isChecked) {
        this.selectedFileNames.add(fileName);
        this.wipeScope = 'selective';
      } else {
        this.selectedFileNames.delete(fileName);
        if (this.selectedFileNames.size === 0) {
          this.wipeScope = 'entire';
        }
      }

      const btnEntire = document.getElementById('btn-mode-entire-drive');
      const btnSelective = document.getElementById('btn-mode-selective-files');
      const selectiveControls = document.getElementById('selective-controls');

      if (btnEntire) btnEntire.classList.toggle('active', this.wipeScope === 'entire');
      if (btnSelective) btnSelective.classList.toggle('active', this.wipeScope === 'selective');
      if (selectiveControls) selectiveControls.style.display = (this.wipeScope === 'selective') ? 'flex' : 'none';

      this.updateTargetedSelectionBar();
      this.renderFileExplorerList();
      this.renderSummaryActionBox();
    };

    proto.selectAllFiles = function(selectAll) {
      if (!this.selectedFileNames) this.selectedFileNames = new Set();
      const dev = this.selectedDevice;
      if (!dev) return;

      const currentFiles = Array.isArray(dev.currentFiles) ? dev.currentFiles : [];
      if (selectAll) {
        this.wipeScope = 'selective';
        currentFiles.forEach(f => {
          if (f.name) this.selectedFileNames.add(f.name);
        });
      } else {
        this.selectedFileNames.clear();
        this.wipeScope = 'entire';
      }

      const btnEntire = document.getElementById('btn-mode-entire-drive');
      const btnSelective = document.getElementById('btn-mode-selective-files');
      const selectiveControls = document.getElementById('selective-controls');

      if (btnEntire) btnEntire.classList.toggle('active', this.wipeScope === 'entire');
      if (btnSelective) btnSelective.classList.toggle('active', this.wipeScope === 'selective');
      if (selectiveControls) selectiveControls.style.display = (this.wipeScope === 'selective') ? 'flex' : 'none';

      this.updateTargetedSelectionBar();
      this.renderFileExplorerList();
      this.renderSummaryActionBox();
    };

    proto.updateTargetedSelectionBar = function() {
      const bar = document.getElementById('targeted-selection-bar');
      const textEl = document.getElementById('targeted-selection-text');
      const count = this.selectedFileNames ? this.selectedFileNames.size : 0;

      if (!bar) return;

      if (count > 0) {
        bar.style.display = 'flex';
        if (textEl) {
          textEl.innerHTML = `🎯 <strong>Targeted File Mode:</strong> ${count} file${count === 1 ? '' : 's'} selected for secure shredding`;
        }
      } else {
        bar.style.display = 'none';
      }

      const goBtn = document.getElementById('btn-go-phase-2');
      if (goBtn) {
        const span = goBtn.querySelector('span');
        if (span) {
          if (count > 0) {
            span.textContent = `Continue to Shred Selected (${count} File${count === 1 ? '' : 's'})`;
          } else {
            span.textContent = 'Continue to Sanitization Method';
          }
        }
      }
    };

    proto.renderFileExplorerList = function() {
      const listEl = document.getElementById('file-explorer-list');
      if (!listEl || !this.selectedDevice) return;

      const dev = this.selectedDevice;
      const currentFiles = Array.isArray(dev.currentFiles) ? dev.currentFiles : [];
      const recoverableFiles = Array.isArray(dev.deletedRecoverableFiles) ? dev.deletedRecoverableFiles : [];

      let filesToShow = [];

      if (this.explorerFilter === 'all') {
        filesToShow = currentFiles.map(f => ({ ...f, status: 'active' }))
          .concat(recoverableFiles.map(f => ({ ...f, status: 'recoverable' })));
      } else if (this.explorerFilter === 'active') {
        filesToShow = currentFiles.map(f => ({ ...f, status: 'active' }));
      } else if (this.explorerFilter === 'recoverable') {
        filesToShow = recoverableFiles.map(f => ({ ...f, status: 'recoverable' }));
      }

      if (filesToShow.length === 0) {
        listEl.innerHTML = `
          <div class="empty-folder-state" style="text-align:center; padding:32px; color:var(--text-muted);">
            <div class="empty-folder-icon" style="font-size:28px; margin-bottom:8px;">📁</div>
            <div class="empty-folder-text" style="font-size:13px; font-weight:600;">
              ${this.explorerFilter === 'recoverable' ? 'No recoverable deleted files found' : 'This drive has no files (Clean)'}
            </div>
            <div style="margin-top:12px;">
              <button class="btn btn-chip" style="font-size:12px; padding:6px 14px;" onclick="app.quickAddSampleFiles()">
                + Add Sample Files to Test
              </button>
            </div>
          </div>
        `;
        return;
      }

      const rows = filesToShow.map(file => {
        const isVolume = file.name && file.name.startsWith('💾');
        const fileName = file.name || 'Unknown';
        const fileSize = file.size || '—';
        const fileStatus = file.status || 'active';
        const recoverability = file.recoverability || '';
        const isChecked = this.selectedFileNames && this.selectedFileNames.has(fileName);

        let fileIcon = `<svg class="file-icon file" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;

        if (isVolume) {
          fileIcon = `<svg class="file-icon folder" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`;
        } else if (fileStatus === 'recoverable') {
          fileIcon = `<svg class="file-icon recoverable" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>`;
        }

        let fileType = isVolume ? 'Volume' : (fileStatus === 'recoverable' ? 'Deleted' : 'File');
        if (fileSize === '<dir>') fileType = 'Folder';

        let statusCell = `<span class="status-indicator ${fileStatus}"></span> ${fileStatus === 'recoverable' ? 'Recoverable' : 'Active'}`;
        if (recoverability) {
          const recovClass = recoverability.toLowerCase().includes('high') ? 'danger' : 'warning';
          statusCell = `<span class="status-indicator ${recovClass}"></span> ${recoverability}`;
        }

        const checkboxHtml = `
          <input type="checkbox" style="margin-right:8px; cursor:pointer; accent-color:var(--cyan-neon);" 
                 ${isChecked ? 'checked' : ''} 
                 onchange="app.toggleFileSelection('${fileName.replace(/'/g, "\\'")}', this.checked)" 
                 onclick="event.stopPropagation()">
        `;

        return `
          <div class="file-row ${isVolume ? 'folder' : ''} ${isChecked ? 'selected-row' : ''}" 
               style="${isChecked ? 'background:rgba(0,240,255,0.08); border-left:3px solid var(--cyan-neon);' : ''}"
               onclick="app.toggleFileSelection('${fileName.replace(/'/g, "\\'")}', ${!isChecked})">
            <div class="file-name-cell" style="display:flex; align-items:center;">
              ${checkboxHtml}
              ${fileIcon}
              <span class="file-name-text" title="${fileName}" style="margin-left:6px; font-weight:${isChecked ? '700' : '400'}; color:${isChecked ? 'var(--cyan-neon)' : 'inherit'};">${fileName}</span>
            </div>
            <div class="file-size-cell">${fileSize}</div>
            <div class="file-date-cell">${fileType}</div>
            <div class="file-status-cell">${statusCell}</div>
          </div>
        `;
      }).join('');

      listEl.innerHTML = rows;
    };

    proto.renderSummaryActionBox = function() {
      const box = document.getElementById('summary-action-box');
      if (!box || !this.selectedDevice) return;

      const dev = this.selectedDevice;
      const currentFiles = Array.isArray(dev.currentFiles) ? dev.currentFiles : [];
      const recoverableFiles = Array.isArray(dev.deletedRecoverableFiles) ? dev.deletedRecoverableFiles : [];
      const isClean = !!dev.isAlreadyClean && currentFiles.length === 0;
      const selectedCount = this.selectedFileNames ? this.selectedFileNames.size : 0;

      let message = '';
      let cssClass = 'summary-action-box safe';

      if (selectedCount > 0) {
        cssClass = 'summary-action-box warn';
        message = `🎯 TARGETED SHRED: ${selectedCount} file(s) selected for permanent destruction. Unselected files will remain intact.`;
      } else if (dev.expectedOutcome === 'RED') {
        cssClass = 'summary-action-box danger';
        message = `🚨 Hardware is failing — this drive REQUIRES physical shredding after wipe.`;
      } else if (isClean) {
        cssClass = 'summary-action-box safe';
        message = `✓ Drive is clean with 0 files. Full drive sanitization available for formal re-certification.`;
      } else if (recoverableFiles.length > 0) {
        cssClass = 'summary-action-box warn';
        message = `⚠ Entire Drive Wipe will erase ${currentFiles.length} active file(s) and purge ${recoverableFiles.length} recoverable deleted item(s).`;
      } else if (currentFiles.length > 0) {
        cssClass = 'summary-action-box safe';
        message = `✓ Ready for sanitization. Wipe will permanently erase ${currentFiles.length} file(s) across all sectors.`;
      } else {
        cssClass = 'summary-action-box safe';
        message = `✓ No files detected. Drive ready for verification wipe.`;
      }

      box.className = cssClass;
      box.textContent = message;
    };

    proto.filterExplorerView = function(filter) {
      this.explorerFilter = filter;

      const toolbarAll = document.getElementById('toolbar-all');
      const toolbarActive = document.getElementById('toolbar-active');
      const toolbarRecoverable = document.getElementById('toolbar-recoverable');

      if (toolbarAll) toolbarAll.classList.toggle('active', filter === 'all');
      if (toolbarActive) toolbarActive.classList.toggle('active', filter === 'active');
      if (toolbarRecoverable) toolbarRecoverable.classList.toggle('active', filter === 'recoverable');

      this.renderFileExplorerList();
    };
  }

  // Attach immediately or on ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', attachMethods);
  } else {
    attachMethods();
  }
})();
