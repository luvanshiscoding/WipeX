/**
 * WipeX - Drive Status & File Explorer Module
 * Clean macOS/Windows Finder-style UI for drive content visualization
 */

// Wait for app to be ready, then attach methods
(function() {

  // Polling until app is ready
  function attachMethods() {
    if (typeof window.app === 'undefined' || !window.app) {
      setTimeout(attachMethods, 50);
      return;
    }

    // File explorer state
    window.app.explorerFilter = window.app.explorerFilter || 'all';

    /**
     * Renders the drive status panel with file explorer
     */
    window.app.renderDriveStatus = function() {
      const panel = document.getElementById('drive-status-panel');
      if (!panel) return;

      const dev = this.selectedDevice;
      if (!dev) {
        panel.style.display = 'none';
        return;
      }
      panel.style.display = 'block';

      // Update header badge
      const cleanBadge = document.getElementById('clean-status-badge');
      const isClean = !!dev.isAlreadyClean;
      if (cleanBadge) {
        cleanBadge.textContent = isClean ? '✓ DRIVE IS CLEAN' : '⚠ CONTAINS DATA';
        cleanBadge.className = 'clean-status-badge ' + (isClean ? 'status-clean' : 'status-data');
      }

      // Update capacity bar
      const pct = typeof dev.capacityUsedPct === 'number' ? dev.capacityUsedPct : 0;
      const usedBytes = dev.capacityUsedBytes || 0;
      const totalBytes = dev.capacityBytes || 0;

      const capLabel = document.getElementById('capacity-values-label');
      const capBar = document.getElementById('capacity-bar-used');

      if (capLabel) {
        capLabel.textContent = `${this.formatBytes(usedBytes)} / ${this.formatBytes(totalBytes)} (${pct.toFixed(1)}%)`;
      }

      if (capBar) {
        capBar.style.width = `${Math.min(100, Math.max(0, pct))}%`;
        capBar.className = isClean ? 'capacity-bar-used clean' : 'capacity-bar-used';
      }

      // Update address bar
      const addressDrive = document.getElementById('address-drive-name');
      if (addressDrive) {
        addressDrive.textContent = dev.model || 'This Drive';
      }

      // Build file list
      const currentFiles = Array.isArray(dev.currentFiles) ? dev.currentFiles : [];
      const recoverableFiles = Array.isArray(dev.deletedRecoverableFiles) ? dev.deletedRecoverableFiles : [];

      // Update sidebar counts
      const totalCount = currentFiles.length + recoverableFiles.length;
      const sidebarAll = document.getElementById('sidebar-all-count');
      const sidebarActive = document.getElementById('sidebar-active-count');
      const sidebarRecoverable = document.getElementById('sidebar-recoverable-count');

      if (sidebarAll) sidebarAll.textContent = totalCount;
      if (sidebarActive) sidebarActive.textContent = currentFiles.length;
      if (sidebarRecoverable) sidebarRecoverable.textContent = recoverableFiles.length;

      // Update summary stats
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

      // Render file list
      this.renderFileExplorerList();

      // Update summary action box
      this.renderSummaryActionBox();
    };

    /**
     * Renders the file explorer list based on current filter
     */
    window.app.renderFileExplorerList = function() {
      const listEl = document.getElementById('file-explorer-list');
      if (!listEl || !this.selectedDevice) return;

      const dev = this.selectedDevice;
      const currentFiles = Array.isArray(dev.currentFiles) ? dev.currentFiles : [];
      const recoverableFiles = Array.isArray(dev.deletedRecoverableFiles) ? dev.deletedRecoverableFiles : [];

      let filesToShow = [];

      if (this.explorerFilter === 'all') {
        // Show active files first, then recoverable
        filesToShow = currentFiles.map(f => ({ ...f, status: 'active' }))
          .concat(recoverableFiles.map(f => ({ ...f, status: 'recoverable' })));
      } else if (this.explorerFilter === 'active') {
        filesToShow = currentFiles.map(f => ({ ...f, status: 'active' }));
      } else if (this.explorerFilter === 'recoverable') {
        filesToShow = recoverableFiles.map(f => ({ ...f, status: 'recoverable' }));
      }

      if (filesToShow.length === 0) {
        listEl.innerHTML = `
          <div class="empty-folder-state">
            <div class="empty-folder-icon">📁</div>
            <div class="empty-folder-text">
              ${this.explorerFilter === 'recoverable' ? 'No recoverable files found' : 'This drive is empty'}
            </div>
          </div>
        `;
        return;
      }

      // Render file rows
      const rows = filesToShow.map(file => {
        const isVolume = file.name && file.name.startsWith('💾');
        const fileName = file.name || 'Unknown';
        const fileSize = file.size || '—';
        const fileStatus = file.status || 'active';
        const recoverability = file.recoverability || '';

        let fileIcon = `<svg class="file-icon file" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;

        if (isVolume) {
          fileIcon = `<svg class="file-icon folder" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`;
        } else if (fileStatus === 'recoverable') {
          fileIcon = `<svg class="file-icon recoverable" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>`;
        }

        let fileType = isVolume ? 'Volume' : (fileStatus === 'recoverable' ? 'Deleted' : 'File');
        if (fileSize === '<dir>') fileType = 'Folder';

        let statusCell = `<span class="status-indicator ${fileStatus}"></span> ${fileStatus === 'recoverable' ? 'Recoverable' : 'Active'}`;
        if (recoverability) {
          const recovClass = recoverability.toLowerCase().includes('high') ? 'danger' : 'warning';
          statusCell = `<span class="status-indicator ${recovClass}"></span> ${recoverability}`;
        }

        return `
          <div class="file-row ${isVolume ? 'folder' : ''}">
            <div class="file-name-cell">
              ${fileIcon}
              <span class="file-name-text" title="${fileName}">${fileName}</span>
            </div>
            <div class="file-size-cell">${fileSize}</div>
            <div class="file-date-cell">${fileType}</div>
            <div class="file-status-cell">${statusCell}</div>
          </div>
        `;
      }).join('');

      listEl.innerHTML = rows;
    };

    /**
     * Updates the summary action box
     */
    window.app.renderSummaryActionBox = function() {
      const box = document.getElementById('summary-action-box');
      if (!box || !this.selectedDevice) return;

      const dev = this.selectedDevice;
      const currentFiles = Array.isArray(dev.currentFiles) ? dev.currentFiles : [];
      const recoverableFiles = Array.isArray(dev.deletedRecoverableFiles) ? dev.deletedRecoverableFiles : [];
      const isClean = !!dev.isAlreadyClean;

      let message = '';
      let cssClass = 'summary-action-box safe';

      if (dev.expectedOutcome === 'RED') {
        cssClass = 'summary-action-box danger';
        message = `🚨 Hardware is failing — this drive REQUIRES physical shredding after wipe.`;
      } else if (isClean) {
        cssClass = 'summary-action-box safe';
        message = `✓ Drive appears empty. Wipe still recommended for formal certification.`;
      } else if (recoverableFiles.length > 0) {
        cssClass = 'summary-action-box warn';
        message = `⚠ Wipe will erase ${currentFiles.length} active file(s) and purge ${recoverableFiles.length} recoverable deleted item(s).`;
      } else if (currentFiles.length > 0) {
        cssClass = 'summary-action-box safe';
        message = `✓ Ready for sanitization. Wipe will permanently erase ${currentFiles.length} file(s).`;
      } else {
        cssClass = 'summary-action-box safe';
        message = `✓ No files detected. Drive ready for verification wipe.`;
      }

      box.className = cssClass;
      box.textContent = message;
    };

    /**
     * Filter explorer view
     */
    window.app.filterExplorerView = function(filter) {
      this.explorerFilter = filter;

      // Update toolbar buttons
      const toolbarAll = document.getElementById('toolbar-all');
      const toolbarActive = document.getElementById('toolbar-active');
      const toolbarRecoverable = document.getElementById('toolbar-recoverable');

      if (toolbarAll) toolbarAll.classList.toggle('active', filter === 'all');
      if (toolbarActive) toolbarActive.classList.toggle('active', filter === 'active');
      if (toolbarRecoverable) toolbarRecoverable.classList.toggle('active', filter === 'recoverable');

      // Update sidebar
      document.querySelectorAll('.explorer-sidebar .sidebar-item').forEach(item => {
        item.classList.remove('active');
      });

      this.renderFileExplorerList();
    };

    /**
     * Toggle explorer view mode (list/details)
     */
    window.app.toggleExplorerView = function(mode) {
      document.querySelectorAll('.view-toggle-btn').forEach(btn => {
        btn.classList.remove('active');
      });
      if (event && event.target) {
        const btn = event.target.closest('.view-toggle-btn');
        if (btn) btn.classList.add('active');
      }
    };
  }

  // Start attaching
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', attachMethods);
  } else {
    attachMethods();
  }

})();

