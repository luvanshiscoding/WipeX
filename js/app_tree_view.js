/**
 * WipeX - Hierarchical File Tree Module
 * macOS Finder-style expandable tree structure
 */

(function() {

  function attachTreeMethods() {
    if (typeof window.app === 'undefined' || !window.app) {
      setTimeout(attachTreeMethods, 50);
      return;
    }

    // Tree state
    window.app.expandedFolders = new Set();
    window.app.fileTree = null;

    /**
     * Builds a hierarchical tree structure from flat file list
     */
    window.app.buildFileTree = function(files) {
      const tree = {
        name: 'Root',
        path: '/',
        type: 'folder',
        size: 0,
        children: []
      };

      files.forEach(file => {
        let fileName = file.name || '';
        let fileSize = file.size || '0 B';

        // Parse volume entries (💾 Macintosh HD — /)
        if (fileName.startsWith('💾')) {
          const match = fileName.match(/💾\s*([^—]+)\s*—\s*(.+)/);
          if (match) {
            const volumeName = match[1].trim();
            const mountPoint = match[2].trim();

            // Add volume as root-level folder
            let volumeNode = tree.children.find(c => c.name === volumeName);
            if (!volumeNode) {
              volumeNode = {
                name: volumeName,
                path: mountPoint,
                type: 'volume',
                size: fileSize,
                sizeBytes: this.parseSize(fileSize),
                children: [],
                icon: '💾'
              };
              tree.children.push(volumeNode);
            }
          }
        }
        // Parse file paths (Macintosh HD/Applications)
        else if (fileName.includes('/')) {
          const parts = fileName.split('/');
          const volumeName = parts[0];
          const filePath = parts.slice(1).join('/');

          // Find or create volume
          let volumeNode = tree.children.find(c => c.name === volumeName);
          if (!volumeNode) {
            volumeNode = {
              name: volumeName,
              path: '/' + volumeName,
              type: 'volume',
              size: '0 B',
              sizeBytes: 0,
              children: [],
              icon: '💾'
            };
            tree.children.push(volumeNode);
          }

          // Add file/folder to volume
          if (filePath) {
            const isDir = fileSize === '<dir>';
            volumeNode.children.push({
              name: filePath,
              path: fileName,
              type: isDir ? 'folder' : 'file',
              size: isDir ? '—' : fileSize,
              sizeBytes: isDir ? 0 : this.parseSize(fileSize),
              children: isDir ? [] : undefined,
              icon: isDir ? '📁' : '📄'
            });
          }
        }
        // Standalone files
        else {
          const isDir = fileSize === '<dir>';
          tree.children.push({
            name: fileName,
            path: fileName,
            type: isDir ? 'folder' : 'file',
            size: isDir ? '—' : fileSize,
            sizeBytes: isDir ? 0 : this.parseSize(fileSize),
            children: isDir ? [] : undefined,
            icon: isDir ? '📁' : '📄'
          });
        }
      });

      return tree;
    };

    /**
     * Parse size string to bytes for sorting
     */
    window.app.parseSize = function(sizeStr) {
      if (!sizeStr || sizeStr === '—' || sizeStr === '<dir>') return 0;

      const match = sizeStr.match(/([\d.]+)\s*([KMGT]?B)/i);
      if (!match) return 0;

      const value = parseFloat(match[1]);
      const unit = match[2].toUpperCase();

      const multipliers = {
        'B': 1,
        'KB': 1024,
        'MB': 1024 * 1024,
        'GB': 1024 * 1024 * 1024,
        'TB': 1024 * 1024 * 1024 * 1024
      };

      return value * (multipliers[unit] || 1);
    };

    /**
     * Renders the file tree
     */
    window.app.renderFileTree = function() {
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
          <div class="empty-folder-state">
            <div class="empty-folder-icon">📁</div>
            <div class="empty-folder-text">
              ${this.explorerFilter === 'recoverable' ? 'No recoverable files found' : 'This drive is empty'}
            </div>
          </div>
        `;
        return;
      }

      // Build tree structure
      this.fileTree = this.buildFileTree(filesToShow);

      // Render tree
      listEl.innerHTML = this.renderTreeNode(this.fileTree.children, 0);
    };

    /**
     * Renders a tree node recursively
     */
    window.app.renderTreeNode = function(nodes, depth) {
      if (!nodes || nodes.length === 0) return '';

      // Sort: folders first, then by name
      const sorted = [...nodes].sort((a, b) => {
        if (a.type === 'folder' && b.type !== 'folder') return -1;
        if (a.type !== 'folder' && b.type === 'folder') return 1;
        return a.name.localeCompare(b.name);
      });

      return sorted.map(node => {
        const isFolder = node.type === 'folder' || node.type === 'volume';
        const isExpanded = this.expandedFolders.has(node.path);
        const hasChildren = node.children && node.children.length > 0;
        const paddingLeft = depth * 20;

        let icon = node.icon || '📄';
        if (node.type === 'volume') icon = '💾';
        else if (node.type === 'folder') icon = isExpanded ? '📂' : '📁';
        else if (node.type === 'file') icon = '📄';

        let chevron = '';
        if (isFolder && hasChildren) {
          chevron = `<svg class="tree-chevron ${isExpanded ? 'expanded' : ''}" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>`;
        } else if (isFolder) {
          chevron = '<span class="tree-chevron-spacer"></span>';
        }

        const clickHandler = isFolder ? `onclick="app.toggleFolder('${node.path.replace(/'/g, "\\'")}')"` : '';
        const folderClass = isFolder ? 'folder-row' : '';
        const expandedClass = isExpanded ? 'expanded' : '';

        let html = `
          <div class="tree-row ${folderClass} ${expandedClass}" style="padding-left: ${paddingLeft}px;" ${clickHandler}>
            <div class="tree-row-content">
              ${chevron}
              <span class="tree-icon">${icon}</span>
              <span class="tree-name">${this.escapeHtml(node.name)}</span>
              <span class="tree-size">${node.size}</span>
            </div>
          </div>
        `;

        // Render children if expanded
        if (isExpanded && hasChildren) {
          html += this.renderTreeNode(node.children, depth + 1);
        }

        return html;
      }).join('');
    };

    /**
     * Toggle folder expansion
     */
    window.app.toggleFolder = function(path) {
      if (this.expandedFolders.has(path)) {
        this.expandedFolders.delete(path);
      } else {
        this.expandedFolders.add(path);
      }
      this.renderFileTree();
    };

    /**
     * Escape HTML to prevent XSS
     */
    window.app.escapeHtml = function(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    };

    /**
     * Override renderFileExplorerList to use tree view
     */
    window.app.renderFileExplorerList = window.app.renderFileTree;

  }

  // Start attaching
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', attachTreeMethods);
  } else {
    attachTreeMethods();
  }

})();
