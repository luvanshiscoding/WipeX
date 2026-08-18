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
     * File type icon helper
     */
    window.app.getFileIcon = function(fileName) {
      if (!fileName) return '📄';
      const ext = fileName.split('.').pop().toLowerCase();
      if (['mpg', 'mpeg', 'mp4', 'mkv', 'mov', 'avi', 'wmv'].includes(ext)) return '🎬';
      if (['mp3', 'wav', 'aac', 'flac', 'm4a', 'ogg'].includes(ext)) return '🎵';
      if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'heic'].includes(ext)) return '🖼️';
      if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2'].includes(ext)) return '📦';
      if (['pdf', 'doc', 'docx', 'txt', 'rtf', 'pages'].includes(ext)) return '📑';
      if (['html', 'htm', 'js', 'py', 'json', 'css', 'ts'].includes(ext)) return '💻';
      if (['apk', 'dmg', 'iso', 'exe'].includes(ext)) return '💿';
      return '📄';
    };

    /**
     * Builds a hierarchical tree structure from file list
     */
    window.app.buildFileTree = function(files) {
      const tree = {
        name: 'Root',
        path: '/',
        type: 'folder',
        size: 0,
        children: []
      };

      if (!files || !files.length) return tree;

      files.forEach(file => {
        let fileName = file.name || '';
        let fileSize = file.size || '0 B';
        const isDir = (fileSize === '<dir>');

        // Parse volume header entries (💾 VolumeName — /Volumes/Path)
        if (fileName.startsWith('💾')) {
          const match = fileName.match(/💾\s*([^—]+)\s*—\s*(.+)/);
          if (match) {
            const volumeName = match[1].trim();
            const mountPoint = match[2].trim();
            let volumeNode = tree.children.find(c => c.name === volumeName);
            if (!volumeNode) {
              volumeNode = {
                name: volumeName,
                path: volumeName,
                type: 'volume',
                size: fileSize,
                sizeBytes: this.parseSize(fileSize),
                children: [],
                icon: '💾'
              };
              tree.children.push(volumeNode);
              // Auto-expand top-level volume
              this.expandedFolders.add(volumeName);
            }
          }
          return;
        }

        // Relative path segments: e.g. "NO NAME/DCIM/10. HOLI.mpg" or "Documents/file.pdf"
        const segments = fileName.split('/').filter(s => s.trim().length > 0);
        if (!segments.length) return;

        let currentLevel = tree.children;
        let currentPath = '';

        segments.forEach((seg, idx) => {
          const isLast = (idx === segments.length - 1);
          currentPath = currentPath ? `${currentPath}/${seg}` : seg;

          let existingNode = currentLevel.find(n => n.name === seg);

          if (isLast) {
            if (!existingNode) {
              const node = {
                name: seg,
                path: currentPath,
                type: isDir ? 'folder' : 'file',
                size: isDir ? '—' : fileSize,
                sizeBytes: isDir ? 0 : this.parseSize(fileSize),
                children: isDir ? [] : undefined,
                icon: isDir ? '📁' : this.getFileIcon(seg)
              };
              currentLevel.push(node);
            } else if (!isDir) {
              existingNode.type = 'file';
              existingNode.size = fileSize;
              existingNode.sizeBytes = this.parseSize(fileSize);
              existingNode.icon = this.getFileIcon(seg);
            }
          } else {
            // Intermediate folder
            if (!existingNode) {
              existingNode = {
                name: seg,
                path: currentPath,
                type: (idx === 0 && currentLevel === tree.children) ? 'volume' : 'folder',
                size: '—',
                sizeBytes: 0,
                children: [],
                icon: (idx === 0 && currentLevel === tree.children) ? '💾' : '📁'
              };
              currentLevel.push(existingNode);
              // Auto-expand root folder/volume
              if (idx === 0) {
                this.expandedFolders.add(currentPath);
              }
            }
            if (!existingNode.children) existingNode.children = [];
            currentLevel = existingNode.children;
          }
        });
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
