/**
 * WipeX - 3D Cybersecurity Canvas & Feature Line-by-Line Typewriter Engine
 * Renders an interactive 3D particle constellation with cyber horizon grid,
 * and types out feature highlights smoothly line-by-line in the terminal.
 */

(function() {
  "use strict";

  const FEATURE_LINES = [
    { prefix: "[INIT]", text: "WipeX Enterprise Zero-Trust Data Sanitization Platform loaded.", color: "cyan" },
    { prefix: "[SCAN]", text: "Real-time storage device discovery across NVMe, SATA SSDs, & HDDs.", color: "green" },
    { prefix: "[FORENSIC]", text: "Deep undelete scanner reveals hidden trash, unallocated sectors, & .fseventsd.", color: "amber" },
    { prefix: "[PURGE]", text: "Hardware controller purge: NVMe crypto erase & ATA enhanced voltage reset.", color: "cyan" },
    { prefix: "[VISUALIZE]", text: "Real-time 256-cluster sector matrix visualizer with live MB/s throughput.", color: "green" },
    { prefix: "[AUDIT]", text: "Mathematical Shannon Entropy audit proves 100% zero residual data.", color: "cyan" },
    { prefix: "[TRIAGE]", text: "Circular economy health triage grades drives for resale, internal reuse, or shred.", color: "green" },
    { prefix: "[LEDGER]", text: "Hardware-bound ECDSA digital certificates & historical audit trail.", color: "amber" },
    { prefix: "[READY]", text: "All security modules operational. Click "Start Wiping" to begin.", color: "green" }
  ];

  class Cyber3DDashboard {
    constructor() {
      this.canvas = document.getElementById("cyber-3d-canvas");
      this.ctx = this.canvas ? this.canvas.getContext("2d") : null;
      this.animId = null;
      this.particles = [];
      this.nodes = [];
      this.gridOffset = 0;
      this.mouse = { x: window.innerWidth / 2, y: window.innerHeight / 2 };
      
      this.typewriterLineIndex = 0;
      this.typewriterCharIndex = 0;
      this.typewriterTimer = null;
      this.isTyping = false;
    }

    init() {
      if (!this.canvas) return;

      if (!this._hasInitialized) {
        this._hasInitialized = true;
        this.resize();
        window.addEventListener("resize", () => this.resize());
        window.addEventListener("mousemove", (e) => {
          const rect = this.canvas.getBoundingClientRect();
          this.mouse.x = e.clientX - rect.left;
          this.mouse.y = e.clientY - rect.top;
        });
        this.createParticles();
        this.createNodes();
        this.startAnimation();
      }

      // Always restart the typewriter so it types fresh when navigating back
      this.startFeatureTypewriter();
    }

    resize() {
      if (!this.canvas) return;
      const parent = this.canvas.parentElement;
      this.width = this.canvas.width = parent ? parent.clientWidth : window.innerWidth;
      this.height = this.canvas.height = parent ? parent.clientHeight : 540;
    }

    createParticles() {
      this.particles = [];
      const count = Math.min(55, Math.floor(this.width / 22));
      for (let i = 0; i < count; i++) {
        this.particles.push({
          x: Math.random() * this.width,
          y: Math.random() * this.height,
          z: Math.random() * 800 + 200,
          vx: (Math.random() - 0.5) * 0.5,
          vy: (Math.random() - 0.5) * 0.5,
          vz: Math.random() * 1.8 + 0.8,
          size: Math.random() * 2 + 1.2,
          color: Math.random() > 0.4 ? "#00f0ff" : (Math.random() > 0.5 ? "#00ff88" : "#3b82f6"),
          alpha: Math.random() * 0.65 + 0.35
        });
      }
    }

    createNodes() {
      this.nodes = [];
      const nodeCount = 14;
      for (let i = 0; i < nodeCount; i++) {
        this.nodes.push({
          x: Math.random() * (this.width - 100) + 50,
          y: Math.random() * (this.height - 100) + 50,
          targetX: Math.random() * (this.width - 100) + 50,
          targetY: Math.random() * (this.height - 100) + 50,
          radius: Math.random() * 3.5 + 2.5,
          pulse: Math.random() * Math.PI * 2,
          color: i % 2 === 0 ? "#00f0ff" : "#00ff88"
        });
      }
    }

    startAnimation() {
      if (this.animId) cancelAnimationFrame(this.animId);
      const render = () => {
        this.draw();
        this.animId = requestAnimationFrame(render);
      };
      this.animId = requestAnimationFrame(render);
    }

    draw() {
      if (!this.ctx) return;
      const ctx = this.ctx;
      const w = this.width;
      const h = this.height;

      ctx.clearRect(0, 0, w, h);

      // 1. Perspective Cyber Horizon Grid
      this.drawPerspectiveGrid(ctx, w, h);

      // 2. 3D Floating Particles
      for (const p of this.particles) {
        p.z -= p.vz;
        if (p.z <= 10) {
          p.z = 800;
          p.x = Math.random() * w;
          p.y = Math.random() * h;
        }

        const k = 250 / p.z;
        const screenX = (p.x - w / 2) * k + w / 2;
        const screenY = (p.y - h / 2) * k + h / 2;
        const radius = Math.max(0.6, p.size * k);

        if (screenX >= 0 && screenX <= w && screenY >= 0 && screenY <= h) {
          ctx.beginPath();
          ctx.arc(screenX, screenY, radius, 0, Math.PI * 2);
          ctx.fillStyle = p.color;
          ctx.globalAlpha = Math.min(1, p.alpha * (1 - p.z / 800));
          ctx.shadowBlur = 8 * k;
          ctx.shadowColor = p.color;
          ctx.fill();
          ctx.shadowBlur = 0;
          ctx.globalAlpha = 1.0;
        }
      }

      // 3. Floating Network Nodes & Connections
      for (let i = 0; i < this.nodes.length; i++) {
        const n1 = this.nodes[i];
        n1.pulse += 0.035;
        n1.x += (n1.targetX - n1.x) * 0.008;
        n1.y += (n1.targetY - n1.y) * 0.008;

        if (Math.hypot(n1.targetX - n1.x, n1.targetY - n1.y) < 6) {
          n1.targetX = Math.random() * (w - 100) + 50;
          n1.targetY = Math.random() * (h - 100) + 50;
        }

        for (let j = i + 1; j < this.nodes.length; j++) {
          const n2 = this.nodes[j];
          const dist = Math.hypot(n1.x - n2.x, n1.y - n2.y);
          if (dist < 160) {
            const alpha = (1 - dist / 160) * 0.2;
            ctx.beginPath();
            ctx.moveTo(n1.x, n1.y);
            ctx.lineTo(n2.x, n2.y);
            ctx.strokeStyle = "rgba(0, 240, 255, " + alpha + ")";
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }

        // Draw node aura
        const currentRadius = n1.radius + Math.sin(n1.pulse) * 1.2;
        ctx.beginPath();
        ctx.arc(n1.x, n1.y, currentRadius * 2, 0, Math.PI * 2);
        ctx.fillStyle = n1.color;
        ctx.globalAlpha = 0.12;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(n1.x, n1.y, currentRadius, 0, Math.PI * 2);
        ctx.fillStyle = n1.color;
        ctx.globalAlpha = 0.85;
        ctx.shadowBlur = 10;
        ctx.shadowColor = n1.color;
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.globalAlpha = 1.0;
      }
    }

    drawPerspectiveGrid(ctx, w, h) {
      this.gridOffset = (this.gridOffset + 0.35) % 36;
      const horizon = h * 0.65;

      ctx.save();
      ctx.strokeStyle = "rgba(0, 240, 255, 0.06)";
      ctx.lineWidth = 1;

      const vanishX = w / 2 + (this.mouse.x - w / 2) * 0.08;
      const vanishY = horizon - 30;

      for (let x = -w * 0.4; x <= w * 1.4; x += 55) {
        ctx.beginPath();
        ctx.moveTo(x, h);
        ctx.lineTo(vanishX, vanishY);
        ctx.stroke();
      }

      for (let y = horizon; y <= h; y += 16) {
        const factor = (y - horizon) / (h - horizon);
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.strokeStyle = "rgba(0, 240, 255, " + (factor * 0.1) + ")";
        ctx.stroke();
      }
      ctx.restore();
    }

    startFeatureTypewriter() {
      const container = document.getElementById("feature-typewriter-container");
      if (!container) return;

      container.innerHTML = "";
      this.typewriterLineIndex = 0;
      this.typewriterCharIndex = 0;

      if (this.typewriterTimer) clearInterval(this.typewriterTimer);

      const typeNextLine = () => {
        if (this.typewriterLineIndex >= FEATURE_LINES.length) {
          // Loop after pause
          setTimeout(() => {
            this.startFeatureTypewriter();
          }, 6000);
          return;
        }

        const lineData = FEATURE_LINES[this.typewriterLineIndex];
        const lineEl = document.createElement("div");
        lineEl.className = "t-feature-line";

        const prefixEl = document.createElement("span");
        prefixEl.className = "t-prefix prefix-" + lineData.color;
        prefixEl.textContent = lineData.prefix + " ";

        const textEl = document.createElement("span");
        textEl.className = "t-text";

        const cursorEl = document.createElement("span");
        cursorEl.className = "typewriter-cursor";
        cursorEl.textContent = "█";

        lineEl.appendChild(prefixEl);
        lineEl.appendChild(textEl);
        lineEl.appendChild(cursorEl);
        container.appendChild(lineEl);

        // Auto-scroll terminal container
        container.parentElement.scrollTop = container.parentElement.scrollHeight;

        let charIdx = 0;
        const charTimer = setInterval(() => {
          if (charIdx < lineData.text.length) {
            textEl.textContent += lineData.text.charAt(charIdx);
            charIdx++;
            container.parentElement.scrollTop = container.parentElement.scrollHeight;
          } else {
            clearInterval(charTimer);
            cursorEl.remove();
            this.typewriterLineIndex++;
            setTimeout(typeNextLine, 280);
          }
        }, 18);
      };

      typeNextLine();
    }
  }

  function attachDashboard() {
    const proto = (typeof WipeXApp !== "undefined") ? WipeXApp.prototype : null;
    if (!proto) {
      setTimeout(attachDashboard, 20);
      return;
    }

    proto.initDashboardAnimations = function() {
      if (!this._cyberDashboard) {
        this._cyberDashboard = new Cyber3DDashboard();
      }
      this._cyberDashboard.init();
    };
  }

  attachDashboard();

  // ─── Global Background Canvas (persists across all views) ─────────────────
  class GlobalBgCanvas {
    constructor() {
      this.canvas = document.getElementById("global-bg-canvas");
      this.ctx = this.canvas ? this.canvas.getContext("2d") : null;
      this.particles = [];
      this.animId = null;
      this.width = 0;
      this.height = 0;
      this.mouse = { x: -9999, y: -9999 };
    }

    init() {
      if (!this.canvas || !this.ctx) return;
      this.resize();
      window.addEventListener("resize", () => this.resize());
      window.addEventListener("mousemove", (e) => {
        this.mouse.x = e.clientX;
        this.mouse.y = e.clientY;
      });
      this.spawnParticles();
      this.animate();
    }

    resize() {
      this.width = this.canvas.width = window.innerWidth;
      this.height = this.canvas.height = window.innerHeight;
    }

    spawnParticles() {
      this.particles = [];
      const count = Math.min(80, Math.floor((this.width * this.height) / 18000));
      for (let i = 0; i < count; i++) {
        this.particles.push(this.makeParticle());
      }
    }

    makeParticle(atBottom = false) {
      return {
        x: Math.random() * this.width,
        y: atBottom ? this.height + 10 : Math.random() * this.height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: -(Math.random() * 0.5 + 0.15),
        radius: Math.random() * 1.8 + 0.4,
        alpha: Math.random() * 0.5 + 0.15,
        color: Math.random() > 0.5 ? "#00f0ff" : (Math.random() > 0.5 ? "#00ff88" : "#6366f1"),
        life: 1.0,
        decay: Math.random() * 0.002 + 0.001
      };
    }

    animate() {
      const ctx = this.ctx;
      const w = this.width;
      const h = this.height;
      ctx.clearRect(0, 0, w, h);

      for (let i = this.particles.length - 1; i >= 0; i--) {
        const p = this.particles[i];
        p.x += p.vx;
        p.y += p.vy;
        p.life -= p.decay;

        // Subtle mouse repulsion
        const dx = p.x - this.mouse.x;
        const dy = p.y - this.mouse.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          const force = (120 - dist) / 120 * 0.4;
          p.vx += (dx / dist) * force;
          p.vy += (dy / dist) * force;
        }

        if (p.life <= 0 || p.y < -10 || p.x < -10 || p.x > w + 10) {
          this.particles[i] = this.makeParticle(true);
          continue;
        }

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.globalAlpha = p.alpha * p.life;
        ctx.shadowBlur = 6;
        ctx.shadowColor = p.color;
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.globalAlpha = 1;
      }

      this.animId = requestAnimationFrame(() => this.animate());
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    // Boot the global background animation
    const globalBg = new GlobalBgCanvas();
    globalBg.init();
  });
})();
