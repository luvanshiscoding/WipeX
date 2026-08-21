/**
 * WipeX - 3D Cybersecurity Canvas & TypeScript Typewriter Dashboard
 * Features real-time particle grid, floating cryptographic nodes, cyber matrix streams,
 * and realistic code typewriter animation for the homepage.
 */

(function() {
  "use strict";

  const TYPEWRITER_SNIPPETS = [
    `// wipex-kernel-stream.ts - Enterprise Zero-Trust Storage Controller
import { KernelBlockStream, EntropyAuditor, ECDSA_P256 } from "@wipex/core";

async function executeCertifiedSanitization(drive: PhysicalMedia): Promise<WipeProof> {
  console.log(\`[WIPEX-KERNEL] Locking physical LBA geometry on \${drive.serialNumber}...\`);
  
  // 1. Hardware-level controller purge (SES=2 / NVMe Sanitize)
  const stream = new KernelBlockStream(drive.rawDevicePath, {
    mode: "DIRECT_UNBUFFERED_IO",
    sectorAlignment: 4096,
    purgeMethod: "NIST_SP_800_88_REV1_PURGE"
  });
  
  await stream.dispatchHardwareKeyDestruction();
  
  // 2. High-speed multi-pass cryptographic overwrite
  await stream.pipeZeroPattern({
    passes: 1,
    verifyInterleaved: true,
    hpaDcoUnfreeze: true
  });
  
  // 3. Mathematical Shannon Entropy Audit (10,000 LBAs)
  const entropy = await EntropyAuditor.computeShannonEntropy(drive, 10000);
  assert(entropy.value === 0.000000, "Entropy deviation detected! Residual data remains.");
  
  // 4. Hardware-bound ECDSA NIST P-256 Digital Certificate
  return await ECDSA_P256.signTamperProofCertificate({
    serial: drive.serialNumber,
    model: drive.model,
    entropy: entropy.value,
    status: "PASSED_100_PERCENT_CLEAN"
  });
}`
  ];

  class Cyber3DDashboard {
    constructor() {
      this.canvas = document.getElementById("cyber-3d-canvas");
      this.ctx = this.canvas ? this.canvas.getContext("2d") : null;
      this.animId = null;
      this.particles = [];
      this.nodes = [];
      this.connections = [];
      this.gridOffset = 0;
      this.mouse = { x: window.innerWidth / 2, y: window.innerHeight / 2 };
      this.typewriterIndex = 0;
      this.typewriterCharIndex = 0;
      this.isTyping = false;
      this.typewriterTimer = null;
      this.hasInit = false;
    }

    init() {
      if (!this.canvas) return;
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
      this.startTypewriter();
      this.hasInit = true;
    }

    resize() {
      if (!this.canvas) return;
      const parent = this.canvas.parentElement;
      this.width = this.canvas.width = parent ? parent.clientWidth : window.innerWidth;
      this.height = this.canvas.height = parent ? parent.clientHeight : 520;
    }

    createParticles() {
      this.particles = [];
      const count = Math.min(60, Math.floor(this.width / 20));
      for (let i = 0; i < count; i++) {
        this.particles.push({
          x: Math.random() * this.width,
          y: Math.random() * this.height,
          z: Math.random() * 800 + 200,
          vx: (Math.random() - 0.5) * 0.6,
          vy: (Math.random() - 0.5) * 0.6,
          vz: Math.random() * 2 + 1,
          size: Math.random() * 2 + 1,
          color: Math.random() > 0.4 ? "#00f0ff" : (Math.random() > 0.5 ? "#00ff88" : "#3b82f6"),
          alpha: Math.random() * 0.7 + 0.3
        });
      }
    }

    createNodes() {
      this.nodes = [];
      const nodeCount = 16;
      for (let i = 0; i < nodeCount; i++) {
        this.nodes.push({
          x: Math.random() * (this.width - 100) + 50,
          y: Math.random() * (this.height - 100) + 50,
          z: Math.random() * 400 + 100,
          targetX: Math.random() * (this.width - 100) + 50,
          targetY: Math.random() * (this.height - 100) + 50,
          radius: Math.random() * 4 + 3,
          pulse: Math.random() * Math.PI * 2,
          type: i % 3 === 0 ? "crypto" : (i % 3 === 1 ? "sector" : "audit"),
          label: i % 3 === 0 ? "ECDSA" : (i % 3 === 1 ? "LBA:0x" + Math.floor(Math.random()*9999).toString(16).toUpperCase() : "H(X)=0.0")
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

      // 1. Draw 3D Perspective Cyber Horizon Grid
      this.drawPerspectiveGrid(ctx, w, h);

      // 2. Draw 3D Floating Particles
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
        const radius = Math.max(0.5, p.size * k);

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

      // 3. Draw Interconnected Network Nodes
      for (let i = 0; i < this.nodes.length; i++) {
        const n1 = this.nodes[i];
        n1.pulse += 0.04;
        n1.x += (n1.targetX - n1.x) * 0.01;
        n1.y += (n1.targetY - n1.y) * 0.01;

        if (Math.hypot(n1.targetX - n1.x, n1.targetY - n1.y) < 5) {
          n1.targetX = Math.random() * (w - 100) + 50;
          n1.targetY = Math.random() * (h - 100) + 50;
        }

        for (let j = i + 1; j < this.nodes.length; j++) {
          const n2 = this.nodes[j];
          const dist = Math.hypot(n1.x - n2.x, n1.y - n2.y);
          if (dist < 180) {
            const alpha = (1 - dist / 180) * 0.25;
            ctx.beginPath();
            ctx.moveTo(n1.x, n1.y);
            ctx.lineTo(n2.x, n2.y);
            ctx.strokeStyle = "rgba(0, 240, 255, " + alpha + ")";
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }

        // Draw node aura
        const currentRadius = n1.radius + Math.sin(n1.pulse) * 1.5;
        const color = n1.type === "crypto" ? "#00f0ff" : (n1.type === "sector" ? "#00ff88" : "#38bdf8");

        ctx.beginPath();
        ctx.arc(n1.x, n1.y, currentRadius * 2.2, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.globalAlpha = 0.15;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(n1.x, n1.y, currentRadius, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.globalAlpha = 0.9;
        ctx.shadowBlur = 12;
        ctx.shadowColor = color;
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.globalAlpha = 1.0;

        // Label
        ctx.font = "10px JetBrains Mono, monospace";
        ctx.fillStyle = "rgba(255,255,255,0.7)";
        ctx.fillText(n1.label, n1.x + 8, n1.y + 3);
      }
    }

    drawPerspectiveGrid(ctx, w, h) {
      this.gridOffset = (this.gridOffset + 0.4) % 40;
      const horizon = h * 0.65;

      ctx.save();
      ctx.strokeStyle = "rgba(0, 240, 255, 0.07)";
      ctx.lineWidth = 1;

      // Perspective vertical grid lines converging towards center horizon
      const vanishX = w / 2 + (this.mouse.x - w / 2) * 0.1;
      const vanishY = horizon - 40;

      for (let x = -w * 0.5; x <= w * 1.5; x += 60) {
        ctx.beginPath();
        ctx.moveTo(x, h);
        ctx.lineTo(vanishX, vanishY);
        ctx.stroke();
      }

      // Horizontal ground plane lines
      for (let y = horizon; y <= h; y += 18) {
        const factor = (y - horizon) / (h - horizon);
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.strokeStyle = "rgba(0, 240, 255, " + (factor * 0.12) + ")";
        ctx.stroke();
      }
      ctx.restore();
    }

    startTypewriter() {
      const target = document.getElementById("typescript-typewriter-target");
      if (!target) return;

      const snippet = TYPEWRITER_SNIPPETS[this.typewriterIndex % TYPEWRITER_SNIPPETS.length];
      target.textContent = "";
      this.typewriterCharIndex = 0;

      if (this.typewriterTimer) clearInterval(this.typewriterTimer);

      this.typewriterTimer = setInterval(() => {
        if (this.typewriterCharIndex < snippet.length) {
          const char = snippet.charAt(this.typewriterCharIndex);
          target.textContent += char;
          this.typewriterCharIndex++;
        } else {
          clearInterval(this.typewriterTimer);
          // Pause then restart
          setTimeout(() => {
            this.startTypewriter();
          }, 8000);
        }
      }, 25);
    }
  }

  // Attach dashboard helper to prototype
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

  // Auto initialize on DOMContentLoaded if dashboard is open
  document.addEventListener("DOMContentLoaded", () => {
    setTimeout(() => {
      if (window.app && typeof window.app.initDashboardAnimations === "function") {
        window.app.initDashboardAnimations();
      }
    }, 100);
  });
})();
