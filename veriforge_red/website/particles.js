/**
 * VeriForge Red - Particle Network Animation
 * Standalone canvas-based particle system with mouse interaction
 * Red (#c62828) and white (#ffffff) particles with connecting lines
 */

(function() {
  'use strict';

  const CONFIG = {
    particleCount: 80,
    connectionDistance: 150,
    mouseRepelDistance: 200,
    mouseRepelForce: 0.5,
    particleSpeed: 0.4,
    particleRadius: 2.5,
    colors: {
      red: '#c62828',
      redLight: '#e94560',
      white: '#ffffff',
      whiteDim: 'rgba(255,255,255,0.4)'
    }
  };

  class Particle {
    constructor(canvasWidth, canvasHeight) {
      this.canvasWidth = canvasWidth;
      this.canvasHeight = canvasHeight;
      this.x = Math.random() * canvasWidth;
      this.y = Math.random() * canvasHeight;
      const angle = Math.random() * Math.PI * 2;
      const speed = Math.random() * CONFIG.particleSpeed + 0.1;
      this.vx = Math.cos(angle) * speed;
      this.vy = Math.sin(angle) * speed;
      this.radius = Math.random() * CONFIG.particleRadius + 1;
      this.isRed = Math.random() < 0.35;
      this.alpha = Math.random() * 0.5 + 0.5;
    }

    update(mouse, width, height) {
      this.x += this.vx;
      this.y += this.vy;

      if (this.x < 0) this.x = width;
      if (this.x > width) this.x = 0;
      if (this.y < 0) this.y = height;
      if (this.y > height) this.y = 0;

      if (mouse.x !== null && mouse.y !== null) {
        const dx = this.x - mouse.x;
        const dy = this.y - mouse.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONFIG.mouseRepelDistance && dist > 0) {
          const force = (CONFIG.mouseRepelDistance - dist) / CONFIG.mouseRepelDistance;
          this.x += (dx / dist) * force * CONFIG.mouseRepelForce * 5;
          this.y += (dy / dist) * force * CONFIG.mouseRepelForce * 5;
        }
      }
    }

    draw(ctx) {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.fillStyle = this.isRed
        ? `rgba(198, 40, 40, ${this.alpha})`
        : `rgba(255, 255, 255, ${this.alpha * 0.7})`;
      ctx.fill();
    }
  }

  class ParticleNetwork {
    constructor(canvasId, options = {}) {
      this.canvas = document.getElementById(canvasId);
      if (!this.canvas) return;

      this.ctx = this.canvas.getContext('2d');
      this.particles = [];
      this.mouse = { x: null, y: null };
      this.animationId = null;
      this.isActive = true;
      this.config = Object.assign({}, CONFIG, options);
      this.logicalWidth = 0;
      this.logicalHeight = 0;

      this.resize();
      this.initParticles();
      this.bindEvents();
      this.animate();
    }

    resize() {
      const parent = this.canvas.parentElement;
      const w = parent ? parent.offsetWidth : window.innerWidth;
      const h = parent ? parent.offsetHeight : window.innerHeight;
      const dpr = window.devicePixelRatio || 1;
      this.canvas.width = w * dpr;
      this.canvas.height = h * dpr;
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      this.canvas.style.width = w + 'px';
      this.canvas.style.height = h + 'px';
      this.logicalWidth = w;
      this.logicalHeight = h;
    }

    initParticles() {
      this.particles = [];
      for (let i = 0; i < this.config.particleCount; i++) {
        this.particles.push(new Particle(this.logicalWidth, this.logicalHeight));
      }
    }

    bindEvents() {
      const track = (x, y) => {
        const rect = this.canvas.getBoundingClientRect();
        this.mouse.x = x - rect.left;
        this.mouse.y = y - rect.top;
      };

      this.canvas.addEventListener('mousemove', e => track(e.clientX, e.clientY));
      this.canvas.addEventListener('mouseleave', () => { this.mouse.x = null; this.mouse.y = null; });
      this.canvas.addEventListener('touchmove', e => { e.preventDefault(); track(e.touches[0].clientX, e.touches[0].clientY); }, { passive: false });
      this.canvas.addEventListener('touchend', () => { this.mouse.x = null; this.mouse.y = null; });

      let resizeTimeout;
      window.addEventListener('resize', () => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(() => this.resize(), 150);
      });

      document.addEventListener('visibilitychange', () => {
        this.isActive = !document.hidden;
        if (this.isActive) this.animate();
      });
    }

    drawConnections() {
      const particles = this.particles;
      const ctx = this.ctx;

      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < this.config.connectionDistance) {
            const alpha = (1 - dist / this.config.connectionDistance) * 0.25;
            const isRedConnection = particles[i].isRed && particles[j].isRed;
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = isRedConnection
              ? `rgba(198, 40, 40, ${alpha * 1.5})`
              : `rgba(255, 255, 255, ${alpha})`;
            ctx.lineWidth = isRedConnection ? 1.2 : 0.6;
            ctx.stroke();
          }
        }
      }
    }

    animate() {
      if (!this.isActive) { this.animationId = null; return; }
      this.ctx.clearRect(0, 0, this.logicalWidth, this.logicalHeight);

      for (const p of this.particles) {
        p.update(this.mouse, this.logicalWidth, this.logicalHeight);
        p.draw(this.ctx);
      }
      this.drawConnections();
      this.animationId = requestAnimationFrame(() => this.animate());
    }

    destroy() {
      this.isActive = false;
      if (this.animationId) { cancelAnimationFrame(this.animationId); this.animationId = null; }
    }
  }

  window.ParticleNetwork = ParticleNetwork;

  document.addEventListener('DOMContentLoaded', () => {
    const canvas = document.getElementById('particle-canvas');
    if (canvas) new ParticleNetwork('particle-canvas');
  });
})();
