/**
 * VeriForge Red - Main Application JavaScript
 * Scroll animations, interactions, counters, mobile menu
 */

(function() {
  'use strict';

  /* ============================================
     DOM READY
     ============================================ */
  function onReady(fn) {
    if (document.readyState !== 'loading') {
      fn();
    } else {
      document.addEventListener('DOMContentLoaded', fn);
    }
  }

  /* ============================================
     MOBILE NAV TOGGLE
     ============================================ */
  function initMobileNav() {
    const toggle = document.querySelector('.nav-toggle');
    const navLinks = document.querySelector('.nav-links');
    if (!toggle || !navLinks) return;

    toggle.addEventListener('click', () => {
      navLinks.classList.toggle('active');
      const isOpen = navLinks.classList.contains('active');
      toggle.setAttribute('aria-expanded', String(isOpen));
    });

    // Close nav on link click
    navLinks.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        navLinks.classList.remove('active');
        toggle.setAttribute('aria-expanded', 'false');
      });
    });
  }

  /* ============================================
     SMOOTH SCROLL FOR ANCHOR LINKS
     ============================================ */
  function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
      anchor.addEventListener('click', function(e) {
        const targetId = this.getAttribute('href');
        if (targetId === '#') return;
        const target = document.querySelector(targetId);
        if (target) {
          e.preventDefault();
          const navHeight = document.querySelector('.navbar')?.offsetHeight || 0;
          const top = target.getBoundingClientRect().top + window.pageYOffset - navHeight;
          window.scrollTo({ top, behavior: 'smooth' });
        }
      });
    });
  }

  /* ============================================
     SCROLL-TRIGGERED ENTRANCE ANIMATIONS
     ============================================ */
  function initScrollAnimations() {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          // Optionally unobserve after first trigger
          // observer.unobserve(entry.target);
        }
      });
    }, {
      threshold: 0.1,
      rootMargin: '0px 0px -40px 0px'
    });

    document.querySelectorAll('.animate-on-scroll').forEach(el => {
      observer.observe(el);
    });
  }

  /* ============================================
     COUNTER ANIMATION
     ============================================ */
  function initCounterAnimations() {
    const counters = document.querySelectorAll('[data-counter]');
    if (!counters.length) return;

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          animateCounter(entry.target);
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.5 });

    counters.forEach(counter => observer.observe(counter));
  }

  function animateCounter(el) {
    const target = parseInt(el.getAttribute('data-counter'), 10);
    const suffix = el.getAttribute('data-suffix') || '';
    const prefix = el.getAttribute('data-prefix') || '';
    const duration = 1500;
    const startTime = performance.now();

    function update(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out quart
      const eased = 1 - Math.pow(1 - progress, 4);
      const current = Math.round(target * eased);
      el.textContent = prefix + current.toLocaleString() + suffix;

      if (progress < 1) {
        requestAnimationFrame(update);
      }
    }

    requestAnimationFrame(update);
  }

  /* ============================================
     DOWNLOAD BUTTON HANDLERS
     ============================================ */
  function initDownloadHandlers() {
    document.querySelectorAll('[data-download]').forEach(btn => {
      btn.addEventListener('click', handleDownload);
    });
  }

  function handleDownload(e) {
    const platform = this.getAttribute('data-download');
    const version = this.getAttribute('data-version') || 'v1.0.0';

    // Show a brief feedback
    const originalText = this.innerHTML;
    this.innerHTML = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="currentColor" stroke-width="2" stroke-dasharray="20 10" transform="rotate(-90 8 8)"><animateTransform attributeName="transform" type="rotate" from="0 8 8" to="360 8 8" dur="1s" repeatCount="indefinite"/></circle></svg> Downloading...';
    this.disabled = true;

    // Simulate download delay then redirect
    setTimeout(() => {
      this.innerHTML = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M3 8l3 3 7-7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg> Starting...';

      // In production, this would be a real download URL
      const downloadUrls = {
        windows: '#download-veriforge-red-windows-' + version,
        android: '#download-veriforge-red-android-' + version,
        'windows-portable': '#download-veriforge-red-windows-portable-' + version,
        'windows-service': '#download-veriforge-red-windows-service-' + version,
        'android-debug': '#download-veriforge-red-android-debug-' + version
      };

      const url = downloadUrls[platform] || '#';
      console.log('[VeriForge Red] Download initiated:', platform, version, url);

      // Show coming soon notification
      setTimeout(() => {
        this.innerHTML = originalText;
        this.disabled = false;
        showNotification('Download will start automatically when ' + version + ' is released.', 'info');
      }, 800);
    }, 600);
  }

  /* ============================================
     NOTIFICATION SYSTEM
     ============================================ */
  function showNotification(message, type) {
    // Remove existing notifications
    const existing = document.querySelector('.vf-notification');
    if (existing) existing.remove();

    const notification = document.createElement('div');
    notification.className = 'vf-notification';
    notification.setAttribute('role', 'alert');
    notification.style.cssText = `
      position: fixed;
      bottom: 24px;
      right: 24px;
      max-width: 380px;
      padding: 16px 20px;
      background: ${type === 'error' ? '#c62828' : '#16213e'};
      color: #fff;
      border: 1px solid ${type === 'error' ? '#e94560' : 'rgba(198,40,40,0.3)'};
      border-radius: 12px;
      font-size: 0.88rem;
      font-weight: 500;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
      z-index: 10000;
      animation: slideInRight 0.4s ease-out;
      line-height: 1.5;
    `;
    notification.textContent = message;

    document.body.appendChild(notification);

    setTimeout(() => {
      notification.style.animation = 'slideOutRight 0.3s ease-in';
      setTimeout(() => notification.remove(), 300);
    }, 4000);
  }

  /* ============================================
     COLLAPSIBLE SECTIONS
     ============================================ */
  function initCollapsibles() {
    document.querySelectorAll('.collapsible-header').forEach(header => {
      header.addEventListener('click', () => {
        const collapsible = header.closest('.collapsible');
        collapsible.classList.toggle('open');
        const isOpen = collapsible.classList.contains('open');
        header.setAttribute('aria-expanded', String(isOpen));
      });
    });
  }

  /* ============================================
     NAVBAR SCROLL EFFECT
     ============================================ */
  function initNavbarScroll() {
    const navbar = document.querySelector('.navbar');
    if (!navbar) return;

    let lastScroll = 0;
    window.addEventListener('scroll', () => {
      const currentScroll = window.pageYOffset;

      if (currentScroll > 50) {
        navbar.style.background = 'rgba(10, 10, 26, 0.95)';
        navbar.style.boxShadow = '0 2px 20px rgba(0,0,0,0.3)';
      } else {
        navbar.style.background = 'rgba(10, 10, 26, 0.85)';
        navbar.style.boxShadow = 'none';
      }

      lastScroll = currentScroll;
    }, { passive: true });
  }

  /* ============================================
     KEYBOARD SHORTCUTS
     ============================================ */
  function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      // Escape closes mobile nav
      if (e.key === 'Escape') {
        const navLinks = document.querySelector('.nav-links');
        const toggle = document.querySelector('.nav-toggle');
        if (navLinks && navLinks.classList.contains('active')) {
          navLinks.classList.remove('active');
          toggle.setAttribute('aria-expanded', 'false');
        }
      }
    });
  }

  /* ============================================
     ADD NOTIFICATION KEYFRAME ANIMATIONS
     ============================================ */
  function injectNotificationStyles() {
    if (document.getElementById('vf-notification-styles')) return;
    const style = document.createElement('style');
    style.id = 'vf-notification-styles';
    style.textContent = `
      @keyframes slideInRight {
        from { opacity: 0; transform: translateX(100%); }
        to { opacity: 1; transform: translateX(0); }
      }
      @keyframes slideOutRight {
        from { opacity: 1; transform: translateX(0); }
        to { opacity: 0; transform: translateX(100%); }
      }
    `;
    document.head.appendChild(style);
  }

  /* ============================================
     INITIALIZE ALL
     ============================================ */
  onReady(() => {
    initMobileNav();
    initSmoothScroll();
    initScrollAnimations();
    initCounterAnimations();
    initDownloadHandlers();
    initCollapsibles();
    initNavbarScroll();
    initKeyboardShortcuts();
    injectNotificationStyles();

    console.log('%c VeriForge Red ', 'background: #c62828; color: #fff; font-weight: bold; padding: 4px 8px; border-radius: 4px;', 'initialized');
  });
})();
