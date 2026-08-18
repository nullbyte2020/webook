/**
 * Shared anti-fingerprinting / stealth layer for Kimiko webapp3.
 *
 * Addresses the detection vectors from the fingerprinting research:
 *   - Cross-layer navigator / screen consistency
 *   - Canvas 2D farbling (session + eTLD+1 bound noise)
 *   - WebGL vendor / renderer spoofing and readPixels farbling
 *   - CDP / automation artifact cleanup
 */

'use strict';

function normalizeProfile(profile) {
  const p = { ...profile };
  const isIOS = p.platform === 'iPhone' || p.platform === 'iPad' || (p.os || '').includes('iPhone OS');
  const isAndroid = p.platform === 'Android' || (p.userAgent || '').includes('Android');

  if (isIOS) {
    p.hardwareConcurrency = Math.min(p.hardwareConcurrency || 6, 6);
    p.deviceMemory = Math.min(p.deviceMemory || 6, 6);
  } else if (isAndroid) {
    p.hardwareConcurrency = Math.min(p.hardwareConcurrency || 8, 8);
    p.deviceMemory = Math.min(p.deviceMemory || 12, 12);
  }

  if (!p.webglVendor) {
    if (isIOS) p.webglVendor = 'Apple Inc.';
    else if (isAndroid) p.webglVendor = 'Google Inc. (Qualcomm)';
    else if (p.platform === 'MacIntel') p.webglVendor = 'Apple Inc.';
    else p.webglVendor = p.vendor || 'Google Inc. (NVIDIA)';
  }
  if (!p.webglRenderer) {
    if (isIOS) p.webglRenderer = 'Apple GPU';
    else if (isAndroid) p.webglRenderer = 'Adreno (TM) 730';
    else if (p.platform === 'MacIntel') p.webglRenderer = 'Apple M1';
    else p.webglRenderer = 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Direct3D11 vs_5_0 ps_5_0, D3D11)';
  }

  p.width = Math.floor(p.width || 1920);
  p.height = Math.floor(p.height || 1080);
  p.dpr = Number(p.dpr) || 1;
  return p;
}

function generateStealthScript(profile) {
  const p = normalizeProfile(profile);
  const langJson = JSON.stringify(p.languages || ['en-US', 'en']);
  const firstLang = JSON.stringify((p.languages || ['en-US'])[0]);
  const maxTouchPoints = p.isMobile ? 5 : 0;
  const availHeight = p.isMobile ? p.height : Math.max(100, p.height - Math.floor(p.height * 0.04));

  return `(() => {
    'use strict';

    // Navigator / screen consistency
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    Object.defineProperty(navigator, 'plugins', { get: () => [
      { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
      { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
      { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' }
    ] });
    Object.defineProperty(navigator, 'mimeTypes', { get: () => [
      { type: 'application/pdf', suffixes: 'pdf', description: '', enabledPlugin: navigator.plugins[1] },
      { type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: navigator.plugins[0] },
      { type: 'application/x-nacl', suffixes: '', description: 'Native Client module', enabledPlugin: navigator.plugins[2] }
    ] });
    Object.defineProperty(navigator, 'languages', { get: () => ${langJson} });
    Object.defineProperty(navigator, 'language', { get: () => ${firstLang} });
    Object.defineProperty(navigator, 'platform', { get: () => ${JSON.stringify(p.platform || 'Win32')} });
    Object.defineProperty(navigator, 'deviceMemory', { get: () => ${p.deviceMemory || 8} });
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => ${p.hardwareConcurrency || 4} });
    Object.defineProperty(navigator, 'maxTouchPoints', { get: () => ${maxTouchPoints} });
    Object.defineProperty(navigator, 'vendor', { get: () => ${JSON.stringify(p.webglVendor || p.vendor || '')} });
    Object.defineProperty(navigator, 'product', { get: () => 'Gecko' });
    Object.defineProperty(navigator, 'productSub', { get: () => '20030107' });
    Object.defineProperty(navigator, 'cookieEnabled', { get: () => true });

    const origQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = (parameters) => (
      parameters.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission })
        : origQuery(parameters)
    );

    window.chrome = window.chrome || {};
    window.chrome.runtime = window.chrome.runtime || {};
    window.chrome.csi = window.chrome.csi || function() {};
    window.chrome.loadTimes = window.chrome.loadTimes || function() { return {}; };

    Object.defineProperty(screen, 'width', { get: () => ${p.width} });
    Object.defineProperty(screen, 'height', { get: () => ${p.height} });
    Object.defineProperty(screen, 'availWidth', { get: () => ${p.width} });
    Object.defineProperty(screen, 'availHeight', { get: () => ${availHeight} });
    Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
    Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });
    Object.defineProperty(window, 'devicePixelRatio', { get: () => ${p.dpr} });
    try {
      Object.defineProperty(window.screen, 'orientation', { get: () => ({ angle: 0, type: ${JSON.stringify(p.isMobile ? 'portrait-primary' : 'landscape-primary')} }) });
    } catch {}

    // Farbling helpers
    function getDomainSeed() {
      try {
        const host = new URL(location.href).hostname;
        const parts = host.split('.');
        return parts.slice(-2).join('.');
      } catch { return 'localhost'; }
    }
    function djb2(str) {
      let h = 5381;
      for (let i = 0; i < str.length; i++) h = ((h << 5) + h) + str.charCodeAt(i);
      return h >>> 0;
    }
    const sessionSeed = ${Math.floor(Math.random() * 0xffffffff)};
    const seed = djb2(getDomainSeed() + String(sessionSeed));
    let s = seed;
    function rnd() { s = (s * 1664525 + 1013904223) >>> 0; return s; }
    const noiseMask = 1 + (rnd() % 7);

    function farblePixel(r, g, b, a) {
      const n = rnd();
      return [
        r ^ (n & noiseMask),
        g ^ ((n >> 8) & noiseMask),
        b ^ ((n >> 16) & noiseMask),
        a
      ];
    }
    function farbleImageData(img) {
      const d = img.data;
      for (let i = 0; i < d.length; i += 4) {
        const [r, g, b, a] = farblePixel(d[i], d[i+1], d[i+2], d[i+3]);
        d[i] = r; d[i+1] = g; d[i+2] = b; d[i+3] = a;
      }
      return img;
    }

    // Canvas 2D farbling
    const origGetContext = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function(type, ...args) {
      const ctx = origGetContext.call(this, type, ...args);
      if (!ctx) return ctx;
      const canvas = this;
      if (type === '2d') {
        try {
          const origGetImageData = ctx.getImageData;
          ctx.getImageData = function(...fa) {
            return farbleImageData(origGetImageData.apply(this, fa));
          };
          const origToDataURL = canvas.toDataURL;
          canvas.toDataURL = function(...fa) {
            const url = origToDataURL.apply(canvas, fa);
            if (url.length <= 100) return url;
            const idx = url.length - 8 - (rnd() % 8);
            const code = url.charCodeAt(idx);
            const replacement = String.fromCharCode(65 + ((code + noiseMask) % 62));
            return url.slice(0, idx) + replacement + url.slice(idx + 1);
          };
        } catch {}
      }
      return ctx;
    };

    // WebGL spoofing
    const WEBGL_VENDOR = ${JSON.stringify(p.webglVendor)};
    const WEBGL_RENDERER = ${JSON.stringify(p.webglRenderer)};
    function patchWebGL(ctx) {
      if (!ctx) return ctx;
      try {
        const origGetParameter = ctx.getParameter;
        ctx.getParameter = function(pname) {
          if (pname === this.VENDOR || pname === 0x1f00) return WEBGL_VENDOR;
          if (pname === this.RENDERER || pname === 0x1f01) return WEBGL_RENDERER;
          if (pname === this.UNMASKED_VENDOR_WEBGL) return WEBGL_VENDOR;
          if (pname === this.UNMASKED_RENDERER_WEBGL) return WEBGL_RENDERER;
          return origGetParameter.call(this, pname);
        };
        const origReadPixels = ctx.readPixels;
        ctx.readPixels = function(x, y, w, h, fmt, type, pixels) {
          origReadPixels.call(this, x, y, w, h, fmt, type, pixels);
          if (pixels && pixels instanceof Uint8Array) {
            for (let i = 0; i < pixels.length; i += 4) {
              const [r, g, b, a] = farblePixel(pixels[i], pixels[i+1], pixels[i+2], pixels[i+3]);
              pixels[i] = r; pixels[i+1] = g; pixels[i+2] = b; pixels[i+3] = a;
            }
          }
        };
      } catch {}
      return ctx;
    }
    ['webgl', 'webgl2', 'experimental-webgl'].forEach(type => {
      const orig = HTMLCanvasElement.prototype.getContext;
      HTMLCanvasElement.prototype.getContext = function(requested, ...args) {
        const ctx = orig.call(this, requested, ...args);
        if (ctx && requested === type) patchWebGL(ctx);
        return ctx;
      };
    });

    // Anti-CDP / automation cleanup
    try { delete navigator.__proto__.webdriver; } catch {}
    try {
      if (window.outerWidth - window.innerWidth > 160) {
        Object.defineProperty(window, 'outerWidth', { get: () => ${p.width} });
        Object.defineProperty(window, 'outerHeight', { get: () => ${p.height} });
      }
    } catch {}
    try {
      const origGetBattery = navigator.getBattery;
      if (origGetBattery) {
        navigator.getBattery = function() {
          return Promise.resolve({ charging: true, level: 0.87, chargingTime: 0, dischargingTime: Infinity });
        };
      }
    } catch {}
  })();`;
}

function defaultMobileProfile(options = {}) {
  return normalizeProfile({
    name: 'iPhone 14 Pro',
    width: 393,
    height: 852,
    dpr: 3,
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    platform: 'iPhone',
    languages: ['ar-SA', 'ar', 'en-US', 'en'],
    timezoneId: 'Asia/Riyadh',
    colorScheme: 'dark',
    isMobile: true,
    hasTouch: true,
    vendor: 'Apple Computer, Inc.',
    browser: 'Safari',
    hardwareConcurrency: 6,
    deviceMemory: 6,
    ...options,
  });
}

function defaultDesktopProfile(options = {}) {
  return normalizeProfile({
    name: 'Windows Chrome',
    width: 1920,
    height: 1080,
    dpr: 1,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    platform: 'Win32',
    languages: ['ar-SA', 'ar', 'en-US', 'en'],
    timezoneId: 'Asia/Riyadh',
    colorScheme: 'light',
    isMobile: false,
    hasTouch: false,
    vendor: 'Google Inc.',
    browser: 'Chrome',
    hardwareConcurrency: 8,
    deviceMemory: 8,
    ...options,
  });
}

module.exports = {
  normalizeProfile,
  generateStealthScript,
  defaultMobileProfile,
  defaultDesktopProfile,
};
