/**
 * fingerprint-auditor.js
 * Evaluates browser fingerprint entropy vectors (Canvas, WebGL, AudioContext).
 */

export function auditFingerprintEntropy(metrics = {}) {
  const findings = [];
  const {
    hasCanvasNoise = false,
    hasAudioNoise = false,
    webglVendor = '',
    webglRenderer = '',
    fontsCount = 0
  } = metrics;

  // Check 1: Hardware WebGL Unmasked Renderer
  if (webglRenderer && !webglRenderer.includes('Generic') && !webglRenderer.includes('Mesa')) {
    findings.push({
      id: 'FINGERPRINT_WEBGL_HARDWARE_EXPOSURE',
      category: 'fingerprint',
      severity: 'MEDIUM',
      title: 'Unmasked Hardware GPU & Graphics Renderer',
      description: `Browser exposes raw GPU hardware vendor and model ("${webglRenderer}"). Trackers combine GPU performance and driver quirks to uniquely fingerprint your device.`,
      leakedData: `${webglVendor} - ${webglRenderer}`,
      remediation: 'Enable WebGL vendor masking or use privacy browsers (like Brave or Mullvad Browser) that report standard generic GPUs.'
    });
  }

  // Check 2: Deterministic Canvas 2D Hash
  if (!hasCanvasNoise) {
    findings.push({
      id: 'FINGERPRINT_CANVAS_DETERMINISTIC',
      category: 'fingerprint',
      severity: 'LOW',
      title: 'Deterministic Canvas 2D Fingerprint Vector',
      description: 'HTML5 Canvas rendering produces identical pixel hashes across visits without cryptographic sub-pixel jitter or anti-fingerprinting noise.',
      remediation: 'Enable Canvas randomization in browser privacy settings (or use privacy-focused browsers that inject subtle noise into 2D rendering).'
    });
  }

  // Check 3: Font Enumeration Entropy
  if (fontsCount > 80) {
    findings.push({
      id: 'FINGERPRINT_HIGH_FONT_ENTROPY',
      category: 'fingerprint',
      severity: 'LOW',
      title: `High System Font Count (${fontsCount} fonts installed)`,
      description: 'Large collections of custom installed operating system fonts provide high information entropy (typically > 12 bits), making your browser profile distinguishable.',
      leakedData: `${fontsCount} fonts detected`,
      remediation: 'Restrict local font enumeration using browser anti-tracking protections.'
    });
  }

  return {
    findings,
    fingerprintDetails: {
      hasCanvasNoise,
      hasAudioNoise,
      webglRenderer: webglRenderer || 'Generic GPU',
      fontsCount
    }
  };
}
