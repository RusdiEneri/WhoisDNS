/**
 * Lightweight, privacy-first analytics layer.
 *
 * No third-party script is loaded and no cookies, user IDs or personal data
 * leave the browser. Events are pushed to `window.dataLayer` (GTM/GA4
 * compatible) and kept in a bounded in-memory/session buffer so that an
 * analytics collector can be attached later without touching app code.
 */

(function (global) {
  'use strict';

  const STORAGE_KEY = 'whoisdns_events';
  const MAX_BUFFERED_EVENTS = 100;

  const state = {
    enabled: true,
    buffer: []
  };

  function readBuffer() {
    try {
      const raw = global.sessionStorage.getItem(STORAGE_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
      return [];
    }
  }

  function writeBuffer(events) {
    try {
      global.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(events.slice(-MAX_BUFFERED_EVENTS)));
    } catch (_) {}
  }

  function ensureDatalayer() {
    global.dataLayer = global.dataLayer || [];
    global.__whoisdnsEvents = global.__whoisdnsEvents || [];
  }

  /**
   * Record a single interaction.
   * @param {string} name Event name, e.g. "form_submit".
   * @param {object} params Primitives describing the interaction.
   */
  function track(name, params) {
    if (!state.enabled || !name) return;

    ensureDatalayer();

    const payload = Object.assign(
      {
        event: name,
        ts: Date.now(),
        page: global.location.pathname
      },
      params || {}
    );

    global.dataLayer.push(payload);
    global.__whoisdnsEvents.push(payload);

    state.buffer.push(payload);
    if (state.buffer.length > MAX_BUFFERED_EVENTS) state.buffer.shift();
    writeBuffer(state.buffer);

    if (typeof navigator.sendBeacon === 'function' && global.WHOISDNS_ANALYTICS_ENDPOINT) {
      try {
        navigator.sendBeacon(global.WHOISDNS_ANALYTICS_ENDPOINT, JSON.stringify(payload));
      } catch (_) {}
    }

    if (global.__whoisdnsDebug) console.info('[track]', name, params);
  }

  /**
   * Attach automatic click tracking to any element carrying data-track.
   */
  function installClickTracking(root) {
    (root || document).addEventListener(
      'click',
      function (event) {
        const target = event.target.closest('[data-track]');
        if (!target) return;

        track(target.getAttribute('data-track'), {
          label: target.getAttribute('data-track-label') || (target.textContent || '').trim().slice(0, 60),
          href: target.getAttribute('href') || null
        });
      },
      { passive: true }
    );
  }

  function getBufferedEvents() {
    return state.buffer.concat(readBuffer()).slice(-MAX_BUFFERED_EVENTS);
  }

  function setEnabled(value) {
    state.enabled = Boolean(value);
  }

  global.WhoisDnsTrack = {
    track: track,
    installClickTracking: installClickTracking,
    getBufferedEvents: getBufferedEvents,
    setEnabled: setEnabled
  };
})(window);
