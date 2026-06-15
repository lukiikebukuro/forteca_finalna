/**
 * LDI Site Tracker — P5 Analytics
 * Fires on /ldi, /ldi-readme, /ldi-tests, /anima
 * Tracks: page visits + copy events. No raw IP/PII stored.
 */
(function () {
    'use strict';

    var visitId = 'sv_' + Date.now() + '_' + Math.random().toString(36).slice(2, 9);
    var pagePath = window.location.pathname;
    var startTime = Date.now();
    var geoData = { organization: null, city: null, country: null };

    // Expose for ldi_readme.html chat to pass with bot queries
    window.__ldi_visit_id = visitId;
    window.__ldi_geo = geoData;

    function sendTrack() {
        fetch('/api/site-track', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                visit_id: visitId,
                page_path: pagePath,
                referrer: document.referrer || 'direct',
                organization: geoData.organization,
                city: geoData.city,
                country: geoData.country
            })
        }).catch(function () {});
    }

    // Geo lookup via ipapi.co (same as SATELITA)
    fetch('https://ipapi.co/json/')
        .then(function (r) { return r.json(); })
        .then(function (d) {
            geoData.organization = d.org || null;
            geoData.city = d.city || null;
            geoData.country = d.country_name || null;
        })
        .catch(function () {})
        .finally(function () {
            sendTrack();
        });

    // On exit: report duration
    window.addEventListener('beforeunload', function () {
        var duration = Math.round((Date.now() - startTime) / 1000);
        var payload = JSON.stringify({ visit_id: visitId, duration: duration });
        if (navigator.sendBeacon) {
            navigator.sendBeacon('/api/site-exit', payload);
        } else {
            fetch('/api/site-exit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: payload,
                keepalive: true
            }).catch(function () {});
        }
    });

    // Copy tracking
    document.addEventListener('copy', function () {
        var selected = window.getSelection ? window.getSelection().toString() : '';
        if (!selected || selected.trim().length < 3) return;

        fetch('/api/site-track', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                event_type: 'copy',
                visit_id: visitId,
                page_path: pagePath,
                copy_text: selected.slice(0, 50000),
                organization: geoData.organization,
                city: geoData.city
            })
        }).catch(function () {});
    });

})();
