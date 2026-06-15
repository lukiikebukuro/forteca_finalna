/**
 * LDI Site Tracker — P5 Analytics
 * Fires on /ldi, /ldi-readme, /ldi-tests
 * No cookie consent needed: no PII stored, IP is hashed server-side.
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
})();
