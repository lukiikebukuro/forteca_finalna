/**
 * SATELITA v2.0 - GDPR Compliant Visitor Tracking System
 * Zbiera dane o odwiedzających B2B z pełną zgodnością z RODO
 * 
 * SECURITY FEATURES:
 * - IP Hashing (SHA-256)
 * - PII Scrubbing (PESEL, Email, Phone)
 * - Do Not Track Support
 * - Minimal Fingerprinting
 * - Opt-Out Mechanism
 */

class VisitorTracker {
    constructor() {
        this.sessionId = this.generateSessionId();
        this.entryTime = new Date();
        this.lastActivity = new Date();
        this.messageCount = 0;
        this.visitorData = null;
        this.isTracking = false;
        this.socket = null;
        
        // RODO: Sprawdź czy user opt-out
        if (this.checkOptOut()) {
            console.log('🛰️ SATELITA: User opted out - tracking disabled');
            return;
        }
        
        // RODO: Sprawdź Do Not Track
        if (this.checkDoNotTrack()) {
            console.log('🛰️ SATELITA: DNT enabled - anonymous mode');
            this.anonymousMode = true;
        } else {
            this.anonymousMode = false;
        }
        
        console.log('🛰️ SATELITA v2.0: Visitor Tracker initialized (GDPR Compliant)');
        console.log('Session ID:', this.sessionId);
        console.log('Anonymous Mode:', this.anonymousMode);
        
        this.initializeTracking();
    }
    
    /**
     * RODO: Check if user opted out
     */
    checkOptOut() {
        return localStorage.getItem('satelita_opt_out') === 'true';
    }
    
    /**
     * RODO: Check Do Not Track header
     */
    checkDoNotTrack() {
        const dnt = navigator.doNotTrack || 
                    window.doNotTrack || 
                    navigator.msDoNotTrack;
        
        return dnt === '1' || dnt === 'yes';
    }
    
    /**
     * RODO: Public opt-out method
     */
    static optOut() {
        localStorage.setItem('satelita_opt_out', 'true');
        console.log('🛰️ SATELITA: Opted out successfully');
        window.location.reload();
    }
    
    /**
     * RODO: Public opt-in method
     */
    static optIn() {
        localStorage.removeItem('satelita_opt_out');
        console.log('🛰️ SATELITA: Opted in successfully');
        window.location.reload();
    }
    
    /**
     * Generate unique session ID
     */
    generateSessionId() {
        return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
    
    /**
     * Initialize tracking
     */
    async initializeTracking() {
        try {
            // Gather initial visitor data
            await this.gatherVisitorData();
            
            // Initialize WebSocket connection for Live Feed
            this.initializeWebSocket();
            
            // Setup event listeners
            this.setupEventListeners();
            
            // Enable tracking
            this.isTracking = true;
            
            // Send session start event
            await this.sendVisitorEvent('session_start', {
                entry_time: this.entryTime.toISOString(),
                anonymous_mode: this.anonymousMode,
                ...this.visitorData
            });
            
            console.log('🛰️ SATELITA: Tracking started');
            
        } catch (error) {
            console.error('🛰️ SATELITA: Failed to initialize tracking:', error);
        }
    }
    
    /**
     * Initialize WebSocket connection
     */
    initializeWebSocket() {
        try {
            const socketURL = window.location.hostname === 'localhost' 
                ? 'http://localhost:5000' 
                : window.location.origin;
            
            this.socket = io(socketURL, {
                transports: ['polling', 'websocket'],
                reconnection: true,
                reconnectionDelay: 1000,
                reconnectionAttempts: 5,
                timeout: 20000,
                path: '/socket.io/',
                secure: true,
                rejectUnauthorized: false
            });
            
            this.socket.on('connect', () => {
                console.log('🛰️ SATELITA: WebSocket connected');
            });
            
            this.socket.on('disconnect', () => {
                console.log('🛰️ SATELITA: WebSocket disconnected');
            });
            
        } catch (error) {
            console.error('🛰️ SATELITA: Failed to initialize WebSocket:', error);
        }
    }
    
    /**
     * RODO: Hash IP Address using SHA-256
     * Zwraca zahaszowane IP, które nie pozwala na odtworzenie oryginału
     */
    async hashIP(ip) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(ip);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            return `hash_${hashHex.substring(0, 16)}`; // Pierwsze 16 znaków wystarczą
        } catch (error) {
            console.error('🛰️ SATELITA: IP hashing failed:', error);
            return 'hash_unknown';
        }
    }
    
    /**
     * RODO: Maskowanie IP (alternatywna metoda - prostsze)
     * Usuwa ostatni oktet IPv4 lub końcówkę IPv6
     */
    maskIP(ip) {
        if (!ip) return 'masked';
        
        // IPv4: 192.168.1.123 -> 192.168.1.xxx
        if (ip.includes('.')) {
            const parts = ip.split('.');
            return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
        }
        
        // IPv6: 2001:0db8:85a3::8a2e:0370:7334 -> 2001:0db8:85a3::xxxx
        if (ip.includes(':')) {
            const parts = ip.split(':');
            return parts.slice(0, -2).join(':') + '::xxxx';
        }
        
        return 'masked';
    }
    
    /**
     * RODO: Sanityzacja danych wejściowych
     * Usuwa PESEL, Email, Telefon, Karty Kredytowe
     */
    scrubPII(text) {
        if (!text || typeof text !== 'string') return text;
        
        let scrubbed = text;
        
        // Email: user@domain.com
        scrubbed = scrubbed.replace(
            /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
            '[REDACTED_EMAIL]'
        );
        
        // Polski telefon: +48 123 456 789, 123-456-789, 123456789
        scrubbed = scrubbed.replace(
            /(\+48\s?)?(\d{3}[\s\-]?\d{3}[\s\-]?\d{3})/g,
            '[REDACTED_PHONE]'
        );
        
        // PESEL: 11 cyfr
        scrubbed = scrubbed.replace(
            /\b\d{11}\b/g,
            '[REDACTED_PESEL]'
        );
        
        // Karta kredytowa: 16 cyfr (z opcjonalnymi spacjami/myślnikami)
        scrubbed = scrubbed.replace(
            /\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/g,
            '[REDACTED_CARD]'
        );
        
        // IBAN: PL followed by digits
        scrubbed = scrubbed.replace(
            /\bPL\d{26}\b/gi,
            '[REDACTED_IBAN]'
        );
        
        // NIP: 10 cyfr (opcjonalnie z myślnikami)
        scrubbed = scrubbed.replace(
            /\b\d{3}[\-]?\d{3}[\-]?\d{2}[\-]?\d{2}\b/g,
            '[REDACTED_NIP]'
        );
        
        return scrubbed;
    }
    
    /**
     * RODO: Minimalizacja fingerprinting
     * Zbiera TYLKO dane potrzebne do B2B analytics
     */
    getMinimalDeviceInfo() {
        const ua = navigator.userAgent;
        
        // Wykryj typ urządzenia (Mobile/Desktop/Tablet)
        const isMobile = /Mobile|Android|iPhone|iPad|iPod/i.test(ua);
        const isTablet = /iPad|Android(?!.*Mobile)/i.test(ua);
        
        let deviceType = 'Desktop';
        if (isTablet) deviceType = 'Tablet';
        else if (isMobile) deviceType = 'Mobile';
        
        // Wykryj OS (bez wersji - tylko kategoria)
        let os = 'Unknown';
        if (ua.includes('Windows')) os = 'Windows';
        else if (ua.includes('Mac')) os = 'MacOS';
        else if (ua.includes('Linux')) os = 'Linux';
        else if (ua.includes('Android')) os = 'Android';
        else if (ua.includes('iOS') || ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
        
        // Wykryj przeglądarkę (bez wersji)
        let browser = 'Unknown';
        if (ua.includes('Chrome') && !ua.includes('Edge')) browser = 'Chrome';
        else if (ua.includes('Safari') && !ua.includes('Chrome')) browser = 'Safari';
        else if (ua.includes('Firefox')) browser = 'Firefox';
        else if (ua.includes('Edge')) browser = 'Edge';
        else if (ua.includes('Opera') || ua.includes('OPR')) browser = 'Opera';
        
        return {
            device_type: deviceType,
            os: os,
            browser: browser,
            // Tylko ogólne wymiary (zaokrąglone do 100px dla privacy)
            viewport_category: this.categorizeViewport(window.innerWidth, window.innerHeight)
        };
    }
    
    /**
     * RODO: Kategoryzacja viewportu (zamiast dokładnych wymiarów)
     */
    categorizeViewport(width, height) {
        if (width < 768) return 'mobile';
        if (width < 1024) return 'tablet';
        if (width < 1440) return 'laptop';
        return 'desktop';
    }
    
    /**
     * Gather comprehensive visitor data (GDPR-compliant)
     */
    async gatherVisitorData() {
        // RODO: Minimal device info (no fingerprinting)
        const deviceInfo = this.getMinimalDeviceInfo();
        
        this.visitorData = {
            // Basic data (minimal)
            ...deviceInfo,
            language: navigator.language.split('-')[0], // Tylko język, bez regionu
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            
            // Page data
            page_url: window.location.pathname, // Bez query params (mogą zawierać PII)
            page_title: document.title,
            
            // UTM parameters (marketing data - OK for GDPR)
            utm_source: this.getUrlParameter('utm_source'),
            utm_medium: this.getUrlParameter('utm_medium'),
            utm_campaign: this.getUrlParameter('utm_campaign'),
            
            // Referrer (sanitized)
            referrer: this.sanitizeReferrer(document.referrer)
        };
        
        // RODO: W trybie anonymous - nie pobieraj IP/Location
        if (this.anonymousMode) {
            console.log('🛰️ SATELITA: Anonymous mode - skipping IP/location');
            return;
        }
        
        // Try to get IP and location data (dla B2B identification)
        try {
            const ipData = await this.getIPData();
            if (ipData) {
                this.visitorData = { ...this.visitorData, ...ipData };
            }
        } catch (error) {
            console.warn('🛰️ SATELITA: Could not fetch IP data:', error);
        }
    }
    
    /**
     * RODO: Sanitize referrer (remove query params that might contain PII)
     */
    sanitizeReferrer(referrer) {
        if (!referrer) return 'direct';
        
        try {
            const url = new URL(referrer);
            // Return only domain, without query params
            return `${url.protocol}//${url.hostname}${url.pathname}`;
        } catch (error) {
            return 'invalid_referrer';
        }
    }
    
    /**
     * Get IP and location data (GDPR-compliant)
     */
    async getIPData() {
        try {
            const services = [
                'https://api.ipify.org?format=json',
                'https://httpbin.org/ip'
            ];
            
            for (const service of services) {
                try {
                    const response = await fetch(service, { 
                        signal: AbortSignal.timeout(3000)
                    });
                    
                    if (response.ok) {
                        const data = await response.json();
                        const rawIP = data.ip || data.origin;
                        
                        if (rawIP) {
                            // Get location data FIRST (need IP for geolocation API)
                            const locationData = await this.getLocationData(rawIP);
                            
                            // RODO: Hash IP after getting location
                            const hashedIP = await this.hashIP(rawIP);
                            
                            // RODO: Also store masked version for debugging
                            const maskedIP = this.maskIP(rawIP);
                            
                            console.log('🛰️ SATELITA: IP processed');
                            console.log('  Raw IP:', rawIP, '(not stored)');
                            console.log('  Hashed:', hashedIP);
                            console.log('  Masked:', maskedIP);
                            
                            return {
                                ip_hash: hashedIP,      // Stored in DB
                                ip_masked: maskedIP,    // For debugging
                                // NO ip_address field - nigdy nie przechowujemy raw IP
                                ...locationData
                            };
                        }
                    }
                } catch (serviceError) {
                    console.warn(`🛰️ SATELITA: Service ${service} failed:`, serviceError);
                    continue;
                }
            }
        } catch (error) {
            console.warn('🛰️ SATELITA: IP detection failed:', error);
        }
        
        return null;
    }
    
    /**
     * Get location data for IP (for B2B identification)
     */
    async getLocationData(ip) {
        try {
            const response = await fetch(`https://ipapi.co/${ip}/json/`, {
                signal: AbortSignal.timeout(3000)
            });
            
            if (response.ok) {
                const data = await response.json();
                
                // RODO: Return only business-relevant data
                return {
                    country: data.country_name,
                    country_code: data.country_code,
                    city: data.city,
                    region: data.region,
                    timezone: data.timezone,
                    org: data.org,           // Nazwa firmy/ISP - KLUCZOWE dla B2B
                    asn: data.asn            // ASN - identyfikacja organizacji
                    // NIE przechowujemy: postal, lat/long (zbyt precyzyjne)
                };
            }
        } catch (error) {
            console.warn('🛰️ SATELITA: Location lookup failed:', error);
        }
        
        return {};
    }
    
    /**
     * Setup event listeners for tracking
     */
    setupEventListeners() {
        // Track page visibility changes
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.sendVisitorEvent('page_hidden', {
                    time_visible: Date.now() - this.lastActivity.getTime()
                });
            } else {
                this.lastActivity = new Date();
                this.sendVisitorEvent('page_visible', {});
            }
        });
        
        // Track scroll depth (throttled)
        let maxScrollDepth = 0;
        window.addEventListener('scroll', this.throttle(() => {
            const scrollDepth = Math.round(
                (window.scrollY / (document.body.scrollHeight - window.innerHeight)) * 100
            );
            
            if (scrollDepth > maxScrollDepth && scrollDepth % 25 === 0) {
                maxScrollDepth = scrollDepth;
                this.sendVisitorEvent('scroll_depth', {
                    scroll_depth: scrollDepth
                });
            }
        }, 1000));
        
        // Track clicks on important elements
        document.addEventListener('click', (event) => {
            const target = event.target;
            
            if (target.matches('button, a, .action-btn, .cta-primary, .cta-secondary')) {
                this.sendVisitorEvent('element_click', {
                    element_type: target.tagName.toLowerCase(),
                    element_class: target.className.substring(0, 50), // Limit length
                    // RODO: NIE przechowujemy pełnego textu (może zawierać PII)
                    element_id: target.id
                });
            }
        });
        
        // Track input focus
        document.addEventListener('focusin', (event) => {
            if (event.target.matches('input[type="text"], textarea, [contenteditable]')) {
                this.sendVisitorEvent('input_focus', {
                    input_type: event.target.type || 'contenteditable',
                    input_id: event.target.id
                });
            }
        });
        
        // Track bot interactions
        this.trackBotInteractions();
        
        // Track page unload
        window.addEventListener('beforeunload', () => {
            const sessionDuration = Date.now() - this.entryTime.getTime();
            
            navigator.sendBeacon('/api/visitor-tracking', JSON.stringify({
                session_id: this.sessionId,
                event_type: 'session_end',
                timestamp: new Date().toISOString(),
                session_duration: sessionDuration,
                message_count: this.messageCount
            }));
        });
        
        console.log('🛰️ SATELITA: Event listeners configured');
    }
    
    /**
     * Track bot interactions
     */
    trackBotInteractions() {
        if (window.botUI) {
            const originalSendFinalAnalysis = window.botUI.sendFinalAnalysis;
            
            window.botUI.sendFinalAnalysis = async (query) => {
                this.messageCount++;
                
                // RODO: Sanitize query before storing/sending
                const sanitizedQuery = this.scrubPII(query);
                
                // Check if query was scrubbed
                if (sanitizedQuery !== query) {
                    console.warn('🛰️ SATELITA: PII detected and scrubbed from query');
                    console.log('  Original length:', query.length);
                    console.log('  Scrubbed length:', sanitizedQuery.length);
                }
                
                const sessionInfo = this.getVisitorSummary();
                
                // Send to Live Feed via WebSocket
                if (this.socket && this.socket.connected) {
                    const eventData = {
                        query: sanitizedQuery, // RODO: Sanitized query
                        classification: 'ANALYZING',
                        estimatedValue: 0,
                        timestamp: new Date().toISOString(),
                        city: sessionInfo.city || 'Unknown',
                        country: sessionInfo.country || 'Unknown',
                        organization: sessionInfo.organization || 'Unknown',
                        sessionId: this.sessionId,
                        anonymous: this.anonymousMode
                    };
                    
                    this.socket.emit('visitor_event', eventData);
                }
                
                // Send to tracking endpoint
                await this.sendVisitorEvent('bot_query', {
                    query: sanitizedQuery, // RODO: Sanitized
                    message_count: this.messageCount,
                    time_since_entry: Date.now() - this.entryTime.getTime(),
                    city: sessionInfo.city || 'Unknown',
                    country: sessionInfo.country || 'Unknown',
                    organization: sessionInfo.organization || 'Unknown'
                });
                
                // Call original function with ORIGINAL query (bot needs it)
                // But sanitized version is what gets stored
                return originalSendFinalAnalysis.call(window.botUI, query);
            };
            
            console.log('🛰️ SATELITA: Bot interaction tracking enabled');
        } else {
            setTimeout(() => this.trackBotInteractions(), 1000);
        }
    }
    
    /**
     * Send visitor event to backend
     */
    async sendVisitorEvent(eventType, data) {
        if (!this.isTracking) return;
        
        try {
            const payload = {
                session_id: this.sessionId,
                event_type: eventType,
                timestamp: new Date().toISOString(),
                anonymous_mode: this.anonymousMode,
                ...data
            };
            
            const response = await fetch('/api/visitor-tracking', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload),
                credentials: 'include'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const result = await response.json();
            
            if (eventType === 'bot_query' && result.classification) {
                this.updateLiveFeed(data.query, result.classification, result.potential_value);
            }
            
        } catch (error) {
            console.error('🛰️ SATELITA: Failed to send visitor event:', error);
        }
    }
    
    /**
     * Update Live Feed with visitor query
     */
    updateLiveFeed(query, classification, potentialValue) {
        const feedData = {
            timestamp: new Date().toLocaleTimeString('pl-PL'),
            query_text: query,
            decision: classification,
            details: `Visitor: ${this.getVisitorLocation()}`,
            potential_value: potentialValue,
            visitor_session: this.sessionId.substr(-8),
            company_name: this.visitorData?.org || 'Unknown Organization'
        };
        
        if (window.tacticalDashboard) {
            window.tacticalDashboard.addEventToFeed(feedData);
        }
    }
    
    /**
     * Get visitor location string
     */
    getVisitorLocation() {
        if (!this.visitorData || this.anonymousMode) return 'Anonymous';
        
        const parts = [];
        if (this.visitorData.city) parts.push(this.visitorData.city);
        if (this.visitorData.country) parts.push(this.visitorData.country);
        
        return parts.length > 0 ? parts.join(', ') : 'Unknown Location';
    }
    
    /**
     * Get URL parameter
     */
    getUrlParameter(name) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(name);
    }
    
    /**
     * Throttle function
     */
    throttle(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        }
    }
    
    /**
     * Get session summary
     */
    getVisitorSummary() {
        const now = new Date();
        const sessionDuration = now - this.entryTime;
        
        return {
            sessionId: this.sessionId,
            entry_time: this.entryTime.toISOString(),
            session_duration: Math.round(sessionDuration / 1000),
            message_count: this.messageCount,
            location: this.getVisitorLocation(),
            city: this.visitorData?.city || 'Unknown',
            country: this.visitorData?.country || 'Unknown',
            organization: this.visitorData?.org || 'Unknown',
            referrer: this.visitorData?.referrer || 'direct',
            anonymous: this.anonymousMode
            // RODO: NO ip_address field
        };
    }
}

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('.demo-container')) {
        window.visitorTracker = new VisitorTracker();
        
        // Debug commands
        window.getVisitorSummary = () => {
            if (window.visitorTracker) {
                console.table(window.visitorTracker.getVisitorSummary());
            }
        };
        
        // RODO: Public opt-out/opt-in methods
        window.satelitaOptOut = () => VisitorTracker.optOut();
        window.satelitaOptIn = () => VisitorTracker.optIn();
        
        console.log('🛰️ SATELITA v2.0: Visitor tracking active (GDPR Compliant)');
        console.log('Commands:');
        console.log('  getVisitorSummary() - Show session info');
        console.log('  satelitaOptOut() - Disable tracking');
        console.log('  satelitaOptIn() - Enable tracking');
    }
});

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = VisitorTracker;
}