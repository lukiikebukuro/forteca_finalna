/**
 * SATELITA - Visitor Tracking System
 * Zbiera dane o odwiedzających i integruje z Live Feed
 */

class VisitorTracker {
    constructor() {
        this.sessionId = this.generateSessionId();
        this.entryTime = new Date();
        this.lastActivity = new Date();
        this.messageCount = 0;
        this.visitorData = null;
        this.isTracking = false;
        this.socket = null; // WebSocket do Live Feed
        
        console.log('🛰️ SATELITA: Visitor Tracker initialized');
        console.log('Session ID:', this.sessionId);
        
        this.initializeTracking();
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
            
            // WAŻNE: Włącz tracking PRZED wysłaniem session_start!
            this.isTracking = true;
            
            // Send session start event
            await this.sendVisitorEvent('session_start', {
                entry_time: this.entryTime.toISOString(),
                ...this.visitorData
            });
            
            console.log('🛰️ SATELITA: Tracking started');
            
        } catch (error) {
            console.error('🛰️ SATELITA: Failed to initialize tracking:', error);
        }
    }
    
    /**
     * Initialize WebSocket connection for Live Feed communication
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
                console.log('🛰️ SATELITA: WebSocket connected to Live Feed');
            });
            
            this.socket.on('disconnect', () => {
                console.log('🛰️ SATELITA: WebSocket disconnected from Live Feed');
            });
            
        } catch (error) {
            console.error('🛰️ SATELITA: Failed to initialize WebSocket:', error);
        }
    }
    
    /**
     * Gather comprehensive visitor data
     */
    async gatherVisitorData() {
        this.visitorData = {
            // Basic data
            user_agent: navigator.userAgent,
            referrer: document.referrer || 'direct',
            viewport: `${window.innerWidth}x${window.innerHeight}`,
            screen: `${screen.width}x${screen.height}`,
            language: navigator.language,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            
            // Enhanced data
            platform: navigator.platform,
            cookie_enabled: navigator.cookieEnabled,
            online: navigator.onLine,
            
            // Page data
            page_url: window.location.href,
            page_title: document.title,
            
            // UTM parameters
            utm_source: this.getUrlParameter('utm_source'),
            utm_medium: this.getUrlParameter('utm_medium'),
            utm_campaign: this.getUrlParameter('utm_campaign'),
            utm_content: this.getUrlParameter('utm_content'),
            utm_term: this.getUrlParameter('utm_term')
        };
        
        // Try to get IP and location data
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
     * Get IP and location data
     */
    async getIPData() {
        try {
            // Try multiple IP services for reliability
            const services = [
                'https://api.ipify.org?format=json',
                'https://httpbin.org/ip',
                'https://api.myip.com'
            ];
            
            for (const service of services) {
                try {
                    const response = await fetch(service, { 
                        timeout: 3000,
                        signal: AbortSignal.timeout(3000)
                    });
                    
                    if (response.ok) {
                        const data = await response.json();
                        const ip = data.ip || data.origin;
                        
                        if (ip) {
                            // Get location data for this IP
                            const locationData = await this.getLocationData(ip);
                            return {
                                ip_address: ip,
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
     * Get location data for IP
     */
    async getLocationData(ip) {
        try {
            // Use free IP geolocation service
            const response = await fetch(`https://ipapi.co/${ip}/json/`, {
                timeout: 3000,
                signal: AbortSignal.timeout(3000)
            });
            
            if (response.ok) {
                const data = await response.json();
                return {
                    country: data.country_name,
                    country_code: data.country_code,
                    city: data.city,
                    region: data.region,
                    postal: data.postal,
                    latitude: data.latitude,
                    longitude: data.longitude,
                    timezone: data.timezone,
                    org: data.org,
                    isp: data.org
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
        
        // Track scroll depth
        let maxScrollDepth = 0;
        window.addEventListener('scroll', this.throttle(() => {
            const scrollDepth = Math.round(
                (window.scrollY / (document.body.scrollHeight - window.innerHeight)) * 100
            );
            
            if (scrollDepth > maxScrollDepth) {
                maxScrollDepth = scrollDepth;
                this.sendVisitorEvent('scroll_depth', {
                    scroll_depth: scrollDepth,
                    scroll_y: window.scrollY
                });
            }
        }, 1000));
        
        // Track click events (only on important elements)
        document.addEventListener('click', (event) => {
            const target = event.target;
            
            // Track clicks on buttons, links, and interactive elements
            if (target.matches('button, a, .action-btn, .cta-primary, .cta-secondary')) {
                this.sendVisitorEvent('element_click', {
                    element_type: target.tagName.toLowerCase(),
                    element_class: target.className,
                    element_text: target.textContent?.substring(0, 100),
                    element_id: target.id
                });
            }
        });
        
        // Track focus on input fields (bot interaction)
        document.addEventListener('focusin', (event) => {
            if (event.target.matches('input[type="text"], textarea, [contenteditable]')) {
                this.sendVisitorEvent('input_focus', {
                    input_type: event.target.type || 'contenteditable',
                    input_id: event.target.id,
                    input_placeholder: event.target.placeholder
                });
            }
        });
        
        // Track bot messages (integrate with existing bot)
        this.trackBotInteractions();
        
        // Track page unload
        window.addEventListener('beforeunload', () => {
            const sessionDuration = Date.now() - this.entryTime.getTime();
            
            // Use sendBeacon for reliable delivery
            navigator.sendBeacon('/api/visitor-tracking', JSON.stringify({
                session_id: this.sessionId,
                event_type: 'session_end',
                timestamp: new Date().toISOString(),
                session_duration: sessionDuration,
                message_count: this.messageCount,
                max_scroll_depth: maxScrollDepth
            }));
        });
        
        console.log('🛰️ SATELITA: Event listeners configured');
    }
    
    /**
     * Track bot interactions
     */
    trackBotInteractions() {
        // Hook into existing bot's message sending
        if (window.botUI) {
            // Override sendFinalAnalysis to capture query classifications
            const originalSendFinalAnalysis = window.botUI.sendFinalAnalysis;
            
            window.botUI.sendFinalAnalysis = async (query) => {
                this.messageCount++;
                
                // ==== ZADANIE 2.1: WZBOGACENIE DANYCH WYWIADOWCZYCH ====
                // Pobierz szczegółowe dane o sesji
                const sessionInfo = this.getVisitorSummary();
                
                // Wyślij przez WebSocket do Live Feed z pełnymi danymi
                if (this.socket && this.socket.connected) {
                    const eventData = {
                        query: query,
                        classification: 'ANALYZING',
                        estimatedValue: 0,
                        timestamp: new Date().toISOString(),
                        city: sessionInfo.city || 'Unknown',
                        country: sessionInfo.country || 'Unknown',
                        organization: sessionInfo.organization || 'Unknown',
                        sessionId: this.sessionId
                    };
                    
                    console.log('🛰️ SATELITA: Emitting visitor_event with data:', eventData);
                    this.socket.emit('visitor_event', eventData);
                }
                
                // WŁĄCZONE PONOWNIE - potrzebne dla HOT LEADS klasyfikacji
                await this.sendVisitorEvent('bot_query', {
                    query: query,
                    message_count: this.messageCount,
                    time_since_entry: Date.now() - this.entryTime.getTime(),
                    city: sessionInfo.city || 'Unknown',
                    country: sessionInfo.country || 'Unknown',
                    organization: sessionInfo.organization || 'Unknown'
                });
                
                // Call original function
                return originalSendFinalAnalysis.call(window.botUI, query);
            };
            
            console.log('🛰️ SATELITA: Bot interaction tracking enabled');
        } else {
            // Retry later if bot not yet loaded
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
                ...data
            };
            
            // Send to our visitor tracking endpoint
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
            
            // If this is a classification event, show in Live Feed
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
        // Create live feed entry showing visitor activity
        const feedData = {
            timestamp: new Date().toLocaleTimeString('pl-PL'),
            query_text: query,
            decision: classification,
            details: `Visitor: ${this.getVisitorLocation()}`,
            potential_value: potentialValue,
            visitor_session: this.sessionId.substr(-8), // Last 8 chars for privacy
            company_name: this.visitorData?.org || 'Unknown Organization'
        };
        
        // Send to dashboard if available
        if (window.tacticalDashboard) {
            window.tacticalDashboard.addEventToFeed(feedData);
        }
        
        console.log('🛰️ SATELITA: Live Feed updated', feedData);
    }
    
    /**
     * Get visitor location string
     */
    getVisitorLocation() {
        if (!this.visitorData) return 'Unknown Location';
        
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
     * Throttle function to limit event frequency
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
     * Get session summary for debugging AND Live Feed integration
     * ZADANIE 2.1: Funkcja zwracająca pełne dane o sesji
     */
    getVisitorSummary() {
        const now = new Date();
        const sessionDuration = now - this.entryTime;
        
        return {
            sessionId: this.sessionId,
            entry_time: this.entryTime.toISOString(),
            session_duration: Math.round(sessionDuration / 1000), // seconds
            message_count: this.messageCount,
            location: this.getVisitorLocation(),
            city: this.visitorData?.city || 'Unknown',
            country: this.visitorData?.country || 'Unknown',
            organization: this.visitorData?.org || 'Unknown',
            referrer: this.visitorData?.referrer || 'direct',
            ip_address: this.visitorData?.ip_address || 'unknown'
        };
    }
}

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Only initialize on demo page (not on other pages)
    if (document.querySelector('.demo-container')) {
        window.visitorTracker = new VisitorTracker();
        
        // Add debug console command
        window.getVisitorSummary = () => {
            if (window.visitorTracker) {
                console.table(window.visitorTracker.getVisitorSummary());
            }
        };
        
        console.log('🛰️ SATELITA: Visitor tracking active');
        console.log('Debug: Use getVisitorSummary() in console for session info');
    }
});

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = VisitorTracker;
}