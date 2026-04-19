/**
 * ADEPT AI Dashboard - Real-time JavaScript Controller
 * NAPRAWIONE: Liczniki działają z polskimi statusami z backendu
 * v5.2 - FIX dla ELEKTRO + MOTO
 */

class TacticalDashboard {
    constructor() {
        this.socket = null;
        this.charts = {};
        // Map to dedupe incoming events: key -> timestamp_ms
        this.recentEventHashes = new Map();
        // How long to remember event hashes (ms)
        this.eventDedupWindow = 7000;
        this.metrics = {
            foundProducts: { count: 0, amount: 0 },
            lostOpportunities: { count: 0, amount: 0 },
            filteredOut: { count: 0, amount: 0 }
        };
        this.feedPaused = false;
        this.eventQueue = [];
        this.processingQueue = false;
        
        this.animationConfig = {
            duration: 1000,
            easing: 'easeOutCubic',
            stagger: 100
        };
        
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.initialize());
        } else {
            this.initialize();
        }

        // Periodically clean old hashes
        setInterval(() => {
            const now = Date.now();
            for (const [k, t] of Array.from(this.recentEventHashes.entries())) {
                if (now - t > this.eventDedupWindow) this.recentEventHashes.delete(k);
            }
        }, 5000);
    }
    
    async initialize() {
        console.log('🎯 Initializing ADEPT AI Dashboard...');
        
        try {
            this.setupEventListeners();
            await this.initializeWebSocket();
            // Upewnij się, że panel liczników istnieje (fallback jeśli HTML nie ma elementów)
            this.ensureCounterPanelExists();
            // Po połączeniu poproś od razu o aktualne statystyki
            if (this.socket && this.socket.connected) {
                this.requestCurrentStats();
            }
            await this.loadInitialData();
            this.initializeCharts();
            this.initializeMobileSupport();
            this.initializeResizer();
            this.hideLoadingOverlay();
            this.updateConnectionStatus('connected');
            this.startPeriodicUpdates();
            
            console.log('✅ Dashboard initialized successfully');
            this.showToast('Dashboard inicjalizowany pomyślnie', 'success');
            
        } catch (error) {
            console.error('❌ Dashboard initialization failed:', error);
            this.showToast('Błąd inicjalizacji dashboardu', 'error');
            this.hideLoadingOverlay();
        }
    }

    ensureCounterPanelExists() {
        // Sprawdź czy przynajmniej jeden z oczekiwanych elementów istnieje
        const ids = ['foundProductsCount','lostOpportunitiesCount','lostOpportunitiesAmount','filteredOutCount','successRate','savedRevenue'];
        const missing = ids.filter(id => !document.getElementById(id));
        if (missing.length === 0) return; // wszystko ok

        // Jeśli dashboard ma kolumnę, wstaw tam panel, inaczej body
        const container = document.getElementById('dashboardColumn') || document.getElementById('botColumn') || document.body;

        // Stwórz prosty, nieinwazyjny panel w górnym prawym rogu kontenera
        const panel = document.createElement('div');
        panel.id = 'tcd-fallback-counters';
        panel.style.cssText = 'position:relative; max-width:320px; margin:8px; padding:8px; background:rgba(255,255,255,0.95); border:1px solid #e5e7eb; border-radius:8px; box-shadow:0 6px 18px rgba(0,0,0,0.06); font-family:Arial, sans-serif; font-size:13px; color:#111;';

        panel.innerHTML = `
            <div style="display:flex;flex-direction:column;gap:6px">
                <div style="display:flex;justify-content:space-between"><strong>ZNALEZIONE PRODUKTY</strong><span id="foundProductsCount">0</span></div>
                <div style="display:flex;justify-content:space-between"><strong>UTRACONE OKAZJE</strong><span id="lostOpportunitiesCount">0</span></div>
                <div style="display:flex;justify-content:space-between"><strong>Szac. wartość</strong><span id="lostOpportunitiesAmount">0 zł</span></div>
                <div style="display:flex;justify-content:space-between"><strong>ODFILTROWANE</strong><span id="filteredOutCount">0</span></div>
                <div style="display:flex;justify-content:space-between;margin-top:6px;color:#6b7280"><span>Udział utraty</span><span id="successRate">0%</span></div>
                <div style="display:flex;justify-content:space-between;color:#6b7280"><span>Oszczędzone</span><span id="savedRevenue">0 zł</span></div>
            </div>
        `;

        // Dodaj panel na początku kontenera, aby był widoczny
        if (container === document.body) {
            // aby nie przesłaniać UI dodaj do body na końcu i lekko wypozycjonuj
            panel.style.position = 'fixed';
            panel.style.top = '12px';
            panel.style.right = '12px';
            panel.style.zIndex = 9999;
            document.body.appendChild(panel);
        } else {
            container.insertBefore(panel, container.firstChild);
        }

        console.log('ℹ️ Fallback counter panel created for missing elements:', missing);
    }
    
    setupEventListeners() {
        const pauseFeedBtn = document.getElementById('pauseFeed');
        const clearFeedBtn = document.getElementById('clearFeed');
        const resetDemoBtn = document.getElementById('resetDemo');
        const exportDataBtn = document.getElementById('exportData');
        
        this.setupInputFocusListeners();
        
        if (pauseFeedBtn) {
            pauseFeedBtn.addEventListener('click', () => this.toggleFeedPause());
        }
        
        if (clearFeedBtn) {
            clearFeedBtn.addEventListener('click', () => this.clearFeed());
        }
        
        if (resetDemoBtn) {
            resetDemoBtn.addEventListener('click', () => this.resetDemo());
        }
        
        if (exportDataBtn) {
            exportDataBtn.addEventListener('click', () => this.exportData());
        }
        
        window.addEventListener('beforeunload', () => {
            if (this.socket) {
                this.socket.disconnect();
            }
        });
        
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                console.log('📱 Dashboard went to background');
            } else {
                console.log('📱 Dashboard returned to foreground');
                this.requestCurrentStats();
            }
        });
    }
    
    setupInputFocusListeners() {
        const inputSelectors = '.bot-column input[type="text"], .bot-column input[type="search"], .bot-column textarea, .bot-column [contenteditable="true"]';
        
        document.addEventListener('focusin', (event) => {
            if (event.target.matches(inputSelectors)) {
                this.pauseSimulatorForTyping();
            }
        });
        
        document.addEventListener('focusout', (event) => {
            if (event.target.matches(inputSelectors)) {
                setTimeout(() => {
                    const activeElement = document.activeElement;
                    if (!activeElement || !activeElement.matches(inputSelectors)) {
                        this.resumeSimulatorAfterTyping();
                    }
                }, 100);
            }
        });
        
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            const inputs = node.querySelectorAll?.(inputSelectors);
                            if (inputs?.length > 0) {
                                console.log('🎯 Detected new input fields for auto-pause');
                            }
                        }
                    });
                }
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }
    
    pauseSimulatorForTyping() {
        if (this.socket && this.socket.connected) {
            console.log('⏸️ Auto-pausing - element:', document.activeElement);
            this.socket.emit('pause_simulator');
        }
    }
    
    resumeSimulatorAfterTyping() {
        if (this.socket && this.socket.connected) {
            console.log('▶️ Auto-resuming simulator - user stopped typing');
            this.socket.emit('resume_simulator');
        }
    }
    
    async initializeWebSocket() {
        return new Promise((resolve, reject) => {
            try {
                // ZAMKNIJ STARY SOCKET jeśli istnieje
                if (this.socket) {
                    console.log('🔌 Closing existing socket before creating new one');
                    this.socket.close();
                    this.socket = null;
                }
                
                const socketURL = window.location.hostname === 'localhost' 
                    ? 'http://localhost:5000' 
                    : window.location.origin;

                // Use both transports for better compatibility on localhost
                this.socket = io(socketURL, {
                    transports: ['polling', 'websocket'], // Allow both for localhost compatibility
                    upgrade: true,                         // Allow upgrade from polling to websocket
                    reconnection: true,
                    forceNew: true,
                    reconnectionDelay: 1000,
                    reconnectionAttempts: 5,
                    timeout: 20000,
                    path: '/socket.io/'
                });
                
                this.socket.on('connect', () => {
                    console.log('🔌 WebSocket connected');
                    try {
                        const transportName = this.socket.io && this.socket.io.engine && this.socket.io.engine.transport
                            ? this.socket.io.engine.transport.name
                            : (this.socket.io && this.socket.io.engine ? (this.socket.io.engine.transportName || 'unknown') : 'unknown');
                        console.log('🔍 Socket transport in use:', transportName);
                    } catch (e) {
                        console.log('🔍 Socket transport: unable to determine');
                    }
                    this.updateConnectionStatus('connected');
                    // Poproś natychmiast o aktualne statystyki po połączeniu
                    try {
                        this.requestCurrentStats();
                    } catch (e) {
                        console.warn('Unable to request stats on connect:', e);
                    }
                    resolve();
                });
                
                this.socket.on('disconnect', (reason) => {
                    console.log('🔌 WebSocket disconnected:', reason);
                    this.updateConnectionStatus('disconnected');
                    this.showToast('Połączenie przerwane', 'warning');
                });
                
                this.socket.on('connect_error', (error) => {
                    console.error('🔌 WebSocket connection error:', error);
                    this.updateConnectionStatus('disconnected');
                    reject(error);
                });
                
                this.socket.on('connection_confirmed', (data) => {
                    console.log('✅ Connection confirmed:', data.message);
                });
                
                // === ZADANIE 1.2: Nasłuchuj na live_feed_update ===
                this.socket.on('live_feed_update', (data) => {
                    console.log('🛰️ Received live_feed_update:', data);
                    this.handleLiveFeedUpdate(data);
                });
                
                this.socket.on('stats_update', (data) => {
                    this.updateStatistics(data);
                });
                
                this.socket.on('simulator_paused', (data) => {
                    console.log('🔇 Simulator paused by server');
                });
                
                this.socket.on('simulator_resumed', (data) => {
                    console.log('🔊 Simulator resumed by server');
                });
                
                this.socket.on('error', (error) => {
                    console.error('❌ WebSocket error:', error);
                    this.showToast('Błąd WebSocket: ' + error.message, 'error');
                });
                
                setTimeout(() => {
                    if (!this.socket.connected) {
                        reject(new Error('WebSocket connection timeout'));
                    }
                }, 10000);
                
            } catch (error) {
                console.error('❌ WebSocket initialization error:', error);
                reject(error);
            }
        });
    }
    
    async loadInitialData() {
        try {
            console.log('📊 Loading feed history from localStorage...');
            this.loadHistoryFromLocalStorage();
            
            // Inicjalizuj liczniki na 0 (natychmiastowo)
            this.animateCounter('foundProductsCount', 0);
            this.animateCounter('lostOpportunitiesCount', 0);
            this.animateCounter('lostOpportunitiesAmount', 0);
            this.animateCounter('filteredOutCount', 0);
            this.updateAdditionalStats();
            
            // Pobierz dane z serwera
            try {
                const response = await fetch('/api/initial_data');
                if (response.ok) {
                    const data = await response.json();
                    if (data.status === 'success' && data.data) {
                        console.log('✅ Loaded initial data from server:', data.data);
                        if (data.data.today_statistics) {
                            this.updateMetricsFromStats(data.data.today_statistics);
                        }
                        if (data.data.top_missing_products) {
                            this.updateMissingProducts(data.data.top_missing_products);
                        }
                    }
                } else {
                    console.warn('⚠️ Failed to load initial data from server');
                }
            } catch (e) {
                console.warn('⚠️ Error loading initial data:', e);
            }
            
            this.updateMissingProducts([]);
        } catch (error) {
            console.error('❌ Failed to load initial data:', error);
        }
    }
    
    loadHistoryFromLocalStorage() {
        try {
            const savedHistory = JSON.parse(localStorage.getItem('feedHistory')) || [];
            console.log(`📂 Found ${savedHistory.length} events in localStorage`);
            
            savedHistory.reverse().forEach(itemData => {
                this.addFeedItem(itemData, false);
            });
            
            if (savedHistory.length > 0) {
                console.log('✅ Feed history loaded successfully');
            }
        } catch (error) {
            console.error('❌ Failed to load feed history:', error);
        }
    }
    
    /**
     * ZADANIE 1.2 + 2.3: Handler dla live_feed_update z pełnymi danymi gościa
     */
    handleLiveFeedUpdate(data) {
        console.log('🛰️ Processing live_feed_update:', data);
        
        if (this.feedPaused) {
            this.eventQueue.push(data);
            return;
        }
        
        // Dodaj do live feed z pełnymi danymi
        this.addFeedItem(data, true); // true = zapisz do localStorage
        
        // Update metrics
        this.updateMetricsFromLiveFeed(data);
        
        // Update last update time
        this.updateLastUpdateTime();
    }
    
    /**
     * ZADANIE 2.3: Nowa funkcja addFeedItem z pełnymi danymi gościa
     */
    addFeedItem(data, saveToLocalStorage = true) {
        const liveFeed = document.getElementById('liveFeed');
        if (!liveFeed) return;
        
        const placeholder = liveFeed.querySelector('.feed-placeholder');
        if (placeholder) {
            placeholder.remove();
        }
        
        const item = document.createElement('div');
        item.className = 'feed-item';
        
        // ==== ZADANIE 2.3: RENDEROWANIE SZCZEGÓŁÓW GOŚCIA ====
        let visitorInfoHtml = '<div class="feed-visitor-info">Visitor: Unknown</div>';
        
        if (data.organization && data.organization !== 'Unknown') {
            visitorInfoHtml = `<div class="feed-visitor-info">🏢 ${data.organization} (${data.city || 'N/A'})</div>`;
        } else if (data.city && data.city !== 'Unknown') {
            visitorInfoHtml = `<div class="feed-visitor-info">📍 ${data.city}, ${data.country || ''}</div>`;
        }
        
        // Map classification to CSS class
        const classMap = {
            'ZNALEZIONE PRODUKTY': 'found-products',
            'UTRACONE OKAZJE': 'lost-opportunities',
            'ODFILTROWANE': 'filtered-out'
        };
        
        const cssClass = classMap[data.classification] || 'default';
        
        // Build HTML
        item.innerHTML = `
            <div class="feed-timestamp">${data.timestamp || new Date().toLocaleTimeString()}</div>
            <div class="feed-query">"${data.query}"</div>
            ${visitorInfoHtml}
            <span class="feed-classification ${cssClass}">${data.classification}</span>
            ${data.estimatedValue > 0 ? `<div class="feed-value">~${data.estimatedValue} zł</div>` : ''}
        `;
        
        liveFeed.insertBefore(item, liveFeed.firstChild);
        
        // ==== ZADANIE 1.2: ZAPIS DO localStorage ====
        if (saveToLocalStorage) {
            try {
                let history = JSON.parse(localStorage.getItem('feedHistory')) || [];
                history.unshift(data);
                if (history.length > 50) {
                    history.pop();
                }
                localStorage.setItem('feedHistory', JSON.stringify(history));
                console.log('💾 Event saved to localStorage');
            } catch (error) {
                console.error('❌ Failed to save to localStorage:', error);
            }
        }
        
        // Limit displayed items to 50
        const items = liveFeed.querySelectorAll('.feed-item');
        if (items.length > 50) {
            for (let i = 50; i < items.length; i++) {
                items[i].remove();
            }
        }
        
        // Scroll to top
        liveFeed.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    }
    
    /**
     * Update metrics from live feed data
     */
    updateMetricsFromLiveFeed(data) {
        const classification = data.classification;
        const value = data.estimatedValue || 0;
        
        switch (classification) {
            case 'ZNALEZIONE PRODUKTY':
                this.metrics.foundProducts.count++;
                this.animateCounter('foundProductsCount', this.metrics.foundProducts.count);
                break;
                
            case 'UTRACONE OKAZJE':
                this.metrics.lostOpportunities.count++;
                this.metrics.lostOpportunities.amount += value;
                this.animateCounter('lostOpportunitiesCount', this.metrics.lostOpportunities.count);
                this.animateCounter('lostOpportunitiesAmount', this.metrics.lostOpportunities.amount);
                break;
                
            case 'ODFILTROWANE':
                this.metrics.filteredOut.count++;
                this.animateCounter('filteredOutCount', this.metrics.filteredOut.count);
                break;
                
            default:
                console.warn('Unknown classification:', classification);
                break;
        }
        
        this.updateAdditionalStats();
        this.updateChartsData();
    }
    
    getDecisionClass(decision) {
        const decisionUpper = (decision || '').toUpperCase();
        
        if (decisionUpper.includes('ZNALEZION')) {
            return 'found-products';
        } else if (decisionUpper.includes('UTRACON')) {
            return 'lost-opportunities';
        } else if (decisionUpper.includes('ODFILTROWAN')) {
            return 'filtered-out';
        }
        return 'default';
    }
    
    updateMetricsFromStats(stats) {
        // Scal serwerowe statystyki z lokalnymi, nie nadpisuj mniejszych wartości
        if (stats['ZNALEZIONE PRODUKTY']) {
            const serverFound = stats['ZNALEZIONE PRODUKTY'].count || 0;
            this.metrics.foundProducts.count = Math.max(this.metrics.foundProducts.count || 0, serverFound);
        }
        if (stats['UTRACONE OKAZJE']) {
            const serverLostCount = stats['UTRACONE OKAZJE'].count || 0;
            const serverLostValue = stats['UTRACONE OKAZJE'].value || 0;
            this.metrics.lostOpportunities.count = Math.max(this.metrics.lostOpportunities.count || 0, serverLostCount);
            this.metrics.lostOpportunities.amount = Math.max(this.metrics.lostOpportunities.amount || 0, serverLostValue);
        }
        if (stats['ODFILTROWANE']) {
            const serverFiltered = stats['ODFILTROWANE'].count || 0;
            this.metrics.filteredOut.count = Math.max(this.metrics.filteredOut.count || 0, serverFiltered);
        }
        
        this.animateCounter('foundProductsCount', this.metrics.foundProducts.count);
        this.animateCounter('lostOpportunitiesCount', this.metrics.lostOpportunities.count);
        this.animateCounter('lostOpportunitiesAmount', this.metrics.lostOpportunities.amount);
        this.animateCounter('filteredOutCount', this.metrics.filteredOut.count);
        
        this.updateAdditionalStats();
    }
    
    /**
     * Animate counter - NAPRAWIONE z logowaniem błędów
     */
    animateCounter(elementId, targetValue, duration = 0) {
        // WERSJA BRUTALNA - NATYCHMIASTOWA ZMIANA
        const element = document.getElementById(elementId);
        if (!element) {
            // optional: element could be missing in some layouts
            return;
        }

        // Walimy wartość prosto w pysk, bez liczenia klatek
        try {
            // Jeśli targetValue jest liczbą, sformatuj po polsku
            if (typeof targetValue === 'number') {
                element.textContent = targetValue.toLocaleString('pl-PL');
            } else {
                element.textContent = String(targetValue);
            }
        } catch (e) {
            element.textContent = String(targetValue);
        }

        // Opcjonalnie: dodajemy klasę 'flash-update' żeby mignęło (bez opóźnień)
        element.classList.remove('flash-update');
        void element.offsetWidth; // trigger reflow
        element.classList.add('flash-update');
    }
    
    updateAdditionalStats() {
        const totalQueries = (this.metrics.foundProducts?.count || 0) + 
                           (this.metrics.lostOpportunities?.count || 0) + 
                           (this.metrics.filteredOut?.count || 0);
        
        const lostPotential = totalQueries > 0 ? 
            Math.round(((this.metrics.lostOpportunities?.count || 0) / totalQueries) * 100) : 0;
        
        const lostValue = this.metrics.lostOpportunities?.amount || 0;
        
        this.updateElement('successRate', lostPotential + '%');
        this.updateElement('savedRevenue', lostValue.toLocaleString('pl-PL') + ' zł');
    }
    
    updateElement(elementId, value) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = value;
        }
    }
    
    updateConnectionStatus(status) {
        const indicator = document.getElementById('connectionStatus');
        if (indicator) {
            indicator.className = `connection-status ${status}`;
            indicator.title = status === 'connected' ? 'Połączono' : 'Rozłączono';
            
            const span = indicator.querySelector('span');
            if (span) {
                span.textContent = status === 'connected' ? 'Połączony' : 'Rozłączono';
            }
        }
    }
    
    updateLastUpdateTime() {
        const element = document.getElementById('lastUpdate');
        if (element) {
            element.textContent = new Date().toLocaleTimeString('pl-PL');
        }
    }
    
    requestCurrentStats() {
        if (this.socket && this.socket.connected) {
            // Server expects 'request_current_stats'
            this.socket.emit('request_current_stats');
        }
    }
    
    updateStatistics(data) {
        // Support both legacy 'stats' and new 'today_statistics' payloads
        if (data.stats) {
            this.updateMetricsFromStats(data.stats);
        } else if (data.today_statistics) {
            this.updateMetricsFromStats(data.today_statistics);
        } else if (data.todayStatistics) {
            this.updateMetricsFromStats(data.todayStatistics);
        } else {
            console.warn('📊 updateStatistics received unknown payload', data);
        }
    }

    _hashEventKey(eventData) {
        try {
            // Use a reduced string of key fields to avoid heavy hashing libs
            const keyParts = [eventData.decision || eventData.classification || '', eventData.query_text || eventData.query || '', String(eventData.potential_value || ''), String(eventData.timestamp || '')];
            const s = keyParts.join('|');
            // simple djb2 hash
            let h = 5381;
            for (let i = 0; i < s.length; i++) {
                h = ((h << 5) + h) + s.charCodeAt(i);
                h = h & h;
            }
            return 'h_' + (h >>> 0).toString(36);
        } catch (e) {
            return 'h_fallback_' + Math.floor(Math.random() * 1000000);
        }
    }

    _simpleEventKey(eventData) {
        try {
            const decision = (eventData.decision || eventData.classification || '').toString().toUpperCase();
            const query = (eventData.query_text || eventData.query || '').toString().trim();
            const value = String(eventData.potential_value || eventData.estimatedValue || 0);
            // Keep simple and stable across client/server (no timestamp)
            return `s_${decision}|${query}|${value}`;
        } catch (e) {
            return null;
        }
    }
    
    updateMissingProducts(products) {
        const container = document.getElementById('missingProductsList');
        if (!container) return;
        
        if (!products || products.length === 0) {
            container.innerHTML = '<div class="no-data">Brak danych</div>';
            return;
        }
        
        container.innerHTML = products.map(p => `
            <div class="missing-product-item">
                <span class="product-name">${p.category || p.name}</span>
                <span class="product-count">${p.frequency || p.count}x</span>
            </div>
        `).join('');
    }
    
    initializeCharts() {
        console.log('📊 Charts initialization placeholder');
    }
    
    updateChartsData() {
        // Placeholder
    }
    
    toggleFeedPause() {
        this.feedPaused = !this.feedPaused;
        
        const pauseBtn = document.getElementById('pauseFeed');
        if (pauseBtn) {
            const icon = pauseBtn.querySelector('i');
            if (icon) {
                icon.className = this.feedPaused ? 'fas fa-play' : 'fas fa-pause';
            }
            pauseBtn.classList.toggle('paused', this.feedPaused);
        }
        
        if (!this.feedPaused && this.eventQueue.length > 0) {
            this.eventQueue.forEach(event => this.handleNewEvent(event));
            this.eventQueue = [];
        }
        
        this.showToast(this.feedPaused ? 'Feed wstrzymany' : 'Feed wznowiony', 'info');
    }
    
    clearFeed() {
        const liveFeed = document.getElementById('liveFeed');
        if (liveFeed) {
            liveFeed.innerHTML = '<div class="feed-placeholder"><i class="fas fa-satellite-dish"></i><span>Oczekiwanie na dane...</span></div>';
        }
        
        localStorage.removeItem('feedHistory');
        
        this.metrics = {
            foundProducts: { count: 0, amount: 0 },
            lostOpportunities: { count: 0, amount: 0 },
            filteredOut: { count: 0, amount: 0 }
        };
        
        this.animateCounter('foundProductsCount', 0);
        this.animateCounter('lostOpportunitiesCount', 0);
        this.animateCounter('lostOpportunitiesAmount', 0);
        this.animateCounter('filteredOutCount', 0);
        
        this.showToast('Feed wyczyszczony', 'success');
    }
    
    async resetDemo() {
        try {
            const response = await fetch('/api/reset-demo', { method: 'POST' });
            const data = await response.json();
            
            if (data.status === 'success') {
                this.clearFeed();
                this.showToast('Demo zresetowane pomyślnie', 'success');
            } else {
                throw new Error(data.message);
            }
        } catch (error) {
            console.error('❌ Reset demo failed:', error);
            this.showToast('Nie udało się zresetować demo', 'error');
        }
    }
    
    exportData() {
        const data = {
            timestamp: new Date().toISOString(),
            metrics: this.metrics,
            feed_events: Array.from(document.querySelectorAll('.feed-item')).map(item => ({
                timestamp: item.querySelector('.feed-timestamp')?.textContent,
                query: item.querySelector('.feed-query')?.textContent,
                decision: item.querySelector('.feed-decision')?.textContent
            }))
        };
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `dashboard-data-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        
        this.showToast('Dane wyeksportowane', 'success');
    }
    
    startPeriodicUpdates() {
        // Poll more frequently to keep UI responsive (10s)
        setInterval(() => {
            if (this.socket && this.socket.connected) {
                this.requestCurrentStats();
            }
        }, 10000);
        
        setInterval(() => {
            this.updateChartsData();
        }, 300000);
    }
    
    hideLoadingOverlay() {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.classList.add('hidden');
            setTimeout(() => {
                overlay.style.display = 'none';
            }, 500);
        }
    }
    
    showToast(message, type = 'info', duration = 3000) {
        const container = document.getElementById('toastContainer');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'slideInToast 0.3s ease-out reverse';
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, duration);
    }

    initializeResizer() {
        const resizeHandle = document.getElementById('resizeHandle');
        const botColumn = document.getElementById('botColumn');
        const dashboardColumn = document.getElementById('dashboardColumn');
        const collapseBtn = document.getElementById('collapseDashboard');
        
        if (!resizeHandle || !botColumn || !dashboardColumn) {
            console.log('Resizer elements not found - skipping');
            return;
        }
        
        let isResizing = false;
        
        resizeHandle.addEventListener('mousedown', (e) => {
            isResizing = true;
            document.body.style.cursor = 'col-resize';
            document.body.style.userSelect = 'none';
            
            document.addEventListener('mousemove', handleMouseMove);
            document.addEventListener('mouseup', handleMouseUp);
            e.preventDefault();
        });
        
        function handleMouseMove(e) {
            if (!isResizing) return;
            
            const container = document.querySelector('.demo-container');
            const containerRect = container.getBoundingClientRect();
            const newWidth = containerRect.right - e.clientX;
            const constrainedWidth = Math.max(280, Math.min(700, newWidth));
            
            dashboardColumn.style.width = constrainedWidth + 'px';
            e.preventDefault();
        }
        
        function handleMouseUp() {
            isResizing = false;
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
            document.removeEventListener('mousemove', handleMouseMove);
            document.removeEventListener('mouseup', handleMouseUp);
        }
        
        if (collapseBtn) {
            collapseBtn.addEventListener('click', () => {
                const currentWidth = parseInt(dashboardColumn.style.width) || 400;
                
                if (currentWidth <= 300) {
                    dashboardColumn.style.width = '400px';
                    collapseBtn.textContent = '←';
                } else {
                    dashboardColumn.style.width = '60px';
                    collapseBtn.textContent = '→';
                }
            });
        }
        
        console.log('Resizer initialized successfully');
    }
    
    initializeMobileSupport() {
        const isMobile = window.innerWidth <= 768;
        
        if (isMobile) {
            Object.values(this.charts).forEach(chart => {
                if (chart && chart.options) {
                    chart.options.maintainAspectRatio = false;
                    chart.options.responsive = true;
                    chart.update('none');
                }
            });
        }
        
        window.addEventListener('resize', () => {
            setTimeout(() => {
                Object.values(this.charts).forEach(chart => {
                    if (chart && chart.resize) {
                        chart.resize();
                    }
                });
            }, 100);
        });
        
        console.log('📱 Mobile dashboard support initialized');
    }
}

// Initialize dashboard when script loads
window.tacticalDashboard = new TacticalDashboard();