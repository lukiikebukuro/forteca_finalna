/**
 * ADEPT AI Dashboard - Real-time JavaScript Controller
 * Handles WebSocket connections, animations, charts, and live data updates
 */

class TacticalDashboard {
    constructor() {
        this.socket = null;
        this.charts = {};
        this.metrics = {
    lostDemand: { count: 0, amount: 0 },
    typoCorrections: { count: 0, amount: 0 },
    preciseHits: { count: 0, amount: 0 },
    searchFailures: { count: 0, amount: 0 }  // NOWA METRYKA
};
        this.feedPaused = false;
        this.eventQueue = [];
        this.processingQueue = false;
        
        // Animation configurations
        this.animationConfig = {
            duration: 1000,
            easing: 'easeOutCubic',
            stagger: 100
        };
        
        // Initialize on DOM ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.initialize());
        } else {
            this.initialize();
        }
    }
    
    /**
     * Initialize dashboard components
     */
    async initialize() {
        console.log('🎯 Initializing ADEPT AI Dashboard...');
        
        try {
            // Setup event listeners
            this.setupEventListeners();
            
            // Initialize WebSocket connection
            await this.initializeWebSocket();
            
            // Load initial data
            await this.loadInitialData();
            
            // Initialize charts
            this.initializeCharts();

// Initialize mobile responsiveness
this.initializeMobileSupport();
            

            this.initializeResizer();
            
            // Hide loading overlay
            this.hideLoadingOverlay();
            
            // Show connection status
            this.updateConnectionStatus('connected');
            
            // Start periodic updates
            this.startPeriodicUpdates();
            
            console.log('✅ Dashboard initialized successfully');
            this.showToast('Dashboard inicjalizowany pomyślnie', 'success');
            
        } catch (error) {
            console.error('❌ Dashboard initialization failed:', error);
            this.showToast('Błąd inicjalizacji dashboardu', 'error');
            this.hideLoadingOverlay();
        }
    }
    
    /**
     * Setup event listeners for UI interactions
     */
    setupEventListeners() {
        // Feed controls
        const pauseFeedBtn = document.getElementById('pauseFeed');
        const clearFeedBtn = document.getElementById('clearFeed');
        const resetDemoBtn = document.getElementById('resetDemo');
        const exportDataBtn = document.getElementById('exportData');
        
        // Auto-pause simulator when user starts typing
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
        
        // Window events
        window.addEventListener('beforeunload', () => {
            if (this.socket) {
                this.socket.disconnect();
            }
        });
        
        // Visibility change handling
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                console.log('📱 Dashboard went to background');
            } else {
                console.log('📱 Dashboard returned to foreground');
                this.requestCurrentStats();
            }
        });
    }
    
    /**
     * Setup input focus listeners for auto-pause functionality
     */
    setupInputFocusListeners() {
    // Monitor ONLY bot interface inputs (not dashboard inputs)
    const inputSelectors = '.bot-column input[type="text"], .bot-column input[type="search"], .bot-column textarea, .bot-column [contenteditable="true"]';
        
        // Use event delegation to catch dynamically added inputs
        document.addEventListener('focusin', (event) => {
            if (event.target.matches(inputSelectors)) {
                this.pauseSimulatorForTyping();
            }
        });
        
        document.addEventListener('focusout', (event) => {
            if (event.target.matches(inputSelectors)) {
                // Small delay to avoid rapid pause/resume cycles
                setTimeout(() => {
                    // Check if focus moved to another input
                    const activeElement = document.activeElement;
                    if (!activeElement || !activeElement.matches(inputSelectors)) {
                        this.resumeSimulatorAfterTyping();
                    }
                }, 100);
            }
        });
        
        // Also listen for any input elements that might be added later
        // (if bot interface is loaded dynamically)
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
    
    /**
     * Pause simulator when user starts typing
     */
    pauseSimulatorForTyping() {
    if (this.socket && this.socket.connected) {
        const el = document.activeElement;
        console.log('⏸️ Auto-pausing - element:', el);
        console.log('  - tagName:', el.tagName);
        console.log('  - id:', el.id);
        console.log('  - className:', el.className);
        console.log('  - parent:', el.parentElement?.className);
        this.socket.emit('pause_simulator');
    }
}
    
    /**
     * Resume simulator when user stops typing
     */
    resumeSimulatorAfterTyping() {
        if (this.socket && this.socket.connected) {
            console.log('▶️ Auto-resuming simulator - user stopped typing');
            this.socket.emit('resume_simulator');
        }
    }
    /**
     * Initialize WebSocket connection
     */
    async initializeWebSocket() {
        return new Promise((resolve, reject) => {
            try {
                // Connect to Flask-SocketIO server
                // Automatycznie wykryj środowisko
const socketURL = window.location.hostname === 'localhost' 
    ? 'http://localhost:5000' 
    : window.location.origin;

this.socket = io(socketURL, {
    transports: ['polling', 'websocket'], // Polling FIRST dla Render
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionAttempts: 5,
    timeout: 20000, // Zwiększony timeout
    path: '/socket.io/',
    secure: true,
    rejectUnauthorized: false
});
                
                // Connection events
                this.socket.on('connect', () => {
                    console.log('🔌 WebSocket connected');
                    this.updateConnectionStatus('connected');
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
                
                // WYŁĄCZONE - live_feed_update jest TYLKO dla admina!
                // Publiczny TCD nasłuchuje TYLKO na 'new_event'
                // this.socket.on('live_feed_update', (data) => {
                //     console.log('🛰️ SATELITA: Received live_feed_update', data);
                //     this.handleLiveFeedUpdate(data);
                // });
                
                this.socket.on('connect_error', (error) => {
                    console.error('🔌 WebSocket connection error:', error);
                    this.updateConnectionStatus('disconnected');
                    reject(error);
                });
                
                // Data events
                this.socket.on('connection_confirmed', (data) => {
                    console.log('✅ Connection confirmed:', data.message);
                });
                
                this.socket.on('new_event', (eventData) => {
                    this.handleNewEvent(eventData);
                });
                
                this.socket.on('stats_update', (data) => {
                    this.updateStatistics(data);
                });
                
                // Simulator control events
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
                
                // Timeout for connection
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
    
    /**
     * Load initial data from API
     */
    async loadInitialData() {
        try {
            // ==== ZADANIE 1.1: WCZYTANIE HISTORII Z localStorage ====
            console.log('📊 Loading feed history from localStorage...');
            this.loadHistoryFromLocalStorage();
            
            // Use empty initial state for metrics
            this.updateMetricsFromStats({});
            this.updateMissingProducts([]);
        } catch (error) {
            console.error('❌ Failed to load initial data:', error);
        }
    }
    
    /**
     * ZADANIE 1.1: Wczytanie historii z localStorage
     */
    loadHistoryFromLocalStorage() {
        try {
            const savedHistory = JSON.parse(localStorage.getItem('feedHistory')) || [];
            console.log(`📂 Found ${savedHistory.length} events in localStorage`);
            
            // Wyświetl eventy w odwrotnej kolejności (najstarsze pierwsze)
            savedHistory.reverse().forEach(itemData => {
                this.addFeedItem(itemData, false); // false = nie zapisuj ponownie do localStorage
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
        
        // Remove placeholder if present
        const placeholder = liveFeed.querySelector('.feed-placeholder');
        if (placeholder) {
            placeholder.remove();
        }
        
        // Create feed item
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
        
        // Insert at top
        liveFeed.insertBefore(item, liveFeed.firstChild);
        
        // ==== ZADANIE 1.2: ZAPIS DO localStorage ====
        if (saveToLocalStorage) {
            try {
                let history = JSON.parse(localStorage.getItem('feedHistory')) || [];
                history.unshift(data); // Dodaj na początek
                
                // Limit do 50 eventów
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
                if (!this.metrics.foundProducts) this.metrics.foundProducts = { count: 0, amount: 0 };
                this.metrics.foundProducts.count++;
                this.animateCounter('foundProductsCount', this.metrics.foundProducts.count);
                break;
                
            case 'UTRACONE OKAZJE':
                if (!this.metrics.lostOpportunities) this.metrics.lostOpportunities = { count: 0, amount: 0 };
                this.metrics.lostOpportunities.count++;
                this.metrics.lostOpportunities.amount += value;
                this.animateCounter('lostOpportunitiesCount', this.metrics.lostOpportunities.count);
                this.animateCounter('lostOpportunitiesAmount', this.metrics.lostOpportunities.amount);
                break;
                
            case 'ODFILTROWANE':
                if (!this.metrics.filteredOut) this.metrics.filteredOut = { count: 0, amount: 0 };
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
    /**
     * Handle new event from WebSocket
     */
    handleNewEvent(eventData) {
        if (this.feedPaused) {
            this.eventQueue.push(eventData);
            return;
        }
        
        console.log('🔔 New event received:', eventData);
        
        // Add to live feed
        this.addEventToFeed(eventData);
        
        // Update metrics
        this.updateMetricsFromEvent(eventData);
        
        // Update last update time
        this.updateLastUpdateTime();
        
        // Request fresh stats
        setTimeout(() => this.requestCurrentStats(), 500);
    }
    
    /**
     * Add event to live feed with animation
     */
    addEventToFeed(eventData) {
        const liveFeed = document.getElementById('liveFeed');
        if (!liveFeed) return;
        
        // Remove placeholder if present
        const placeholder = liveFeed.querySelector('.feed-placeholder');
        if (placeholder) {
            placeholder.remove();
        }
        
        // Create feed item
        const feedItem = document.createElement('div');
        feedItem.className = `feed-item ${this.getDecisionClass(eventData.decision)}`;
        
        const potentialValue = eventData.potential_value || 0;
        const valueDisplay = potentialValue > 0 ? 
            `<div class="feed-value">Szacowana wartość: ${potentialValue} zł</div>` : '';
        
        feedItem.innerHTML = `
            <div class="feed-timestamp">${eventData.timestamp}</div>
            <div class="feed-query">"${eventData.query_text}"</div>
            <div class="feed-decision ${this.getDecisionClass(eventData.decision)}">
                ${eventData.decision}
            </div>
            <div class="feed-details">${eventData.details}</div>
            ${valueDisplay}
        `;
        
        // Add tooltip with explanation
        if (eventData.explanation) {
            feedItem.title = eventData.explanation;
        }
        
        // Insert at top with animation
        liveFeed.insertBefore(feedItem, liveFeed.firstChild);
        
        // Limit number of feed items (keep last 50)
        // Limit number of feed items (keep last 4) - DODAJ OPÓŹNIENIE
// Limit number of feed items (keep last 50)
const items = liveFeed.querySelectorAll('.feed-item');
if (items.length > 50) {
    for (let i = 50; i < items.length; i++) {
        items[i].remove();
    }
}
        
        // Scroll to top smoothly
        liveFeed.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    }
    
    /**
     * Get CSS class for decision type
     */
    getDecisionClass(decision) {
    switch (decision) {
        case 'ZNALEZIONE PRODUKTY':     // Nowa kategoria
            return 'found-products';
        case 'UTRACONE OKAZJE':         // Zmieniona nazwa z "UTRACONY POPYT"
            return 'lost-opportunities';
        case 'ODFILTROWANE':            // Nowa kategoria (literówki + nonsens)
            return 'filtered-out';
        default:
            return 'default';
    }
}
    
    /**
     * Update metrics from single event
     */
    updateMetricsFromEvent(eventData) {
    const decision = eventData.decision;
    const value = eventData.potential_value || 0;
    
    // Mapowanie starych nazw na nowe (dla kompatybilności)
    let mappedDecision = decision;
    if (decision === 'PRECYZYJNE TRAFIENIE') mappedDecision = 'ZNALEZIONE PRODUKTY';
    if (decision === 'UTRACONY POPYT') mappedDecision = 'UTRACONE OKAZJE';
    if (decision === 'KOREKTA LITERÓWKI' || decision === 'BŁĄD WYSZUKIWANIA') mappedDecision = 'ODFILTROWANE';
    
    switch (mappedDecision) {
        case 'ZNALEZIONE PRODUKTY':
            if (!this.metrics.foundProducts) this.metrics.foundProducts = { count: 0, amount: 0 };
            this.metrics.foundProducts.count++;
            this.animateCounter('foundProductsCount', this.metrics.foundProducts.count);
            break;
            
        case 'UTRACONE OKAZJE':
            if (!this.metrics.lostOpportunities) this.metrics.lostOpportunities = { count: 0, amount: 0 };
            this.metrics.lostOpportunities.count++;
            this.metrics.lostOpportunities.amount += value;
            this.animateCounter('lostOpportunitiesCount', this.metrics.lostOpportunities.count);
            this.animateCounter('lostOpportunitiesAmount', this.metrics.lostOpportunities.amount);
            break;
            
        case 'ODFILTROWANE':
            if (!this.metrics.filteredOut) this.metrics.filteredOut = { count: 0, amount: 0 };
            this.metrics.filteredOut.count++;
            this.animateCounter('filteredOutCount', this.metrics.filteredOut.count);
            break;
            
        default:
            console.warn('Unknown decision type:', decision);
            break;
    }
    

this.updateAdditionalStats();
this.updateChartsData();
}
    
    /**
     * Update metrics from statistics data
     */
    updateMetricsFromStats(stats) {
    // Update lost demand
    const lostDemand = stats['UTRACONY POPYT'] || { count: 0, value: 0 };
    this.metrics.lostDemand.count = lostDemand.count;
    this.metrics.lostDemand.amount = lostDemand.value;
    
    // Update typo corrections
    const typoCorrections = stats['KOREKTA LITERÓWKI'] || { count: 0, value: 0 };
    this.metrics.typoCorrections.count = typoCorrections.count;
    
    // Update precise hits
    const preciseHits = stats['PRECYZYJNE TRAFIENIE'] || { count: 0, value: 0 };
    this.metrics.preciseHits.count = preciseHits.count;
    
    // Update search failures - NOWE
    const searchFailures = stats['BŁĄD WYSZUKIWANIA'] || { count: 0, value: 0 };
    this.metrics.searchFailures.count = searchFailures.count;
    
    // Animate counters
    this.animateCounter('lostDemandCount', this.metrics.lostDemand.count);
    this.animateCounter('lostDemandAmount', this.metrics.lostDemand.amount);
    this.animateCounter('typoCorrectionsCount', this.metrics.typoCorrections.count);
    this.animateCounter('preciseHitsCount', this.metrics.preciseHits.count);
    this.animateCounter('searchFailuresCount', this.metrics.searchFailures.count);  // NOWE
    
    // Update additional stats
    this.updateAdditionalStats();
}
    
    /**
     * Animate counter with smooth count-up effect
     */
    animateCounter(elementId, targetValue, duration = 1000) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const startValue = parseInt(element.textContent.replace(/[^\d]/g, '')) || 0;
        const difference = targetValue - startValue;
        const startTime = performance.now();
        
        const updateCounter = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function (ease-out-cubic)
            const easedProgress = 1 - Math.pow(1 - progress, 3);
            
            const currentValue = Math.round(startValue + (difference * easedProgress));
            
            // Format number with thousand separators
            const formattedValue = currentValue.toLocaleString('pl-PL');
            element.textContent = formattedValue;
            
            // Add scale animation on significant changes
            if (difference > 0 && progress < 0.3) {
                element.style.transform = `scale(${1 + (0.1 * easedProgress)})`;
            } else {
                element.style.transform = 'scale(1)';
            }
            
            if (progress < 1) {
                requestAnimationFrame(updateCounter);
            }
        };
        
        requestAnimationFrame(updateCounter);
    }
    
    /**
     * Update additional statistics
     */
    updateAdditionalStats() {
    const totalQueries = (this.metrics.foundProducts?.count || 0) + 
                       (this.metrics.lostOpportunities?.count || 0) + 
                       (this.metrics.filteredOut?.count || 0);
    
    const lostPotential = totalQueries > 0 ? 
        Math.round(((this.metrics.lostOpportunities?.count || 0) / totalQueries) * 100) : 0;
    
    // Zmienione: liczymy utracone pieniądze zamiast uratowanych
    const lostValue = this.metrics.lostOpportunities?.amount || 0;
    
    this.updateElement('successRate', lostPotential + '%');
    this.updateElement('savedRevenue', lostValue.toLocaleString('pl-PL') + ' zł');
}
    
    /**
     * Update element text content safely
     */
    updateElement(elementId, value) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = value;
        }
    }
    
    /**
     * Populate live feed with historical events
     */
    populateLiveFeed(events) {
        const liveFeed = document.getElementById('liveFeed');
        if (!liveFeed || !events.length) return;
        
        // Clear placeholder
        liveFeed.innerHTML = '';
        
        // Add events (most recent first)
        events.forEach((event, index) => {
            setTimeout(() => {
                const timestamp = new Date(event.timestamp).toLocaleTimeString('pl-PL');
                this.addEventToFeed({
                    ...event,
                    timestamp: timestamp
                });
            }, index * 100); // Stagger animations
        });
    }
    
    /**
     * Update missing products list
     */
    updateMissingProducts(products) {
        const list = document.getElementById('missingProductsList');
        if (!list) return;
        
        if (!products.length) {
            list.innerHTML = `
                <div class="missing-product-placeholder">
                    <p>Brak danych o brakujących produktach</p>
                </div>
            `;
            return;
        }
        
        list.innerHTML = products.map(product => `
            <div class="missing-product-item">
                <div>
                    <div class="missing-product-name">${product.category}</div>
                    <div class="missing-product-count">${product.frequency} zapytań</div>
                </div>
                <div class="missing-product-value">
                    ${product.total_value.toLocaleString('pl-PL')} zł
                </div>
            </div>
        `).join('');
    }
    
    /**
     * Initialize charts using Chart.js
     */
    initializeCharts() {
        this.initializePerformanceChart();
        this.initializeTrendChart();
    }
    
    /**
     * Initialize performance pie chart
     */
    initializePerformanceChart() {
    const canvas = document.getElementById('performanceChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    this.charts.performance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Znalezione Produkty', 'Utracone Okazje', 'Odfiltrowane'],
            datasets: [{
                data: [
                    this.metrics.foundProducts?.count || 0,
                    this.metrics.lostOpportunities?.count || 0,
                    this.metrics.filteredOut?.count || 0
                ],
                backgroundColor: [
    'rgba(34, 197, 94, 0.8)',   // Zielony - znalezione
    'rgba(239, 68, 68, 0.8)',   // Czerwony - utracone (zmienione z niebieskiego)
    'rgba(168, 85, 247, 0.8)'   // Fioletowy - odfiltrowane
],
borderColor: [
    'rgba(34, 197, 94, 1)',
    'rgba(239, 68, 68, 1)',     // Czerwony border
    'rgba(168, 85, 247, 1)'
],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#b0b0b0',
                        padding: 10,
                        font: { size: 10 }
                    }
                }
            }
        }
    });
}
    
    /**
     * Initialize trend line chart
     */
    initializeTrendChart() {
        const canvas = document.getElementById('trendChart');
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        
        // Generate dummy trend data for demonstration
        const hours = [];
        const lostDemandData = [];
        const successData = [];
        
        for (let i = 23; i >= 0; i--) {
            const hour = new Date();
            hour.setHours(hour.getHours() - i);
            hours.push(hour.toLocaleTimeString('pl-PL', { hour: '2-digit', minute: '2-digit' }));
            
            lostDemandData.push(Math.floor(Math.random() * 10));
            successData.push(Math.floor(Math.random() * 25) + 10);
        }
        
        this.charts.trend = new Chart(ctx, {
            type: 'line',
            data: {
                labels: hours,
                datasets: [
                    {
                        label: 'Utracony Popyt',
                        data: lostDemandData,
                        borderColor: 'rgba(255, 71, 87, 1)',
                        backgroundColor: 'rgba(255, 71, 87, 0.1)',
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: 'Sukcesy',
                        data: successData,
                        borderColor: 'rgba(76, 175, 80, 1)',
                        backgroundColor: 'rgba(76, 175, 80, 0.1)',
                        tension: 0.4,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        ticks: {
                            color: '#808080',
                            maxTicksLimit: 8
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    },
                    y: {
                        ticks: {
                            color: '#808080'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#b0b0b0'
                        }
                    }
                }
            }
        });
    }
    
    /**
     * Update charts data
     */
    updateChartsData() {
    if (this.charts.performance) {
        this.charts.performance.data.datasets[0].data = [
            this.metrics.foundProducts?.count || 0,
            this.metrics.lostOpportunities?.count || 0,
            this.metrics.filteredOut?.count || 0
        ];
        this.charts.performance.update('none');
    }
}
    
    /**
     * Update connection status indicator
     */
    updateConnectionStatus(status) {
        const statusElement = document.getElementById('connectionStatus');
        if (!statusElement) return;
        
        statusElement.className = `connection-status ${status}`;
        
        const icon = statusElement.querySelector('i');
        const text = statusElement.querySelector('span');
        
        if (status === 'connected') {
            icon.className = 'fas fa-wifi';
            text.textContent = 'Połączono';
        } else {
            icon.className = 'fas fa-wifi-slash';
            text.textContent = 'Rozłączono';
        }
    }
    
    /**
     * Update last update timestamp
     */
    updateLastUpdateTime() {
        const element = document.getElementById('lastUpdate');
        if (element) {
            element.textContent = `Ostatnia aktualizacja: ${new Date().toLocaleTimeString('pl-PL')}`;
        }
    }
    
    /**
     * Request current statistics from server
     */
    requestCurrentStats() {
        if (this.socket && this.socket.connected) {
            this.socket.emit('request_current_stats');
        }
    }
    
    /**
     * Update statistics from WebSocket data
     */
    updateStatistics(data) {
        if (data.today_statistics) {
            this.updateMetricsFromStats(data.today_statistics);
        }
        
        if (data.top_missing_products) {
            this.updateMissingProducts(data.top_missing_products);
        }
    }
    
    /**
     * Toggle feed pause state
     */
    toggleFeedPause() {
        this.feedPaused = !this.feedPaused;
        const btn = document.getElementById('pauseFeed');
        
        if (this.feedPaused) {
            btn.innerHTML = '<i class="fas fa-play"></i>';
            btn.title = 'Wznów feed';
            this.showToast('Feed wstrzymany', 'warning');
        } else {
            btn.innerHTML = '<i class="fas fa-pause"></i>';
            btn.title = 'Wstrzymaj feed';
            this.showToast('Feed wznowiony', 'success');
            
            // Process queued events
            this.processEventQueue();
        }
    }
    
    /**
     * Process queued events
     */
    processEventQueue() {
        if (this.processingQueue || this.eventQueue.length === 0) return;
        
        this.processingQueue = true;
        
        const processNext = () => {
            if (this.eventQueue.length === 0) {
                this.processingQueue = false;
                return;
            }
            
            const event = this.eventQueue.shift();
            this.handleNewEvent(event);
            
            setTimeout(processNext, 200); // Stagger processing
        };
        
        processNext();
    }
    
    /**
     * Clear live feed
     */
    clearFeed() {
        const liveFeed = document.getElementById('liveFeed');
        if (liveFeed) {
            liveFeed.innerHTML = `
                <div class="feed-placeholder">
                    <i class="fas fa-satellite-dish fa-3x"></i>
                    <p>Feed wyczyszczony</p>
                </div>
            `;
            this.showToast('Feed wyczyszczony', 'success');
        }
    }
    
    /**
     * Reset demo data
     */
    async resetDemo() {
        try {
            const response = await fetch('/api/reset_demo');
            const data = await response.json();
            
            if (data.status === 'success') {
                // Reset metrics
                this.metrics = {
    foundProducts: { count: 0, amount: 0 },
    lostOpportunities: { count: 0, amount: 0 },
    filteredOut: { count: 0, amount: 0 }
};
                
                // Update UI
                this.updateMetricsFromStats({});
                this.clearFeed();
                
                // Update charts
                this.updateChartsData();
                
                this.showToast('Demo zresetowane pomyślnie', 'success');
            } else {
                throw new Error(data.message);
            }
        } catch (error) {
            console.error('❌ Reset demo failed:', error);
            this.showToast('Nie udało się zresetować demo', 'error');
        }
    }
    
    /**
     * Export data to JSON
     */
    exportData() {
        const data = {
            timestamp: new Date().toISOString(),
            metrics: this.metrics,
            feed_events: Array.from(document.querySelectorAll('.feed-item')).map(item => ({
                timestamp: item.querySelector('.feed-timestamp')?.textContent,
                query: item.querySelector('.feed-query')?.textContent,
                decision: item.querySelector('.feed-decision')?.textContent,
                details: item.querySelector('.feed-details')?.textContent
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
    
    /**
     * Start periodic updates
     */
    startPeriodicUpdates() {
        // Request stats every 30 seconds
        setInterval(() => {
            if (this.socket && this.socket.connected) {
                this.requestCurrentStats();
            }
        }, 30000);
        
        // Update charts every 5 minutes
        setInterval(() => {
            this.updateChartsData();
        }, 300000);
    }
    
    /**
     * Hide loading overlay with animation
     */
    hideLoadingOverlay() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.classList.add('hidden');
            setTimeout(() => {
                overlay.style.display = 'none';
            }, 500);
        }
    }
    
    /**
     * Show toast notification
     */
    showToast(message, type = 'info', duration = 3000) {
        const container = document.getElementById('toastContainer');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        
        container.appendChild(toast);
        
        // Auto remove
        setTimeout(() => {
            toast.style.animation = 'slideInToast 0.3s ease-out reverse';
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, duration);
    }

    // DODAJ NOWĄ FUNKCJĘ TUTAJ:
    /**
     * Initialize resizable layout
     */
    initializeResizer() {
    const resizeHandle = document.getElementById('resizeHandle');
    const botColumn = document.getElementById('botColumn');
    const dashboardColumn = document.getElementById('dashboardColumn');
    const collapseBtn = document.getElementById('collapseDashboard');
    
    console.log('Resizer init:', { resizeHandle, botColumn, dashboardColumn, collapseBtn });
    
    if (!resizeHandle || !botColumn || !dashboardColumn) {
        console.error('Resizer elements not found:', {
            resizeHandle: !!resizeHandle,
            botColumn: !!botColumn, 
            dashboardColumn: !!dashboardColumn
        });
        return;
    }
    
    let isResizing = false;
    let startWidth = 0;
    
    // Mouse down na handle
    resizeHandle.addEventListener('mousedown', (e) => {
        console.log('Resizer mousedown');
        isResizing = true;
        startWidth = dashboardColumn.offsetWidth;
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        
        // Dodaj event listeners na document
        document.addEventListener('mousemove', handleMouseMove);
        document.addEventListener('mouseup', handleMouseUp);
        
        e.preventDefault();
        e.stopPropagation();
    });
    
    function handleMouseMove(e) {
        if (!isResizing) return;
        
        const container = document.querySelector('.demo-container');
        const containerRect = container.getBoundingClientRect();
        const mouseX = e.clientX;
        const containerRight = containerRect.right;
        
        // Oblicz nową szerokość dashboardu
        const newWidth = containerRight - mouseX;
        
        // Limity: min 280px, max 700px
        const constrainedWidth = Math.max(280, Math.min(700, newWidth));
        
        // Aplikuj nową szerokość
        dashboardColumn.style.width = constrainedWidth + 'px';
        
        console.log('Resizing:', { mouseX, containerRight, newWidth, constrainedWidth });
        
        e.preventDefault();
    }
    
    function handleMouseUp() {
        console.log('Resizer mouseup');
        isResizing = false;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        
        // Usuń event listeners
        document.removeEventListener('mousemove', handleMouseMove);
        document.removeEventListener('mouseup', handleMouseUp);
    }
    
    // Collapse/Expand functionality  
    if (collapseBtn) {
        collapseBtn.addEventListener('click', () => {
            const currentWidth = parseInt(dashboardColumn.style.width) || 400;
            console.log('Collapse clicked, current width:', currentWidth);
            
            if (currentWidth <= 300) {
                // Expand
                dashboardColumn.style.width = '400px';
                collapseBtn.textContent = '←';
                console.log('Expanded to 400px');
            } else {
                // Collapse  
                dashboardColumn.style.width = '60px';
                collapseBtn.textContent = '→';
                console.log('Collapsed to 60px');
            }
        });
    }
    
    console.log('Resizer initialized successfully');
}
/**
 * Initialize mobile support for dashboard
 */
initializeMobileSupport() {
    // Detect mobile and adjust chart sizing
    const isMobile = window.innerWidth <= 768;
    
    if (isMobile) {
        // Apply mobile optimizations to charts
        Object.values(this.charts).forEach(chart => {
            if (chart && chart.options) {
                chart.options.maintainAspectRatio = false;
                chart.options.responsive = true;
                chart.update('none');
            }
        });
    }
    
    // Handle window resize for charts
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
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, testing elements:');
    console.log('resizeHandle:', document.getElementById('resizeHandle'));
    console.log('botColumn:', document.getElementById('botColumn')); 
    console.log('dashboardColumn:', document.getElementById('dashboardColumn'));
    console.log('collapseDashboard:', document.getElementById('collapseDashboard'));
});