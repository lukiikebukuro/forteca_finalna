/**
 * 🎯 ADMIN DASHBOARD - Twoje Centrum Dowodzenia
 * 
 * CO TO ROBI (po ludzku):
 * 1. Pokazuje kto był na Twojej stronie (firmy, miasta)
 * 2. Mówi co robili (jakie pytania, czy kupili)
 * 3. Wyłapuje HOT LEADS (kto jest mega zainteresowany)
 * 4. Wszystko na żywo - jak ktoś wchodzi, widzisz od razu
 * 
 * Żadnych technikaliów - tylko jasne info dla Ciebie!
 */

class AdminDashboard {
    constructor() {
        console.log('🎯 ADMIN DASHBOARD: Uruchamiam Twoje centrum dowodzenia...');
        
        // Tutaj trzymamy dane
        this.companies = new Map();        // Firmy które nas odwiedziły
        this.activeSessions = [];          // Kto jest TERAZ na stronie
        this.todayStats = {                // Statystyki z dziś
            totalVisitors: 0,
            totalSessions: 0,
            avgDuration: 0,
            conversionRate: 0
        };
        
        this.hotLeads = [];                // HOT LEADS lista (WAŻNE!)
        this.socket = null;
        
        // DODAJ: Załaduj HOT LEADS z localStorage (persistence!)
        this.loadHotLeadsFromStorage();
        
        // Start!
        this.initialize();
    }
    
    /**
     * Załaduj HOT LEADS z localStorage
     */
    loadHotLeadsFromStorage() {
        try {
            const stored = localStorage.getItem('hotLeads');
            if (stored) {
                this.hotLeads = JSON.parse(stored);
                this.hotLeads.forEach(lead => {
                    lead.timestamp = new Date(lead.timestamp);
                });
                console.log(`✅ Załadowano ${this.hotLeads.length} HOT LEADS z localStorage`);
                
                // CRITICAL FIX: Renderuj HOT LEADS po załadowaniu!
                this.updateHotLeadsList();
            }
        } catch (e) {
            console.error('❌ Błąd ładowania HOT LEADS:', e);
            this.hotLeads = [];
        }
    }
    
    saveHotLeadsToStorage() {
        try {
            localStorage.setItem('hotLeads', JSON.stringify(this.hotLeads));
        } catch (e) {
            console.error('❌ Błąd zapisywania HOT LEADS:', e);
        }
    }
    
    /**
     * KROK 1: Uruchom wszystko
     */
    async initialize() {
        console.log('📡 Łączę się z serwerem...');
        
        try {
            // Połącz WebSocket (dane na żywo)
            await this.connectWebSocket();
            
            // Załaduj dane z ostatnich 24h
            await this.loadTodayData();
            
            // Odświeżaj co 30 sekund
            setInterval(() => this.refreshStats(), 30000);
            
            console.log('✅ ADMIN DASHBOARD działa! Możesz śledzić swoich klientów.');
            this.showNotification('Dashboard gotowy!', 'success');
            
        } catch (error) {
            console.error('❌ Błąd uruchamiania:', error);
            this.showNotification('Błąd połączenia z serwerem', 'error');
        }
    }
    
    /**
     * KROK 2: Połącz WebSocket (dane na żywo)
     */
    async connectWebSocket() {
        return new Promise((resolve, reject) => {
            const socketURL = window.location.hostname === 'localhost' 
                ? 'http://localhost:5000' 
                : window.location.origin;
            
            this.socket = io(socketURL, {
                transports: ['polling', 'websocket'],
                reconnection: true,
                reconnectionDelay: 1000,
                reconnectionAttempts: 5
            });
            
            // Połączono!
            this.socket.on('connect', () => {
                console.log('✅ WebSocket połączony - dane będą płynąć na żywo!');
                resolve();
            });
            
            // 🔔 NOWY VISITOR! (to jest najważniejsze)
            this.socket.on('live_feed_update', (data) => {
                console.log('🔔 Nowy visitor!', data);
                this.handleNewVisitor(data);
            });
            
            // Rozłączono
            this.socket.on('disconnect', () => {
                console.warn('⚠️ WebSocket rozłączony');
                this.updateConnectionStatus('disconnected');
            });
            
            // Błąd
            this.socket.on('connect_error', (error) => {
                console.error('❌ Błąd WebSocket:', error);
                reject(error);
            });
            
            // Timeout 10s
            setTimeout(() => {
                if (!this.socket.connected) {
                    reject(new Error('Timeout połączenia WebSocket'));
                }
            }, 10000);
        });
    }
    
    /**
     * KROK 3: Załaduj dane z dziś (ostatnie 24h)
     */
    async loadTodayData() {
        try {
            console.log('📊 Pobieram dane z ostatnich 24h...');
            
            const response = await fetch('/api/admin/visitor-stats');
            const data = await response.json();
            
            if (data.status === 'success') {
                console.log('✅ Dane pobrane:', data);
                
                // Aktualizuj liczby
                this.updateVisitorStats(data.stats);
                
                // Aktualizuj listę firm
                this.updateCompanyList(data.companies);
                
                // Aktualizuj aktywne sesje
                this.updateActiveSessions(data.active_sessions);
                
                // Aktualizuj wykres
                this.updateClassificationChart(data.classification);
                
            } else {
                throw new Error(data.message || 'Błąd pobierania danych');
            }
            
        } catch (error) {
            console.error('❌ Błąd ładowania danych:', error);
            this.showNotification('Nie udało się pobrać danych', 'error');
        }
    }
    
    /**
     * 🔔 NOWY VISITOR! (ktoś właśnie wszedł na stronę)
     */
    handleNewVisitor(data) {
        console.log('👤 Nowy visitor:', {
            firma: data.organization,
            miasto: data.city,
            zapytanie: data.query,
            klasyfikacja: data.classification
        });
        
        // DODANE: Renderuj w Live Feed
        this.addLiveFeedEvent(data);
        
        // 1. Dodaj firmę do listy (jeśli nie ma)
        this.trackCompany(data);
        
        // 2. Sprawdź czy to HOT LEAD
        if (this.isHotLead(data)) {
            this.showHotLeadAlert(data);
        }
        
        // 3. Zaktualizuj liczby
        this.incrementVisitorCount();
        
        // 4. Odśwież statystyki
        this.refreshStats();
    }
    
    /**
     * Śledź firmę (dodaj do listy firm)
     */
    trackCompany(data) {
        const companyName = data.organization || 'Unknown';
        
        if (companyName === 'Unknown') return; // Pomijamy unknown
        
        // Sprawdź czy firma już była
        if (!this.companies.has(companyName)) {
            this.companies.set(companyName, {
                name: companyName,
                city: data.city,
                country: data.country,
                firstVisit: new Date(),
                lastVisit: new Date(),
                totalQueries: 1,
                queries: [data.query],
                highIntentQueries: data.classification === 'ZNALEZIONE PRODUKTY' ? 1 : 0,
                lostOpportunities: data.classification === 'UTRACONE OKAZJE' ? 1 : 0,
                engagementScore: this.calculateEngagementScore(data)
            });
            
            console.log(`🆕 Nowa firma: ${companyName} (${data.city})`);
        } else {
            // Firma już była - zaktualizuj dane
            const company = this.companies.get(companyName);
            company.lastVisit = new Date();
            company.totalQueries++;
            company.queries.push(data.query);
            
            if (data.classification === 'ZNALEZIONE PRODUKTY') {
                company.highIntentQueries++;
            }
            if (data.classification === 'UTRACONE OKAZJE') {
                company.lostOpportunities++;
            }
            
            company.engagementScore = this.calculateEngagementScore(data, company);
            
            console.log(`🔄 Firma wraca: ${companyName} (zapytań: ${company.totalQueries})`);
        }
        
        // Odśwież listę firm na dashboardzie
        this.updateCompanyList(Array.from(this.companies.values()));
    }
    
    /**
     * Czy to HOT LEAD? (bardzo zainteresowany klient)
     */
    isHotLead(data) {
        // HOT LEAD = spełnia jeden z warunków:
        
        // 1. Duża znana firma
        const bigCompanies = ['Google', 'Microsoft', 'Amazon', 'Facebook', 'Apple', 'Orange'];
        if (bigCompanies.some(big => data.organization?.includes(big))) {
            return true;
        }
        
        // 2. Firma która wróciła (3+ zapytania)
        const company = this.companies.get(data.organization);
        if (company && company.totalQueries >= 3) {
            return true;
        }
        
        // 3. High-intent query (znalazł produkty)
        if (data.classification === 'ZNALEZIONE PRODUKTY') {
            return true;
        }
        
        return false;
    }
    
    /**
     * 🔥 ALERT! HOT LEAD wykryty!
     */
    showHotLeadAlert(data) {
        const companyName = data.organization || data.city || 'Unknown';
        const query = data.query;
        
        console.log(`🔥🔥🔥 HOT LEAD: ${companyName} - "${query}"`);
        
        // Pokaż wielki alert na górze dashboardu
        this.showNotification(
            `🔥 HOT LEAD: ${companyName} właśnie szukał: "${query}"`,
            'hot-lead',
            10000 // 10 sekund
        );
        
        // Dodaj do listy hot leads
        this.hotLeads.unshift({
            company: companyName,
            city: data.city,
            query: query,
            timestamp: new Date(),
            estimatedValue: data.estimatedValue || 0
        });
        
        // Odśwież listę hot leads
        this.updateHotLeadsList();
        
        // Zapisz do localStorage
        this.saveHotLeadsToStorage();
    }
    
    /**
     * Oblicz engagement score (0-100)
     * Im wyższy = bardziej zainteresowany
     */
    calculateEngagementScore(data, existingCompany = null) {
        let score = 0;
        
        // Punkty za zapytania
        if (existingCompany) {
            score += Math.min(existingCompany.totalQueries * 10, 40); // max 40 pkt
        } else {
            score += 10; // pierwsze zapytanie
        }
        
        // Punkty za high-intent
        if (data.classification === 'ZNALEZIONE PRODUKTY') {
            score += 30;
        }
        
        // Punkty za utracone okazje (chciał czegoś czego nie ma = zainteresowany)
        if (data.classification === 'UTRACONE OKAZJE') {
            score += 20;
        }
        
        // Punkty za wartość
        if (data.estimatedValue > 500) {
            score += 10;
        }
        
        return Math.min(score, 100); // max 100
    }
    
    /**
     * Zaktualizuj liczby na górze (Visitor Analytics)
     */
    updateVisitorStats(stats) {
        // Aktywni użytkownicy (ostatnie 15 min)
        document.getElementById('activeVisitors').textContent = stats.active_now || 0;
        
        // Sesje dziś
        document.getElementById('totalSessions').textContent = stats.sessions_today || 0;
        
        // Średni czas sesji (w minutach)
        const avgMinutes = Math.floor((stats.avg_duration || 0) / 60);
        const avgSeconds = (stats.avg_duration || 0) % 60;
        document.getElementById('avgDuration').textContent = `${avgMinutes}:${avgSeconds.toString().padStart(2, '0')}`;
        
        // Conversion rate (% sesji z high-intent)
        const convRate = stats.conversion_rate || 0;
        document.getElementById('conversionRate').textContent = `${convRate}%`;
        
        console.log('📊 Statystyki zaktualizowane:', stats);
    }
    
    /**
     * Zaktualizuj listę firm (Companies Tracking)
     */
    updateCompanyList(companies) {
        const container = document.getElementById('companyList');
        if (!container) return;
        
        // Sortuj po engagement score (najgorętsze na górze)
        companies.sort((a, b) => b.engagementScore - a.engagementScore);
        
        // Wyczyść listę
        container.innerHTML = '';
        
        // Dodaj firmy (top 10)
        companies.slice(0, 10).forEach(company => {
            const item = document.createElement('div');
            item.className = 'company-item';
            
            // Kolor engagement score
            let scoreColor = '#6b7280'; // gray
            if (company.engagementScore >= 70) scoreColor = '#ef4444'; // red (HOT!)
            else if (company.engagementScore >= 50) scoreColor = '#f59e0b'; // orange (warm)
            else if (company.engagementScore >= 30) scoreColor = '#3b82f6'; // blue (interested)
            
            // Emoji zainteresowania
            let heatEmoji = '🔥🔥🔥'; // bardzo gorący
            if (company.engagementScore < 70) heatEmoji = '🔥🔥';
            if (company.engagementScore < 50) heatEmoji = '🔥';
            if (company.engagementScore < 30) heatEmoji = '👀';
            
            item.innerHTML = `
                <div class="company-header">
                    <div class="company-name">
                        <strong>${company.name}</strong>
                        <span class="company-location">${company.city}, ${company.country}</span>
                    </div>
                    <div class="engagement-badge" style="background: ${scoreColor}20; color: ${scoreColor};">
                        ${heatEmoji} ${company.engagementScore}/100
                    </div>
                </div>
                <div class="company-stats">
                    <span>📊 ${company.totalQueries} zapytań</span>
                    <span>✅ ${company.highIntentQueries} high-intent</span>
                    <span>❌ ${company.lostOpportunities} utraconych okazji</span>
                </div>
                <div class="company-latest">
                    Ostatnie: "${company.queries[company.queries.length - 1]}"
                </div>
            `;
            
            container.appendChild(item);
        });
        
        console.log(`🏢 Zaktualizowano listę firm: ${companies.length} firm`);
    }
    
    /**
     * Zaktualizuj aktywne sesje (kto jest TERAZ na stronie)
     */
    updateActiveSessions(sessions) {
        const container = document.getElementById('sessionList');
        if (!container) return;
        
        container.innerHTML = '';
        
        if (!sessions || sessions.length === 0) {
            container.innerHTML = '<div class="no-sessions">Brak aktywnych sesji</div>';
            return;
        }
        
        sessions.forEach(session => {
            const item = document.createElement('div');
            item.className = 'session-item';
            
            // Czas trwania sesji
            const duration = this.formatDuration(session.duration || 0);
            
            // Status
            let statusEmoji = '👀'; // ogląda
            if (session.queries > 3) statusEmoji = '🔥'; // bardzo aktywny
            if (session.has_high_intent) statusEmoji = '✅'; // znalazł co chciał
            if (session.has_lost_opportunity) statusEmoji = '❌'; // nie znalazł
            
            item.innerHTML = `
                <div class="session-header">
                    <span class="session-id">${statusEmoji} ${session.company || session.city || 'Unknown'}</span>
                    <span class="session-duration">${duration}</span>
                </div>
                <div class="session-summary">${this.generateSessionSummary(session)}</div>
            `;
            
            container.appendChild(item);
        });
        
        console.log(`⏱️ Aktywne sesje: ${sessions.length}`);
    }
    
    /**
     * Wygeneruj podsumowanie sesji (co user robił)
     */
    generateSessionSummary(session) {
        const parts = [];
        
        if (session.queries > 0) {
            parts.push(`Zadał ${session.queries} pytań`);
        }
        
        if (session.has_high_intent) {
            parts.push('znalazł produkty');
        }
        
        if (session.has_lost_opportunity) {
            parts.push('nie znalazł tego czego szukał');
        }
        
        if (session.latest_query) {
            parts.push(`ostatnie: "${session.latest_query}"`);
        }
        
        return parts.join(' → ') || 'Przegląda stronę';
    }
    
    /**
     * Zaktualizuj wykres klasyfikacji zapytań
     */
    updateClassificationChart(classification) {
        const ctx = document.getElementById('classificationChart');
        if (!ctx) return;
        
        // Usuń stary wykres jeśli istnieje (FIX: sprawdź czy to Chart instance)
        if (window.classificationChart && window.classificationChart instanceof Chart) {
            window.classificationChart.destroy();
        }
        
        // Dane do wykresu
        const data = {
            labels: ['Znalezione Produkty', 'Utracone Okazje', 'Odfiltrowane'],
            datasets: [{
                data: [
                    classification.found || 0,
                    classification.lost || 0,
                    classification.filtered || 0
                ],
                backgroundColor: [
                    '#10b981', // zielony
                    '#ef4444', // czerwony
                    '#6b7280'  // szary
                ],
                borderWidth: 0
            }]
        };
        
        // Stwórz wykres
        window.classificationChart = new Chart(ctx, {
            type: 'doughnut',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            font: {
                                size: 12,
                                family: 'Inter'
                            }
                        }
                    }
                }
            }
        });
        
        console.log('📊 Wykres zaktualizowany:', classification);
    }
    
    /**
     * Zaktualizuj listę HOT LEADS
     */
    updateHotLeadsList() {
        const container = document.getElementById('hotLeadsList');
        if (!container) return;
        
        container.innerHTML = '';
        
        this.hotLeads.slice(0, 5).forEach(lead => {
            const item = document.createElement('div');
            item.className = 'hot-lead-item';
            
            const timeAgo = this.timeAgo(lead.timestamp);
            
            item.innerHTML = `
                <div class="hot-lead-header">
                    <strong>🔥 ${lead.company}</strong>
                    <span class="hot-lead-time">${timeAgo}</span>
                </div>
                <div class="hot-lead-query">"${lead.query}"</div>
                ${lead.estimatedValue > 0 ? `<div class="hot-lead-value">Potencjalna wartość: ${lead.estimatedValue} zł</div>` : ''}
            `;
            
            container.appendChild(item);
        });
    }
    
    /**
     * Odśwież statystyki (co 30s)
     */
    async refreshStats() {
        console.log('🔄 Odświeżam statystyki...');
        await this.loadTodayData();
    }
    
    /**
     * Zwiększ licznik odwiedzających
     */
    incrementVisitorCount() {
        const el = document.getElementById('totalSessions');
        if (el) {
            const current = parseInt(el.textContent) || 0;
            el.textContent = current + 1;
        }
    }
    
    /**
     * Pokaż notyfikację
     */
    showNotification(message, type = 'info', duration = 5000) {
        const container = document.getElementById('notificationContainer');
        if (!container) {
            console.log(`📢 ${message}`);
            return;
        }
        
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        
        container.appendChild(notification);
        
        // Auto remove
        setTimeout(() => {
            notification.remove();
        }, duration);
    }
    
    /**
     * Status połączenia
     */
    updateConnectionStatus(status) {
        const indicator = document.getElementById('connectionStatus');
        if (!indicator) return;
        
        if (status === 'connected') {
            indicator.textContent = '🟢 Tracking Active';
            indicator.style.color = '#10b981';
        } else {
            indicator.textContent = '🔴 Disconnected';
            indicator.style.color = '#ef4444';
        }
    }
    
    /**
     * Formatuj czas trwania (sekundy → MM:SS)
     */
    formatDuration(seconds) {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}:${secs.toString().padStart(2, '0')}`;
    }
    
    /**
     * Ile czasu temu (timestamp → "2 min temu")
     */
    timeAgo(timestamp) {
        const seconds = Math.floor((new Date() - timestamp) / 1000);
        
        if (seconds < 60) return 'Teraz';
        if (seconds < 3600) return `${Math.floor(seconds / 60)} min temu`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)} h temu`;
        return `${Math.floor(seconds / 86400)} dni temu`;
    }

    /**
     * DODANE: Renderuj Live Feed event
     */
    addLiveFeedEvent(data) {
        const liveFeed = document.getElementById('liveFeed');
        if (!liveFeed) return;
        
        // Usuń placeholder jeśli istnieje
        const placeholder = liveFeed.querySelector('[style*="Czekam"]');
        if (placeholder) {
            liveFeed.innerHTML = '';
        }
        
        // Klasyfikacja → CSS class
        const classMap = {
            'ZNALEZIONE PRODUKTY': 'classification-found',
            'UTRACONE OKAZJE': 'classification-lost',
            'ODFILTROWANE': 'classification-filtered'
        };
        
        const cssClass = classMap[data.classification] || 'classification-filtered';
        
        // Stwórz element
        const feedItem = document.createElement('div');
        feedItem.className = 'feed-item';
        feedItem.innerHTML = `
            <div class="feed-timestamp">${data.timestamp || new Date().toLocaleTimeString('pl-PL')}</div>
            <div class="feed-query">${this.escapeHtml(data.query)}</div>
            <span class="feed-classification ${cssClass}">${data.classification}</span>
        `;
        
        // Dodaj na górę
        liveFeed.insertBefore(feedItem, liveFeed.firstChild);
        
        // Ogranicz do 20 najnowszych
        while (liveFeed.children.length > 20) {
            liveFeed.removeChild(liveFeed.lastChild);
        }
    }
    
    /**
     * Escape HTML (bezpieczeństwo)
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// 🚀 URUCHOM DASHBOARD automatycznie
document.addEventListener('DOMContentLoaded', () => {
    console.log('🎯 Inicjalizuję Admin Dashboard...');
    window.adminDashboard = new AdminDashboard();
});
