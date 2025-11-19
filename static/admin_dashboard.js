/**
 * 🎯 ADMIN DASHBOARD v3.0 - SERVER-SIDE STORAGE
 * 
 * ZMIANY:
 * ✅ Hot Leads zapisywane na serwerze (nie localStorage)
 * ✅ Companies zapisywane na serwerze (nie localStorage)
 * ✅ Log History zapisywany na serwerze (nie localStorage)
 * ✅ RODO compliant - dane na backendzie
 */

class AdminDashboard {
    constructor() {
        console.log('🎯 ADMIN DASHBOARD v3.0: Server-side storage enabled...');
        
        // Dane
        this.companies = new Map();        
        this.activeSessions = [];          
        this.todayStats = {                
            totalVisitors: 0,
            totalSessions: 0,
            avgDuration: 0,
            conversionRate: 0
        };
        
        this.hotLeads = [];                
        this.logHistory = [];              
        this.socket = null;
        
        // Start!
        this.initialize();
    }
    
    /**
     * ============================================
     * SERVER-SIDE STORAGE METHODS (zastępują localStorage)
     * ============================================
     */
    
    /**
     * Załaduj HOT LEADS z serwera
     */
    async loadHotLeadsFromServer() {
        try {
            const response = await fetch('/api/admin/load-state/hot_leads');
            const result = await response.json();
            
            if (result.status === 'success' && result.data) {
                this.hotLeads = result.data;
                
                // Konwertuj stringi z powrotem na Date
                this.hotLeads.forEach(lead => {
                    lead.timestamp = new Date(lead.timestamp);
                });
                
                console.log(`✅ Załadowano ${this.hotLeads.length} HOT LEADS z serwera`);
            } else {
                this.hotLeads = [];
                console.log('ℹ️ Brak zapisanych HOT LEADS na serwerze');
            }
        } catch (e) {
            console.error('❌ Błąd ładowania HOT LEADS z serwera:', e);
            this.hotLeads = [];
        }
    }
    
    /**
     * Zapisz HOT LEADS na serwer
     */
    async saveHotLeadsToServer() {
        try {
            const response = await fetch('/api/admin/save-state', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    state_key: 'hot_leads',
                    data: this.hotLeads
                })
            });
            
            const result = await response.json();
            
            if (result.status === 'success') {
                console.log('✅ HOT LEADS zapisane na serwerze');
            } else {
                console.error('❌ Błąd zapisywania HOT LEADS:', result.message);
            }
        } catch (e) {
            console.error('❌ Błąd zapisu HOT LEADS na serwer:', e);
        }
    }
    
    /**
     * Załaduj firmy z serwera
     */
    async loadCompaniesFromServer() {
        try {
            const response = await fetch('/api/admin/load-state/companies');
            const result = await response.json();
            
            if (result.status === 'success' && result.data && result.data.length > 0) {
                const companiesArray = result.data;
                
                companiesArray.forEach(company => {
                    // Konwertuj stringi z powrotem na Date
                    company.firstVisit = new Date(company.firstVisit);
                    company.lastVisit = new Date(company.lastVisit);
                    
                    // Konwertuj timestamps w queries
                    if (company.queries && Array.isArray(company.queries)) {
                        company.queries = company.queries.map(q => ({
                            ...q,
                            timestamp: new Date(q.timestamp)
                        }));
                    } else {
                        company.queries = [];
                    }
                    
                    this.companies.set(company.name, company);
                });
                
                console.log(`✅ Załadowano ${this.companies.size} firm z serwera`);
                
                // Renderuj firmy po załadowaniu
                this.updateCompanyList(Array.from(this.companies.values()));
            } else {
                console.log('ℹ️ Brak zapisanych firm na serwerze');
            }
        } catch (e) {
            console.error('❌ Błąd ładowania firm z serwera:', e);
            this.companies = new Map();
        }
    }
    
    /**
     * Zapisz firmy na serwer
     */
    async saveCompaniesToServer() {
        try {
            const companiesArray = Array.from(this.companies.values());
            
            const response = await fetch('/api/admin/save-state', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    state_key: 'companies',
                    data: companiesArray
                })
            });
            
            const result = await response.json();
            
            if (result.status === 'success') {
                console.log('✅ Firmy zapisane na serwerze');
            } else {
                console.error('❌ Błąd zapisywania firm:', result.message);
            }
        } catch (e) {
            console.error('❌ Błąd zapisu firm na serwer:', e);
        }
    }
    
    /**
     * Załaduj Log History z serwera
     */
    async loadLogHistoryFromServer() {
        try {
            const response = await fetch('/api/admin/load-state/log_history');
            const result = await response.json();
            
            if (result.status === 'success' && result.data) {
                this.logHistory = result.data;
                
                // Konwertuj stringi z powrotem na Date
                this.logHistory.forEach(log => {
                    log.timestamp = new Date(log.timestamp);
                });
                
                console.log(`✅ Załadowano ${this.logHistory.length} logów z serwera`);
                
                // Renderuj logi po załadowaniu
                this.renderLogHistory();
            } else {
                console.log('ℹ️ Brak zapisanych logów na serwerze');
            }
        } catch (e) {
            console.error('❌ Błąd ładowania logów z serwera:', e);
            this.logHistory = [];
        }
    }
    
    /**
     * Zapisz Log History na serwer
     */
    async saveLogHistoryToServer() {
        try {
            const response = await fetch('/api/admin/save-state', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    state_key: 'log_history',
                    data: this.logHistory
                })
            });
            
            const result = await response.json();
            
            if (result.status === 'success') {
                console.log('✅ Logi zapisane na serwerze');
            } else {
                console.error('❌ Błąd zapisywania logów:', result.message);
            }
        } catch (e) {
            console.error('❌ Błąd zapisu logów na serwer:', e);
        }
    }
    
    /**
     * ============================================
     * INICJALIZACJA
     * ============================================
     */
    
    async initialize() {
        console.log('📡 Łączę się z serwerem...');
        
        try {
            // NAJPIERW załaduj dane z serwera
            await this.loadHotLeadsFromServer();
            await this.loadCompaniesFromServer();
            await this.loadLogHistoryFromServer();
            
            // POTEM połącz WebSocket i załaduj dzisiejsze dane
            await this.connectWebSocket();
            await this.loadTodayData();
            
            // Przelicz metryki po załadowaniu
            this.updateVisitorStats({});
            
            // Odświeżaj co 30 sekund
            setInterval(() => this.refreshStats(), 30000);
            
            console.log('✅ ADMIN DASHBOARD v3.0 działa!');
            this.showNotification('Dashboard gotowy! (server-side storage)', 'success');
            
        } catch (error) {
            console.error('❌ Błąd uruchamiania:', error);
            this.showNotification('Błąd połączenia z serwerem', 'error');
        }
    }
    
    /**
     * Połącz WebSocket
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
            
            this.socket.on('connect', () => {
                console.log('✅ WebSocket połączony!');
                resolve();
            });
            
            this.socket.on('live_feed_update', (data) => {
                console.log('🔔 Nowy visitor!', data);
                this.handleNewVisitor(data);
            });
            
            this.socket.on('disconnect', () => {
                console.warn('⚠️ WebSocket rozłączony');
            });
            
            this.socket.on('connect_error', (error) => {
                console.error('❌ Błąd WebSocket:', error);
                reject(error);
            });
            
            setTimeout(() => {
                if (!this.socket.connected) {
                    reject(new Error('Timeout połączenia WebSocket'));
                }
            }, 10000);
        });
    }
    
    /**
     * Załaduj dane z dziś - MERGE z danymi z serwera
     */
    async loadTodayData() {
        try {
            console.log('📊 Pobieram dane z ostatnich 24h...');
            
            const response = await fetch('/api/admin/visitor-stats');
            const data = await response.json();
            
            if (data.status === 'success') {
                console.log('✅ Dane pobrane z backendu:', data);
                
                // Aktualizuj statystyki
                this.updateVisitorStats(data.stats);
                
                // MERGE firm z backendu z danymi z serwera
                if (data.companies && data.companies.length > 0) {
                    console.log('🔄 Merguję dane z backendu z danymi z serwera...');
                    
                    data.companies.forEach(backendCompany => {
                        if (this.companies.has(backendCompany.name)) {
                            console.log(`  ↪ ${backendCompany.name} - używam danych z serwera`);
                        } else {
                            console.log(`  ➕ ${backendCompany.name} - dodaję z backendu`);
                            
                            backendCompany.firstVisit = new Date(backendCompany.firstVisit || Date.now());
                            backendCompany.lastVisit = new Date(backendCompany.lastVisit || Date.now());
                            
                            if (!backendCompany.queries) {
                                backendCompany.queries = [];
                            }
                            
                            this.companies.set(backendCompany.name, backendCompany);
                        }
                    });
                    
                    // Zapisz zmergowane firmy na serwerze
                    await this.saveCompaniesToServer();
                    
                    this.updateCompanyList(Array.from(this.companies.values()));
                }
                
                this.updateStatsWidget();
            }
        } catch (error) {
            console.error('❌ Błąd ładowania danych:', error);
        }
    }
    
    /**
     * ============================================
     * OBSŁUGA NOWYCH VISITORS (z WebSocket)
     * ============================================
     */
    
    handleNewVisitor(data) {
        console.log('👤 Nowy visitor:', data);
        
        const organization = data.organization || 'Unknown';
        
        if (organization === 'Unknown') {
            console.log('⚠️ Pomijam visitor bez organizacji');
            return;
        }
        
        // Zaktualizuj lub stwórz firmę
        if (this.companies.has(organization)) {
            const company = this.companies.get(organization);
            company.lastVisit = new Date();
            company.totalQueries = (company.totalQueries || 0) + 1;
            
            // Dodaj query do historii
            if (!company.queries) company.queries = [];
            company.queries.push({
                text: data.query || 'N/A',
                timestamp: new Date(),
                decision: data.decision || 'UNKNOWN'
            });
            
            // Update intent counters
            if (data.decision === 'ZNALEZIONE PRODUKTY') {
                company.highIntentQueries = (company.highIntentQueries || 0) + 1;
            } else if (data.decision === 'UTRACONE OKAZJE') {
                company.lostOpportunities = (company.lostOpportunities || 0) + 1;
            }
            
            // Przelicz engagement score
            company.engagementScore = Math.min(
                (company.totalQueries * 10) + 
                ((company.highIntentQueries || 0) * 20) + 
                ((company.lostOpportunities || 0) * 10),
                100
            );
            
            console.log(`✅ Zaktualizowano firmę: ${organization}`);
        } else {
            // Nowa firma
            const newCompany = {
                name: organization,
                city: data.city || 'Unknown',
                country: data.country || 'Unknown',
                firstVisit: new Date(),
                lastVisit: new Date(),
                totalQueries: 1,
                highIntentQueries: data.decision === 'ZNALEZIONE PRODUKTY' ? 1 : 0,
                lostOpportunities: data.decision === 'UTRACONE OKAZJE' ? 1 : 0,
                engagementScore: 10,
                queries: [{
                    text: data.query || 'N/A',
                    timestamp: new Date(),
                    decision: data.decision || 'UNKNOWN'
                }]
            };
            
            this.companies.set(organization, newCompany);
            console.log(`➕ Nowa firma dodana: ${organization}`);
        }
        
        // Zapisz na serwerze
        this.saveCompaniesToServer();
        
        // Sprawdź czy to HOT LEAD
        const company = this.companies.get(organization);
        if (company.engagementScore >= 50 && data.decision === 'ZNALEZIONE PRODUKTY') {
            this.addHotLead({
                company: organization,
                query: data.query || 'N/A',
                score: company.engagementScore,
                timestamp: new Date()
            });
        }
        
        // Dodaj do Log History
        this.addLogEntry({
            type: data.decision || 'UNKNOWN',
            company: organization,
            query: data.query || 'N/A',
            timestamp: new Date()
        });
        
        // Odśwież UI
        this.updateCompanyList(Array.from(this.companies.values()));
        this.updateStatsWidget();
        this.incrementVisitorCount();
        
        // Notyfikacja
        this.showNotification(`Nowy visitor: ${organization}`, 'info');
    }
    
    /**
     * Dodaj HOT LEAD
     */
    addHotLead(lead) {
        // Sprawdź czy już nie istnieje (po company name + timestamp w ostatnim 1h)
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        const exists = this.hotLeads.some(l => 
            l.company === lead.company && 
            new Date(l.timestamp) > oneHourAgo
        );
        
        if (!exists) {
            this.hotLeads.unshift(lead);
            
            // Ogranicz do 50 leadów
            if (this.hotLeads.length > 50) {
                this.hotLeads = this.hotLeads.slice(0, 50);
            }
            
            this.saveHotLeadsToServer();
            this.renderHotLeads();
            
            console.log('🔥 Dodano HOT LEAD:', lead.company);
        }
    }
    
    /**
     * Renderuj HOT LEADS
     */
    renderHotLeads() {
        const container = document.getElementById('hotLeadsContainer');
        if (!container) return;
        
        if (this.hotLeads.length === 0) {
            container.innerHTML = '<div class="empty-state">Brak hot leadów</div>';
            return;
        }
        
        container.innerHTML = this.hotLeads.map(lead => `
            <div class="hot-lead-item">
                <div class="lead-company">${this.escapeHtml(lead.company)}</div>
                <div class="lead-query">${this.escapeHtml(lead.query)}</div>
                <div class="lead-meta">
                    <span class="lead-score">🔥 ${lead.score}/100</span>
                    <span class="lead-time">${this.timeAgo(new Date(lead.timestamp))}</span>
                </div>
            </div>
        `).join('');
    }
    
    /**
     * Dodaj wpis do Log History
     */
    addLogEntry(entry) {
        this.logHistory.unshift(entry);
        
        // Ogranicz do 100 wpisów
        if (this.logHistory.length > 100) {
            this.logHistory = this.logHistory.slice(0, 100);
        }
        
        this.saveLogHistoryToServer();
        this.renderLogHistory();
    }
    
    /**
     * Renderuj Log History
     */
    renderLogHistory() {
        const container = document.getElementById('logHistoryContainer');
        if (!container) return;
        
        if (this.logHistory.length === 0) {
            container.innerHTML = '<div class="empty-state">Brak historii</div>';
            return;
        }
        
        // Pokaż ostatnie 20 wpisów
        const recentLogs = this.logHistory.slice(0, 20);
        
        container.innerHTML = recentLogs.map(log => {
            const typeClass = {
                'ZNALEZIONE PRODUKTY': 'log-success',
                'UTRACONE OKAZJE': 'log-warning',
                'ODFILTROWANE': 'log-info'
            }[log.type] || 'log-default';
            
            return `
                <div class="log-entry ${typeClass}">
                    <div class="log-header">
                        <span class="log-type">${log.type}</span>
                        <span class="log-time">${this.timeAgo(new Date(log.timestamp))}</span>
                    </div>
                    <div class="log-company">${this.escapeHtml(log.company)}</div>
                    <div class="log-query">${this.escapeHtml(log.query)}</div>
                </div>
            `;
        }).join('');
    }
    
    /**
     * ============================================
     * COMPANY LIST
     * ============================================
     */
    
    updateCompanyList(companies) {
        const tbody = document.getElementById('companiesTableBody');
        if (!tbody) return;
        
        if (companies.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Brak danych o firmach</td></tr>';
            return;
        }
        
        // Sortuj po engagement score (malejąco)
        companies.sort((a, b) => (b.engagementScore || 0) - (a.engagementScore || 0));
        
        tbody.innerHTML = companies.map(company => {
            const scoreClass = company.engagementScore >= 70 ? 'score-high' : 
                             company.engagementScore >= 40 ? 'score-medium' : 'score-low';
            
            return `
                <tr onclick="window.adminDashboard.showCompanyDetails('${this.escapeHtml(company.name)}')" 
                    style="cursor: pointer;">
                    <td><strong>${this.escapeHtml(company.name)}</strong></td>
                    <td>${this.escapeHtml(company.city)}</td>
                    <td>${company.totalQueries || 0}</td>
                    <td>${company.highIntentQueries || 0}</td>
                    <td>${company.lostOpportunities || 0}</td>
                    <td><span class="engagement-badge ${scoreClass}">${company.engagementScore || 0}/100</span></td>
                </tr>
            `;
        }).join('');
    }
    
    /**
     * Pokaż szczegóły firmy (modal)
     */
    showCompanyDetails(companyName) {
        const company = this.companies.get(companyName);
        if (!company) {
            console.error('Firma nie znaleziona:', companyName);
            return;
        }
        
        // Wypełnij modal danymi
        document.getElementById('modalCompanyName').textContent = company.name;
        document.getElementById('modalCity').textContent = company.city || 'Unknown';
        document.getElementById('modalCountry').textContent = company.country || 'Unknown';
        document.getElementById('modalFirstVisit').textContent = this.formatDate(company.firstVisit);
        document.getElementById('modalLastVisit').textContent = this.formatDate(company.lastVisit);
        document.getElementById('modalTotalQueries').textContent = company.totalQueries || 0;
        document.getElementById('modalHighIntent').textContent = company.highIntentQueries || 0;
        document.getElementById('modalLostOpp').textContent = company.lostOpportunities || 0;
        document.getElementById('modalEngagement').textContent = company.engagementScore || 0;
        
        // Renderuj queries
        const queriesContainer = document.getElementById('modalQueriesList');
        if (company.queries && company.queries.length > 0) {
            queriesContainer.innerHTML = company.queries
                .slice(0, 10) // Ostatnie 10 queries
                .map(q => `
                    <div class="query-item">
                        <div class="query-text">${this.escapeHtml(q.text || 'N/A')}</div>
                        <div class="query-meta">
                            <span class="query-decision">${q.decision || 'UNKNOWN'}</span>
                            <span class="query-time">${this.formatDate(q.timestamp)}</span>
                        </div>
                    </div>
                `).join('');
        } else {
            queriesContainer.innerHTML = '<div class="empty-state">Brak historii zapytań</div>';
        }
        
        // Pokaż modal
        const modal = document.getElementById('companyModal');
        modal.classList.add('active');
        
        console.log('✅ Pokazano szczegóły firmy:', companyName);
    }
    
    /**
     * ============================================
     * STATS WIDGET
     * ============================================
     */
    
    updateStatsWidget() {
        const companies = Array.from(this.companies.values());
        
        let hotCount = 0;
        let warmCount = 0;
        let coldCount = 0;
        let totalPotential = 0;
        
        companies.forEach(company => {
            const score = company.engagementScore || 0;
            const lostOpp = company.lostOpportunities || 0;
            
            // Szacunkowa wartość (500 zł za lost opportunity)
            totalPotential += lostOpp * 500;
            
            if (score >= 70) {
                hotCount++;
            } else if (score >= 40) {
                warmCount++;
            } else {
                coldCount++;
            }
        });
        
        const total = hotCount + warmCount + coldCount || 1;
        
        // Aktualizuj liczby
        const hotCountEl = document.getElementById('hotCount');
        const warmCountEl = document.getElementById('warmCount');
        const coldCountEl = document.getElementById('coldCount');
        
        if (hotCountEl) hotCountEl.textContent = hotCount;
        if (warmCountEl) warmCountEl.textContent = warmCount;
        if (coldCountEl) coldCountEl.textContent = coldCount;
        
        // Aktualizuj paski
        const hotBar = document.getElementById('hotBar');
        const warmBar = document.getElementById('warmBar');
        const coldBar = document.getElementById('coldBar');
        
        if (hotBar) hotBar.style.width = `${(hotCount / total) * 100}%`;
        if (warmBar) warmBar.style.width = `${(warmCount / total) * 100}%`;
        if (coldBar) coldBar.style.width = `${(coldCount / total) * 100}%`;
        
        // Aktualizuj potencjał
        const totalPotentialEl = document.getElementById('totalPotential');
        if (totalPotentialEl) {
            totalPotentialEl.textContent = `${totalPotential.toLocaleString('pl-PL')} zł`;
        }
        
        console.log('🌡️ Stats Widget:', { hotCount, warmCount, coldCount, totalPotential });
    }
    
    /**
     * Policz metryki lokalnie
     */
    calculateLocalStats() {
        const companies = Array.from(this.companies.values());
        const now = new Date();
        const fifteenMinutesAgo = new Date(now - 15 * 60 * 1000);
        
        // Aktywni użytkownicy (ostatnie 15 min)
        let activeUsers = 0;
        companies.forEach(company => {
            const lastVisit = new Date(company.lastVisit);
            if (lastVisit > fifteenMinutesAgo) {
                activeUsers++;
            }
        });
        
        // Sesje dziś
        let totalQueries = 0;
        companies.forEach(company => {
            totalQueries += company.totalQueries || 0;
        });
        
        // Średni czas sesji (estimate)
        let avgDuration = 0;
        if (companies.length > 0) {
            const totalDuration = companies.reduce((sum, company) => {
                const estimatedSeconds = (company.totalQueries || 0) * 45;
                return sum + estimatedSeconds;
            }, 0);
            avgDuration = Math.round(totalDuration / companies.length);
        }
        
        // Conversion rate
        let totalHighIntent = 0;
        companies.forEach(company => {
            totalHighIntent += company.highIntentQueries || 0;
        });
        
        let conversionRate = 0;
        if (totalQueries > 0) {
            conversionRate = Math.round((totalHighIntent / totalQueries) * 100);
        }
        
        return {
            active_now: activeUsers,
            sessions_today: totalQueries,
            avg_duration: avgDuration,
            conversion_rate: conversionRate
        };
    }
    
    /**
     * Zaktualizuj Visitor Stats
     */
    updateVisitorStats(backendStats) {
        const localStats = this.calculateLocalStats();
        
        const stats = {
            active_now: localStats.active_now,
            sessions_today: localStats.sessions_today,
            avg_duration: localStats.avg_duration,
            conversion_rate: localStats.conversion_rate
        };
        
        // Aktualizuj UI
        const activeEl = document.getElementById('activeVisitors');
        const sessionsEl = document.getElementById('totalSessions');
        const durationEl = document.getElementById('avgDuration');
        const convEl = document.getElementById('conversionRate');
        
        if (activeEl) activeEl.textContent = stats.active_now || 0;
        if (sessionsEl) sessionsEl.textContent = stats.sessions_today || 0;
        
        if (durationEl) {
            const avgMinutes = Math.floor((stats.avg_duration || 0) / 60);
            const avgSeconds = (stats.avg_duration || 0) % 60;
            durationEl.textContent = `${avgMinutes}:${avgSeconds.toString().padStart(2, '0')}`;
        }
        
        if (convEl) {
            const convRate = stats.conversion_rate || 0;
            convEl.textContent = `${convRate}%`;
        }
    }
    
    /**
     * Odśwież statystyki
     */
    async refreshStats() {
        console.log('🔄 Odświeżam statystyki...');
        
        try {
            const response = await fetch('/api/admin/visitor-stats');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.updateVisitorStats(data.stats);
            }
        } catch (error) {
            console.error('❌ Błąd odświeżania:', error);
        }
        
        this.updateStatsWidget();
    }
    
    /**
     * Zwiększ licznik
     */
    incrementVisitorCount() {
        const el = document.getElementById('totalSessions');
        if (el) {
            const current = parseInt(el.textContent) || 0;
            el.textContent = current + 1;
        }
    }
    
    /**
     * ============================================
     * UTILITIES
     * ============================================
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
        
        setTimeout(() => {
            notification.remove();
        }, duration);
    }
    
    formatDuration(seconds) {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}:${secs.toString().padStart(2, '0')}`;
    }
    
    formatDate(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleString('pl-PL', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        });
    }
    
    timeAgo(timestamp) {
        const seconds = Math.floor((new Date() - timestamp) / 1000);
        
        if (seconds < 60) return 'Teraz';
        if (seconds < 3600) return `${Math.floor(seconds / 60)} min temu`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)} h temu`;
        return `${Math.floor(seconds / 86400)} dni temu`;
    }
    
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// 🚀 URUCHOM DASHBOARD
document.addEventListener('DOMContentLoaded', () => {
    console.log('🎯 Inicjalizuję Admin Dashboard v3.0 (server-side storage)...');
    window.adminDashboard = new AdminDashboard();
});

// GLOBAL FUNCTION: Close Modal
function closeCompanyModal() {
    const modal = document.getElementById('companyModal');
    if (modal) {
        modal.classList.remove('active');
        console.log('✅ Modal zamknięty');
    }
}
