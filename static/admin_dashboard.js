/**
 * 🎯 ADMIN DASHBOARD v2.1 - FIXED
 * 
 * POPRAWKI:
 * - Modal działa (event listener fix)
 * - Log History persistence (localStorage)
 * - Pomarańczowa ramka Hot Leads
 */

class AdminDashboard {
    constructor() {
        console.log('🎯 ADMIN DASHBOARD v2.1: Uruchamiam zmodernizowane centrum dowodzenia...');
        
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
        
        // Załaduj zapisane dane
        this.loadHotLeadsFromStorage();
        this.loadCompaniesFromStorage();
        this.loadLogHistoryFromStorage();  // NOWE: Persistence logów
        
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
            }
        } catch (e) {
            console.error('❌ Błąd ładowania HOT LEADS:', e);
            this.hotLeads = [];
        }
    }
    
    /**
 * Załaduj firmy z localStorage - FIXED
 */
loadCompaniesFromStorage() {
    try {
        const stored = localStorage.getItem('companies');
        if (stored) {
            const companiesArray = JSON.parse(stored);
            
            companiesArray.forEach(company => {
                // KONWERTUJ stringi z powrotem na Date (dla wyświetlania)
                company.firstVisit = new Date(company.firstVisit);
                company.lastVisit = new Date(company.lastVisit);
                
                // CRITICAL: Konwertuj timestamps w queries
                if (company.queries && Array.isArray(company.queries)) {
                    company.queries = company.queries.map(q => ({
                        ...q,
                        timestamp: new Date(q.timestamp)
                    }));
                } else {
                    company.queries = []; // Fallback jeśli brak queries
                }
                
                this.companies.set(company.name, company);
            });
            
            console.log(`✅ Załadowano ${this.companies.size} firm z localStorage`);
            console.log(`📊 Przykładowa firma:`, Array.from(this.companies.values())[0]);
            
            // Renderuj firmy po załadowaniu
            this.updateCompanyList(Array.from(this.companies.values()));
        }
    } catch (e) {
        console.error('❌ Błąd ładowania firm:', e);
        this.companies = new Map();
    }
}
    
    /**
     * NOWE: Załaduj Log History z localStorage
     */
    loadLogHistoryFromStorage() {
        try {
            const stored = localStorage.getItem('logHistory');
            if (stored) {
                this.logHistory = JSON.parse(stored);
                this.logHistory.forEach(log => {
                    log.timestamp = new Date(log.timestamp);
                });
                console.log(`✅ Załadowano ${this.logHistory.length} logów z localStorage`);
                
                // Renderuj logi po załadowaniu
                this.renderLogHistory();
            }
        } catch (e) {
            console.error('❌ Błąd ładowania logów:', e);
            this.logHistory = [];
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
     * Zapisz firmy do localStorage
     */
    saveCompaniesToStorage() {
        try {
            const companiesArray = Array.from(this.companies.values());
            localStorage.setItem('companies', JSON.stringify(companiesArray));
        } catch (e) {
            console.error('❌ Błąd zapisywania firm:', e);
        }
    }
    
    /**
     * NOWE: Zapisz Log History do localStorage
     */
    saveLogHistoryToStorage() {
        try {
            localStorage.setItem('logHistory', JSON.stringify(this.logHistory));
        } catch (e) {
            console.error('❌ Błąd zapisywania logów:', e);
        }
    }
    
    /**
     * KROK 1: Uruchom wszystko
     */
    async initialize() {
    console.log('📡 Łączę się z serwerem...');
    
    try {
        await this.connectWebSocket();
        await this.loadTodayData();
        
        // NOWE: Przelicz metryki po załadowaniu
        this.updateVisitorStats({});
        
        // Odświeżaj co 30 sekund
        setInterval(() => this.refreshStats(), 30000);
        
        console.log('✅ ADMIN DASHBOARD v2.1 działa!');
        this.showNotification('Dashboard gotowy!', 'success');
        
    } catch (error) {
        console.error('❌ Błąd uruchamiania:', error);
        this.showNotification('Błąd połączenia z serwerem', 'error');
    }
}
    
    /**
     * KROK 2: Połącz WebSocket
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
    /**
 * KROK 3: Załaduj dane z dziś - FIXED (merge zamiast overwrite)
 */
async loadTodayData() {
    try {
        console.log('📊 Pobieram dane z ostatnich 24h...');
        
        const response = await fetch('/api/admin/visitor-stats');
        const data = await response.json();
        
        if (data.status === 'success') {
            console.log('✅ Dane pobrane z backendu:', data);
            
            // Aktualizuj statystyki (to OK)
            this.updateVisitorStats(data.stats);
            
            // CRITICAL: NIE nadpisuj firm! Merge z localStorage
            if (data.companies && data.companies.length > 0) {
                console.log('🔄 Merguję dane z backendu z localStorage...');
                
                data.companies.forEach(backendCompany => {
                    if (this.companies.has(backendCompany.name)) {
                        // Firma już jest w localStorage - zostaw localStorage!
                        console.log(`  ↪ ${backendCompany.name} - używam danych z localStorage`);
                    } else {
                        // Nowa firma z backendu - dodaj
                        console.log(`  ➕ ${backendCompany.name} - dodaję z backendu`);
                        
                        // Konwertuj daty
                        backendCompany.firstVisit = new Date(backendCompany.firstVisit || Date.now());
                        backendCompany.lastVisit = new Date(backendCompany.lastVisit || Date.now());
                        
                        // Konwertuj queries
                        if (backendCompany.queries && Array.isArray(backendCompany.queries)) {
                            backendCompany.queries = backendCompany.queries.map(q => ({
                                ...q,
                                timestamp: new Date(q.timestamp || Date.now())
                            }));
                        } else {
                            backendCompany.queries = [];
                        }
                        
                        this.companies.set(backendCompany.name, backendCompany);
                    }
                });
            }
            
            // TERAZ renderuj (localStorage ma priorytet!)
            this.updateCompanyList(Array.from(this.companies.values()));
            
            // Aktualizuj sesje
            this.updateActiveSessions(data.active_sessions);
            
            // Odśwież Stats Widget po merge
            this.updateStatsWidget();
            
        } else {
            throw new Error(data.message || 'Błąd pobierania danych');
        }
        
    } catch (error) {
        console.error('❌ Błąd ładowania danych:', error);
        
        // Jeśli backend nie działa - używaj TYLKO localStorage
        console.log('⚠️ Backend niedostępny - używam tylko localStorage');
        this.updateCompanyList(Array.from(this.companies.values()));
        this.updateStatsWidget();
    }
}
    
    /**
     * 🔔 NOWY VISITOR!
     */
    handleNewVisitor(data) {
    console.log('👤 Nowy visitor:', {
        firma: data.organization,
        miasto: data.city,
        zapytanie: data.query,
        klasyfikacja: data.classification
    });
    
    // 1. Dodaj do Log History
    this.addToLogHistory(data);
    
    // 2. Pokaż w Live Feed Bar
    this.showLiveFeedNotification(data);
    
    // 3. Dodaj firmę do listy
    this.trackCompany(data);
    
    // 4. Sprawdź czy to HOT LEAD
    if (this.isHotLead(data)) {
        this.showHotLeadAlert(data);
    }
    
    // 5. Zaktualizuj Stats Widget
    this.updateStatsWidget();
    
    // NOWE: 6. Odśwież Visitor Analytics (live!)
    this.updateVisitorStats({}); // Pusty obiekt - używamy lokalnych danych
    
    // 7. Odśwież liczby
    this.incrementVisitorCount();
}
    
    /**
     * Dodaj do Log History + SAVE
     */
    addToLogHistory(data) {
        const logEntry = {
            timestamp: new Date(),
            query: data.query,
            company: data.organization || data.city || 'Unknown',
            classification: data.classification
        };
        
        this.logHistory.unshift(logEntry);
        this.logHistory = this.logHistory.slice(0, 100); // Ostatnie 100
        
        // ZAPISZ DO localStorage
        this.saveLogHistoryToStorage();
        
        // Renderuj
        this.renderLogHistory();
    }
    
    /**
     * Renderuj Log History
     */
    renderLogHistory() {
        const container = document.getElementById('logHistoryList');
        if (!container) return;
        
        container.innerHTML = '';
        
        if (this.logHistory.length === 0) {
            container.innerHTML = '<div style="text-align: center; color: #9ca3af; padding: 20px; font-size: 12px;">Czekam na pierwsze zdarzenia...</div>';
            return;
        }
        
        this.logHistory.slice(0, 20).forEach(log => {
            const item = document.createElement('div');
            item.className = 'log-item';
            
            const time = log.timestamp.toLocaleTimeString('pl-PL');
            
            item.innerHTML = `
                <div class="log-timestamp">${time}</div>
                <div class="log-query">"${this.escapeHtml(log.query)}"</div>
                <div class="log-company">📍 ${this.escapeHtml(log.company)}</div>
            `;
            
            container.appendChild(item);
        });
    }
    
    /**
     * Pokaż Live Feed Notification Bar
     */
    showLiveFeedNotification(data) {
        const bar = document.getElementById('liveFeedBar');
        const text = document.getElementById('liveFeedText');
        
        if (!bar || !text) return;
        
        const company = data.organization || data.city || 'Unknown';
        text.textContent = `${company} - "${data.query}"`;
        
        bar.classList.add('active');
        
        setTimeout(() => {
            bar.classList.remove('active');
        }, 5000);
    }
    
    /**
 * Śledź firmę - FIXED VERSION
 */
trackCompany(data) {
    const companyName = data.organization || 'Unknown';
    
    if (companyName === 'Unknown') return;
    
    if (!this.companies.has(companyName)) {
        // NOWA FIRMA
        const newCompany = {
            name: companyName,
            city: data.city || 'Unknown',
            country: data.country || 'Unknown',
            firstVisit: new Date().toISOString(), // ZMIANA: String zamiast Date
            lastVisit: new Date().toISOString(),  // ZMIANA: String zamiast Date
            totalQueries: 1,
            queries: [{
                query: data.query,
                timestamp: new Date().toISOString(), // ZMIANA: String zamiast Date
                classification: data.classification || 'UNKNOWN',
                estimatedValue: data.estimatedValue || 0
            }],
            highIntentQueries: data.classification === 'ZNALEZIONE PRODUKTY' ? 1 : 0,
            lostOpportunities: data.classification === 'UTRACONE OKAZJE' ? 1 : 0,
            engagementScore: this.calculateEngagementScore(data)
        };
        
        this.companies.set(companyName, newCompany);
        console.log(`🆕 Nowa firma: ${companyName} (${data.city})`);
        
    } else {
        // FIRMA JUŻ ISTNIEJE - UPDATE
        const company = this.companies.get(companyName);
        
        // Update podstawowych danych
        company.lastVisit = new Date().toISOString(); // ZMIANA: String
        company.totalQueries++;
        
        // CRITICAL: Dodaj nowe query
        const newQuery = {
            query: data.query,
            timestamp: new Date().toISOString(), // ZMIANA: String
            classification: data.classification || 'UNKNOWN',
            estimatedValue: data.estimatedValue || 0
        };
        
        company.queries.push(newQuery);
        
        // Update counters
        if (data.classification === 'ZNALEZIONE PRODUKTY') {
            company.highIntentQueries++;
        }
        if (data.classification === 'UTRACONE OKAZJE') {
            company.lostOpportunities++;
        }
        
        // Recalculate engagement
        company.engagementScore = this.calculateEngagementScore(data, company);
        
        console.log(`🔄 Firma wraca: ${companyName} (${company.totalQueries} zapytań, ${company.queries.length} w tablicy)`);
    }
    
    // CRITICAL: Zapisz natychmiast!
    this.saveCompaniesToStorage();
    
    // Odśwież UI
    this.updateCompanyList(Array.from(this.companies.values()));
}
    /**
     * Czy to HOT LEAD?
     */
    isHotLead(data) {
        const bigCompanies = ['Google', 'Microsoft', 'Amazon', 'Facebook', 'Apple', 'Orange', 'PKN', 'PZU'];
        if (bigCompanies.some(big => data.organization?.includes(big))) {
            return true;
        }
        
        const company = this.companies.get(data.organization);
        if (company && company.totalQueries >= 3) {
            return true;
        }
        
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
        
        this.showNotification(
            `🔥 HOT LEAD: ${companyName} właśnie szukał: "${query}"`,
            'hot-lead',
            10000
        );
        
        const existingLead = this.hotLeads.find(lead => lead.company === companyName);
        
        if (existingLead) {
            existingLead.queries = existingLead.queries || [];
            existingLead.queries.push(query);
            existingLead.lastQuery = query;
            existingLead.timestamp = new Date();
            existingLead.totalQueries = (existingLead.totalQueries || 0) + 1;
            existingLead.estimatedValue = (existingLead.estimatedValue || 0) + (data.estimatedValue || 0);
        } else {
            this.hotLeads.unshift({
                company: companyName,
                city: data.city,
                query: query,
                lastQuery: query,
                queries: [query],
                totalQueries: 1,
                timestamp: new Date(),
                estimatedValue: data.estimatedValue || 0
            });
        }
        
        this.hotLeads = this.hotLeads.slice(0, 10);
        this.saveHotLeadsToStorage();
    }
    
    /**
     * Oblicz engagement score
     */
    calculateEngagementScore(data, existingCompany = null) {
        let score = 0;
        
        if (existingCompany) {
            score += Math.min(existingCompany.totalQueries * 10, 40);
        } else {
            score += 10;
        }
        
        if (data.classification === 'ZNALEZIONE PRODUKTY') {
            score += 30;
        }
        
        if (data.classification === 'UTRACONE OKAZJE') {
            score += 20;
        }
        
        if (data.estimatedValue > 500) {
            score += 10;
        }
        
        return Math.min(score, 100);
    }
    
    /**
     * FIXED: Zaktualizuj listę firm Z DZIAŁAJĄCYM MODALEM
     */
    updateCompanyList(companies) {
        const container = document.getElementById('hotLeadsCompanies');
        if (!container) {
            console.warn('⚠️ Container hotLeadsCompanies nie znaleziony!');
            return;
        }
        
        // Sortuj po engagement score
        companies.sort((a, b) => b.engagementScore - a.engagementScore);
        
        container.innerHTML = '';
        
        if (companies.length === 0) {
            container.innerHTML = `
                <div class="no-companies">
                    📡 Brak firm do wyświetlenia<br>
                    <small style="color: #9ca3af; margin-top: 8px; display: block;">Czekam na pierwsze odwiedziny</small>
                </div>
            `;
            return;
        }
        
        // Top 20 firm
        companies.slice(0, 20).forEach((company, index) => {
            const card = document.createElement('div');
            card.className = 'company-card';
            
            // CRITICAL: Dodaj data-company-index dla modalа
            card.setAttribute('data-company-index', index);
            
            // Kolor engagement score
            let scoreColor = '#6b7280';
            if (company.engagementScore >= 70) scoreColor = '#ef4444';
            else if (company.engagementScore >= 50) scoreColor = '#f59e0b';
            else if (company.engagementScore >= 30) scoreColor = '#3b82f6';
            
            // Emoji zainteresowania
            let heatEmoji = '🔥🔥🔥';
            if (company.engagementScore < 70) heatEmoji = '🔥🔥';
            if (company.engagementScore < 50) heatEmoji = '🔥';
            if (company.engagementScore < 30) heatEmoji = '👀';
            
            // Ostatnie zapytanie (bezpiecznie)
            const lastQuery = company.queries && company.queries.length > 0 
                ? company.queries[company.queries.length - 1].query 
                : 'Brak zapytań';
            
            card.innerHTML = `
                <div class="company-header">
                    <div class="company-name">
                        <strong>${this.escapeHtml(company.name)}</strong>
                        <span class="company-location">${this.escapeHtml(company.city)}, ${this.escapeHtml(company.country)}</span>
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
                    Ostatnie: "${this.escapeHtml(lastQuery)}"
                </div>
            `;
            
            // FIXED: Użyj onclick z globalną funkcją
            card.onclick = () => {
                console.log('🖱️ Kliknięto kartę firmy:', company.name);
                window.adminDashboard.openCompanyModal(company);
            };
            
            container.appendChild(card);
        });
        
        console.log(`🏢 Zaktualizowano listę firm: ${companies.length} firm`);
    }
    
    /**
 * Otwórz modal - Z DEBUGOWANIEM
 */
openCompanyModal(company) {
    console.log('📂 Otwieranie modala dla:', company.name);
    console.log('📋 Queries w firmie:', company.queries);
    console.log('📊 Liczba queries:', company.queries?.length);
    
    // Sprawdź czy modal istnieje
    const modal = document.getElementById('companyModal');
    if (!modal) {
        console.error('❌ Modal nie znaleziony w DOM!');
        return;
    }
    
    // Ustaw tytuł
    const modalTitle = document.getElementById('modalCompanyName');
    const modalLocation = document.getElementById('modalCompanyLocation');
    
    if (modalTitle) modalTitle.textContent = company.name;
    if (modalLocation) modalLocation.textContent = `${company.city}, ${company.country}`;
    
    // Ustaw statystyki
    const modalTotal = document.getElementById('modalTotalQueries');
    const modalIntent = document.getElementById('modalHighIntent');
    const modalLost = document.getElementById('modalLostOpp');
    
    if (modalTotal) modalTotal.textContent = company.totalQueries;
    if (modalIntent) modalIntent.textContent = company.highIntentQueries;
    if (modalLost) modalLost.textContent = company.lostOpportunities;
    
    // Renderuj listę zapytań
    const queriesList = document.getElementById('modalQueriesList');
    if (!queriesList) {
        console.error('❌ modalQueriesList nie znaleziony!');
        return;
    }
    
    queriesList.innerHTML = '';
    
    if (!company.queries || company.queries.length === 0) {
        console.warn('⚠️ Firma nie ma queries!');
        queriesList.innerHTML = '<div style="text-align: center; color: #9ca3af; padding: 20px;">Brak zapytań w historii</div>';
    } else {
        console.log(`✅ Renderuję ${company.queries.length} zapytań`);
        
        // Od najnowszych
        const sortedQueries = [...company.queries].reverse();
        
        sortedQueries.forEach((q, index) => {
            console.log(`  Query ${index + 1}:`, q);
            
            const item = document.createElement('div');
            item.className = 'query-item';
            
            const timestamp = new Date(q.timestamp).toLocaleString('pl-PL');
            
            // Klasyfikacja CSS
            const classMap = {
                'ZNALEZIONE PRODUKTY': 'classification-found',
                'UTRACONE OKAZJE': 'classification-lost',
                'ODFILTROWANE': 'classification-filtered'
            };
            const cssClass = classMap[q.classification] || 'classification-filtered';
            
            item.innerHTML = `
                <div class="query-timestamp">⏱️ ${timestamp}</div>
                <div class="query-text">"${this.escapeHtml(q.query)}"</div>
                <span class="query-classification ${cssClass}">${q.classification}</span>
                ${q.estimatedValue > 0 ? `<span style="margin-left: 8px; font-size: 11px; color: #10b981; font-weight: 600;">💰 ${q.estimatedValue} zł</span>` : ''}
            `;
            
            queriesList.appendChild(item);
        });
    }
    
    // Pokaż modal
    modal.classList.add('active');
    console.log('✅ Modal otwarty!');
}
    
    /**
     * Zaktualizuj Stats Widget
     */
    updateStatsWidget() {
        const companies = Array.from(this.companies.values());
        
        let hotCount = 0;
        let warmCount = 0;
        let coldCount = 0;
        let totalPotential = 0;
        
        companies.forEach(company => {
            // Policz potencjał
            if (company.queries) {
                company.queries.forEach(q => {
                    if (q.classification === 'UTRACONE OKAZJE' && q.estimatedValue) {
                        totalPotential += q.estimatedValue;
                    }
                });
            }
            
            // Klasyfikuj
            if (company.totalQueries >= 5) {
                hotCount++;
            } else if (company.totalQueries >= 2) {
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
 * NOWE: Policz metryki lokalnie (z localStorage + live data)
 */
calculateLocalStats() {
    const companies = Array.from(this.companies.values());
    const now = new Date();
    const fifteenMinutesAgo = new Date(now - 15 * 60 * 1000);
    
    // 1. Aktywni użytkownicy (ostatnie 15 min)
    let activeUsers = 0;
    companies.forEach(company => {
        const lastVisit = new Date(company.lastVisit);
        if (lastVisit > fifteenMinutesAgo) {
            activeUsers++;
        }
    });
    
    // 2. Sesje dziś (suma wszystkich queries)
    let totalQueries = 0;
    companies.forEach(company => {
        totalQueries += company.totalQueries || 0;
    });
    
    // 3. Średni czas sesji (estimate based on queries)
    // Założenie: 1 query = ~45 sekund interakcji
    let avgDuration = 0;
    if (companies.length > 0) {
        const totalDuration = companies.reduce((sum, company) => {
            // Estimate: więcej zapytań = dłuższa sesja
            const estimatedSeconds = (company.totalQueries || 0) * 45;
            return sum + estimatedSeconds;
        }, 0);
        avgDuration = Math.round(totalDuration / companies.length);
    }
    
    // 4. Conversion rate (high-intent / total)
    let totalHighIntent = 0;
    companies.forEach(company => {
        totalHighIntent += company.highIntentQueries || 0;
    });
    
    let conversionRate = 0;
    if (totalQueries > 0) {
        conversionRate = Math.round((totalHighIntent / totalQueries) * 100);
    }
    
    console.log('📊 Local stats calculated:', {
        activeUsers,
        totalQueries,
        avgDuration,
        conversionRate
    });
    
    return {
        active_now: activeUsers,
        sessions_today: totalQueries,
        avg_duration: avgDuration,
        conversion_rate: conversionRate
    };
}


    /**
 * Zaktualizuj Visitor Stats - HYBRID (backend + localStorage)
 */
updateVisitorStats(backendStats) {
    console.log('📊 Backend stats:', backendStats);
    
    // CRITICAL: Użyj lokalnych obliczeń zamiast backendu!
    const localStats = this.calculateLocalStats();
    
    console.log('📊 Using local stats:', localStats);
    
    // Użyj lokalnych statystyk (bardziej dokładne!)
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
    
    console.log('✅ Visitor stats updated (local calculations)');
}
    
    /**
     * Zaktualizuj aktywne sesje
     */
    updateActiveSessions(sessions) {
        console.log(`⏱️ Aktywne sesje: ${sessions?.length || 0}`);
    }
    
    /**
     * Odśwież statystyki
     */
    async refreshStats() {
    console.log('🔄 Odświeżam statystyki (bez nadpisywania firm)...');
    
    try {
        const response = await fetch('/api/admin/visitor-stats');
        const data = await response.json();
        
        if (data.status === 'success') {
            // Tylko statystyki - NIE firmy!
            this.updateVisitorStats(data.stats);
            
            console.log('✅ Statystyki odświeżone (firmy nietknięte)');
        }
    } catch (error) {
        console.error('❌ Błąd odświeżania:', error);
    }
    
    // Zawsze odśwież Stats Widget (z localStorage)
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
        
        setTimeout(() => {
            notification.remove();
        }, duration);
    }
    
    /**
     * Formatuj czas
     */
    formatDuration(seconds) {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}:${secs.toString().padStart(2, '0')}`;
    }
    
    /**
     * Ile czasu temu
     */
    timeAgo(timestamp) {
        const seconds = Math.floor((new Date() - timestamp) / 1000);
        
        if (seconds < 60) return 'Teraz';
        if (seconds < 3600) return `${Math.floor(seconds / 60)} min temu`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)} h temu`;
        return `${Math.floor(seconds / 86400)} dni temu`;
    }
    
    /**
     * Escape HTML
     */
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// 🚀 URUCHOM DASHBOARD
document.addEventListener('DOMContentLoaded', () => {
    console.log('🎯 Inicjalizuję Admin Dashboard v2.1...');
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