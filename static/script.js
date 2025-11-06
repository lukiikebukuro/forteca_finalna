// Universal Soldier E-commerce Bot v5.1 - Doktryna Cierpliwego Nasłuchu
class EcommerceBotUI {
    constructor() {
        this.API_PREFIX = '/motobot-prototype';
        this.cartCount = 0;
        this.chatInterface = document.getElementById('chat-interface');
        this.messagesContainer = document.getElementById('messages-container');
        this.buttonContainer = document.getElementById('button-container');
        this.textInputContainer = document.getElementById('text-input-container');
        this.userInput = document.getElementById('user-input');
        this.sendBtn = document.getElementById('send-btn');
        this.loadingOverlay = document.getElementById('loading-overlay');
        this.cartCounter = document.getElementById('cart-counter');
        
        // NAPRAWIONE confidence messages
        this.CONFIDENCE_MESSAGES = {
            HIGH: {
                icon: '✅',
                prefix: 'Znaleźliśmy',
                class: 'results-high-confidence'
            },
            MEDIUM: {
                icon: '🤔',
                prefix: 'Czy chodziło Ci o',
                class: 'results-medium-confidence',
                suffix: 'System automatycznie poprawił literówki'
            },
            LOW: {
                icon: '❓',
                prefix: 'Nie rozumiemy zapytania',
                class: 'results-low-confidence',
                helper: 'Sprawdź pisownię lub użyj innych słów'
            },
            NO_MATCH: {
                icon: '🔍',
                prefix: 'Nie mamy tego produktu',
                class: 'results-no-match',
                cta: 'Twoje zapytanie zostało zapisane!'
            },
            NONE: {
                icon: '💭',
                prefix: 'Wpisz zapytanie',
                class: 'results-none'
            }
        };
        
        // Initialize GA4 session
        this.trackEvent('session_initialized', {
            timestamp: new Date().toISOString(),
            version: '5.1-patient-listening'
        });
        
        // Search state
        this.searchMode = false;
        this.faqMode = false;
        this.currentContext = null;
        this.suggestionsDropdown = null;
        this.lastConfidenceLevel = 'NONE';
        this.lastQuery = '';
        // Mobile responsiveness
this.isMobile = window.innerWidth <= 768;
this.dashboardOverlay = null;
        
        // === DOKTRYNA CIERPLIWEGO NASŁUCHU - TIMERY ===
        this.searchTimeout = null;           // 200ms - sugestie real-time
        this.finalAnalysisTimeout = null;    // 800ms - finalna analiza do TCD
        
        this.createSuggestionsDropdown();
        this.initializeEventListeners();
        this.startBot();
        
        console.log('🎯 DOKTRYNA CIERPLIWEGO NASŁUCHU v5.1');
        console.log('   📡 Sugestie: 200ms debounce');
        console.log('   📊 TCD Update: 800ms debounce');
        console.log('   ✅ Jeden finał = jeden event');
    }

    trackEvent(eventName, params = {}) {
        if (typeof gtag === 'function') {
            gtag('event', eventName, {
                ...params,
                source: 'universal_soldier_patient_listening',
                timestamp: new Date().toISOString()
            });
        }
    }
    
    async trackAnalytics(eventType, eventData) {
        try {
            await fetch(this.API_PREFIX + '/track-analytics', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    event_type: eventType,
                    event_data: eventData
                })
            });
        } catch (error) {
            console.warn('[Analytics] Failed to track event:', error);
        }
    }
    
    createSuggestionsDropdown() {
        this.suggestionsDropdown = document.createElement('div');
        this.suggestionsDropdown.className = 'suggestions-dropdown';
    }
    
    initializeEventListeners() {
        const resetBtn = document.getElementById('reset-btn');
        if (resetBtn) {
            resetBtn.addEventListener('click', () => {
                if (confirm('Czy na pewno chcesz rozpocząć nową sesję?')) {
                    this.resetSession();
                }
            });
        }
        
        const messageForm = document.getElementById('message-form');
        if (messageForm) {
            messageForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.sendTextMessage();
            });
        }
        
        if (this.userInput) {
            this.userInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    this.sendTextMessage();
                }
            });
            
            // === DOKTRYNA CIERPLIWEGO NASŁUCHU - GŁÓWNY EVENT LISTENER ===
            this.userInput.addEventListener('input', (e) => {
                const query = e.target.value.trim();
                this.lastQuery = query;
                
                // Reset obu timerów
                if (this.searchTimeout) {
                    clearTimeout(this.searchTimeout);
                }
                if (this.finalAnalysisTimeout) {
                    clearTimeout(this.finalAnalysisTimeout);
                }
                
                if (query.length < 2) {
                    this.hideSuggestions();
                    this.lastConfidenceLevel = 'NONE';
                    return;
                }
                
                if (!this.searchMode && !this.faqMode) {
                    return;
                }
                
                // WARSTWA 1: Sugestie real-time (200ms)
                this.searchTimeout = setTimeout(() => {
                    this.performSearch(query);
                }, 200);
                
                // WARSTWA 2: Finalna analiza do TCD (800ms)
                this.finalAnalysisTimeout = setTimeout(() => {
                    this.sendFinalAnalysis(query);
                }, 800);
            });
            
            this.userInput.addEventListener('blur', () => {
                setTimeout(() => this.hideSuggestions(), 200);
            });
        }
    }
    
    async startBot() {
        console.log('[DEBUG] Starting Universal Soldier bot v5.1 - Patient Listening');
        this.showLoading(true);
        
        this.messagesContainer.innerHTML = '';
        this.buttonContainer.innerHTML = '';
        this.textInputContainer.style.display = 'none';
        
        try {
            const response = await fetch(this.API_PREFIX + '/bot/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin',
                body: JSON.stringify({})
            });
            
            if (!response.ok) {
                throw new Error(`Server error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.reply) {
                this.displayBotMessage(data.reply);
            }
            
        } catch (error) {
            console.error('[ERROR] Failed to start bot:', error);
            this.showError('Nie udało się uruchomić asystenta.');
        } finally {
            this.showLoading(false);
        }
    }
    
    displayBotMessage(reply) {
        if (!reply) return;
        
        this.removeTypingIndicator();
        
        const messageElement = document.createElement('div');
        messageElement.className = 'message bot-message';
        
        if (reply.confidence_level) {
            const confidenceConfig = this.CONFIDENCE_MESSAGES[reply.confidence_level];
            if (confidenceConfig) {
                messageElement.classList.add(confidenceConfig.class);
            }
        }
        
        messageElement.style.opacity = '0';
        
        let messageContent = `
            <div class="message-avatar">🤖</div>
            <div class="message-content">
        `;
        
        // Handle lost demand special case
        if (reply.lost_demand) {
            messageContent += this.createLostDemandForm(reply.text_message);
        } else if (reply.text_message) {
            let formattedMessage = reply.text_message
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/\n/g, '<br>');
            messageContent += `<div class="message-text">${formattedMessage}</div>`;
        }
        
        if (reply.cart_updated) {
            this.cartCount++;
            this.updateCartCounter();
        }
        
        messageContent += '</div>';
        messageElement.innerHTML = messageContent;
        this.messagesContainer.appendChild(messageElement);
        
        setTimeout(() => {
            messageElement.style.opacity = '1';
        }, 50);
        
        if (reply.buttons && reply.buttons.length > 0) {
            this.displayButtons(reply.buttons);
            this.textInputContainer.style.display = 'none';
        }
        
        if (reply.enable_input || reply.input_expected) {
            this.textInputContainer.style.display = 'block';
            this.buttonContainer.innerHTML = '';
            this.searchMode = reply.search_mode || false;
            this.faqMode = reply.faq_mode || false;
            if (this.userInput) {
                this.userInput.placeholder = reply.input_placeholder || 'Wpisz swoją wiadomość...';
                this.userInput.focus();
            }
        } else if (!reply.buttons || reply.buttons.length === 0) {
            this.textInputContainer.style.display = 'block';
        }
        
        this.scrollToBottom();
    }
    
    createLostDemandForm(message) {
        const formattedMessage = message
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\n/g, '<br>');
            
        return `
            <div class="message-text">${formattedMessage}</div>
            <div class="lost-demand-form" style="margin-top: 1rem; padding: 1rem; background: #f9fafb; border-radius: 8px;">
                <input type="email" 
                       id="lost-demand-email" 
                       placeholder="Twój email (opcjonalnie)" 
                       style="width: 100%; padding: 0.5rem; margin-bottom: 0.5rem; border: 1px solid #d1d5db; border-radius: 4px;">
                <button onclick="window.botUI.submitLostDemand()" 
                        style="background: #22c55e; color: white; padding: 0.5rem 1rem; border-radius: 4px; border: none; cursor: pointer;">
                    📧 Powiadom mnie o dostępności
                </button>
            </div>
        `;
    }
    
    async submitLostDemand() {
        const emailInput = document.getElementById('lost-demand-email');
        const email = emailInput ? emailInput.value : '';
        const query = this.lastQuery || this.userInput.value;
        
        try {
            const response = await fetch(this.API_PREFIX + '/report-lost-demand', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    query: query,
                    email: email,
                    notify: !!email
                })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.showNotification('✅ ' + data.message);
                if (emailInput) {
                    emailInput.value = '';
                    emailInput.disabled = true;
                }
                
                this.trackAnalytics('lost_demand_reported', {
                    query: query,
                    email_provided: !!email
                });
            }
        } catch (error) {
            console.error('[ERROR] Failed to submit lost demand:', error);
            this.showNotification('❌ Wystąpił błąd.');
        }
    }
    
    displayButtons(buttons) {
        this.buttonContainer.innerHTML = '';
        this.textInputContainer.style.display = 'none';
        
        buttons.forEach((button, index) => {
            const buttonElement = document.createElement('button');
            buttonElement.className = 'action-btn';
            buttonElement.innerHTML = button.text;
            buttonElement.style.animationDelay = `${index * 0.1}s`;
            buttonElement.addEventListener('click', () => this.handleButtonClick(button.action));
            this.buttonContainer.appendChild(buttonElement);
        });
    }
    
    async handleButtonClick(action) {
        console.log('[DEBUG] Button clicked:', action);
        
        const clickedButton = event.target;
        this.displayUserMessage(clickedButton.textContent);
        
        this.buttonContainer.innerHTML = '';
        this.showLoading(true);
        this.showTypingIndicator();
        
        try {
            const response = await fetch(this.API_PREFIX + '/bot/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin',
                body: JSON.stringify({ button_action: action })
            });
            
            if (!response.ok) {
                throw new Error(`Server error: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (action.startsWith('machine_')) {
                this.currentContext = 'product_search';
                this.searchMode = true;
                this.faqMode = false;
            } else if (action === 'faq_search') {
                this.currentContext = 'faq_search';
                this.searchMode = false;
                this.faqMode = true;
            }
            
            if (data.reply) {
                setTimeout(() => {
                    this.displayBotMessage(data.reply);
                }, 500);
            }
        } catch (error) {
            console.error('[ERROR] Button action failed:', error);
            this.showError('Wystąpił błąd.');
        } finally {
            this.showLoading(false);
        }
    }
    async sendTextMessage() {
        const message = this.userInput.value.trim();
        if (!message) return;
        
        this.displayUserMessage(message);
        this.userInput.value = '';
        
        // Reset timerów przy wysłaniu
        if (this.searchTimeout) clearTimeout(this.searchTimeout);
        if (this.finalAnalysisTimeout) clearTimeout(this.finalAnalysisTimeout);
        
        this.showTypingIndicator();
        this.showLoading(true);
        
        try {
            // Wyślij wiadomość do bota
            const response = await fetch(this.API_PREFIX + '/bot/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin',
                body: JSON.stringify({ message })
            });
            
            if (!response.ok) {
                throw new Error(`Server error: ${response.status}`);
            }
            
            const data = await response.json();
            
            // NATYCHMIASTOWA analiza dla TCD przy Enter
            if (this.searchMode || this.faqMode) {
                await this.sendFinalAnalysis(message);
            }
            
            if (data.reply) {
                setTimeout(() => {
                    this.displayBotMessage(data.reply);
                }, 300 + Math.random() * 700);
            }
        } catch (error) {
            console.error('[ERROR] Message send failed:', error);
            this.showError('Nie udało się wysłać wiadomości.');
        } finally {
            this.showLoading(false);
        }
    }
    
    displayUserMessage(text) {
        const messageElement = document.createElement('div');
        messageElement.className = 'message user-message';
        messageElement.style.opacity = '0';
        messageElement.innerHTML = `
            <div class="message-content">
                <div class="message-text">${this.escapeHtml(text)}</div>
            </div>
            <div class="message-avatar">👤</div>
        `;
        this.messagesContainer.appendChild(messageElement);
        
        setTimeout(() => {
            messageElement.style.opacity = '1';
        }, 50);
        
        this.scrollToBottom();
    }
    
    /**
     * === WARSTWA 1: SUGESTIE REAL-TIME (200ms) ===
     * Pokazuje sugestie użytkownikowi, NIE zapisuje do TCD
     */
    async performSearch(query) {
        if (!query) return;
        
        const searchType = this.faqMode ? 'faq' : 'products';
        
        try {
            const response = await fetch(this.API_PREFIX + '/search-suggestions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({ 
                    query: query,
                    type: searchType 
                })
            });
            
            if (!response.ok) {
                throw new Error(`Search failed: ${response.status}`);
            }
            
            const data = await response.json();
            console.log('[SUGGESTIONS] Results:', data);
            
            this.lastConfidenceLevel = data.confidence_level || 'HIGH';
            
            // Tylko sugestie - BEZ wysyłania do TCD
            if (data.suggestions && data.suggestions.length > 0) {
                this.displaySearchSuggestions(data.suggestions, this.lastConfidenceLevel, searchType);
            } else {
                this.displayNoSuggestions(query, searchType, this.lastConfidenceLevel);
            }
            
        } catch (error) {
            console.error('[ERROR] Search failed:', error);
            this.hideSuggestions();
        }
    }
    
    /**
     * === WARSTWA 2: FINALNA ANALIZA DO TCD (800ms) ===
     * Wysyła JEDEN event do TCD po pauzie w pisaniu
     */
    async sendFinalAnalysis(query) {
        if (!query || query.length < 2) return;
        
        const searchType = this.faqMode ? 'faq' : 'products';
        
        try {
            console.log(`[FINAL ANALYSIS] Sending to TCD: "${query}"`);
            
            const response = await fetch(this.API_PREFIX + '/api/analyze_query', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    query: query,
                    type: searchType
                })
            });
            
            if (!response.ok) {
                throw new Error(`Analysis failed: ${response.status}`);
            }
            
            const data = await response.json();
            console.log(`[FINAL ANALYSIS] TCD updated: ${data.decision} (confidence: ${data.confidence_level})`);
            
        } catch (error) {
            console.error('[ERROR] Final analysis failed:', error);
        }
    }
    
    displaySearchSuggestions(suggestions, confidenceLevel, searchType) {
        this.suggestionsDropdown.innerHTML = '';
        this.suggestionsDropdown.className = 'suggestions-dropdown';
        
        const confidenceConfig = this.CONFIDENCE_MESSAGES[confidenceLevel] || this.CONFIDENCE_MESSAGES.HIGH;
        
        if (confidenceLevel !== 'HIGH') {
            const header = document.createElement('div');
            header.className = `suggestions-header ${confidenceConfig.class}`;
            header.innerHTML = `
                <span class="confidence-icon">${confidenceConfig.icon}</span>
                <span class="confidence-message">${confidenceConfig.prefix}:</span>
            `;
            this.suggestionsDropdown.appendChild(header);
        }
        
        suggestions.forEach(item => {
            const suggestionElement = document.createElement('div');
            suggestionElement.className = `suggestion-item ${confidenceConfig.class}`;
            
            if (item.type === 'faq') {
                suggestionElement.classList.add('faq-suggestion');
                suggestionElement.innerHTML = `
                    <div class="suggestion-item-header">
                        <div class="suggestion-product-info">
                            <div class="suggestion-product-name">
                                ❓ ${item.text || item.question}
                            </div>
                            <div class="suggestion-product-details">
                                <span class="suggestion-match-score">Dopasowanie: ${item.score}%</span>
                                <span style="color: #d1d5db;">|</span>
                                <span class="suggestion-category">${item.category || 'FAQ'}</span>
                            </div>
                        </div>
                    </div>
                `;
                
                suggestionElement.addEventListener('click', () => {
                    this.userInput.value = item.text || item.question;
                    this.hideSuggestions();
                    this.trackAnalytics('faq_suggestion_accepted', {
                        question: item.text,
                        score: item.score
                    });
                    setTimeout(() => this.sendTextMessage(), 100);
                });
                
            } else {
                let stockBadge = '';
                if (item.stock_status === 'available') {
                    stockBadge = `<span class="suggestion-stock-indicator stock-available">✅ ${item.stock} szt.</span>`;
                } else if (item.stock_status === 'limited') {
                    stockBadge = `<span class="suggestion-stock-indicator stock-limited">⚠️ Ostatnie ${item.stock} szt.</span>`;
                } else {
                    stockBadge = `<span class="suggestion-stock-indicator stock-out">❌ Brak</span>`;
                }
                
                let scoreClass = 'score-high';
                if (confidenceLevel === 'MEDIUM') scoreClass = 'score-medium';
                if (confidenceLevel === 'LOW') scoreClass = 'score-low';
                
                suggestionElement.innerHTML = `
                    <div class="suggestion-item-header">
                        <div class="suggestion-product-info">
                            <div class="suggestion-product-name">${item.text}</div>
                            <div class="suggestion-product-details">
                                <span class="suggestion-product-code">${item.id}</span>
                                <span style="color: #d1d5db;">|</span>
                                <span class="suggestion-product-brand">${item.brand}</span>
                                <span style="color: #d1d5db;">|</span>
                                <span class="suggestion-score ${scoreClass}">${item.score}%</span>
                                <span style="color: #d1d5db;">|</span>
                                ${stockBadge}
                            </div>
                        </div>
                        <div class="suggestion-price-info">
                            <div class="suggestion-price">${item.price}</div>
                            <div class="suggestion-price-label">netto</div>
                        </div>
                    </div>
                `;
                
                suggestionElement.addEventListener('click', () => {
                    this.hideSuggestions();
                    this.trackAnalytics('product_suggestion_accepted', {
                        suggestion: item.text,
                        confidence_level: confidenceLevel,
                        original_query: this.lastQuery,
                        score: item.score
                    });
                    if (confidenceLevel === 'MEDIUM') {
                        this.trackEvent('typo_correction_accepted', {
                            original: this.lastQuery,
                            corrected: item.text
                        });
                    }
                    this.handleButtonClick(`show_full_card_${item.id}`);
                });
            }
            
            this.suggestionsDropdown.appendChild(suggestionElement);
        });
        
        if (confidenceLevel === 'MEDIUM' && confidenceConfig.suffix) {
            const footer = document.createElement('div');
            footer.className = 'suggestions-footer';
            footer.innerHTML = `<small>${confidenceConfig.suffix}</small>`;
            this.suggestionsDropdown.appendChild(footer);
        }
        
        this.positionDropdown();
    }
    
    displayNoSuggestions(query, searchType, confidenceLevel) {
        this.suggestionsDropdown.innerHTML = '';
        this.suggestionsDropdown.className = 'suggestions-dropdown';
        
        const message = document.createElement('div');
        message.className = 'no-results-message';
        
        const confidenceConfig = this.CONFIDENCE_MESSAGES[confidenceLevel] || this.CONFIDENCE_MESSAGES.NO_MATCH;
        
        if (confidenceLevel === 'LOW') {
            message.innerHTML = `
                <div class="no-results-icon">${confidenceConfig.icon}</div>
                <div class="no-results-text">
                    ${confidenceConfig.prefix}: "<strong>${this.escapeHtml(query)}</strong>"
                </div>
                <div class="no-results-tips">
                    <p>${confidenceConfig.helper}</p>
                    <ul>
                        <li>Sprawdź pisownię</li>
                        <li>Użyj innych słów</li>
                        <li>Spróbuj prostszego zapytania</li>
                    </ul>
                </div>
            `;
        } else if (confidenceLevel === 'NO_MATCH') {
            message.innerHTML = `
                <div class="no-results-icon">${confidenceConfig.icon}</div>
                <div class="no-results-text">
                    ${confidenceConfig.prefix}: "<strong>${this.escapeHtml(query)}</strong>"
                </div>
                <div class="no-results-cta">
                    <p>${confidenceConfig.cta}</p>
                    <button onclick="window.botUI.reportMissingProduct('${this.escapeHtml(query).replace(/'/g, "\\'")}')" 
                            class="report-missing-btn">
                        📧 Zgłoś brakujący produkt
                    </button>
                </div>
            `;
        } else if (searchType === 'faq') {
            message.innerHTML = `
                <div class="no-results-icon">❓</div>
                <div class="no-results-text">
                    Brak odpowiedzi na pytanie: "<strong>${this.escapeHtml(query)}</strong>"
                </div>
                <div class="no-results-tips">
                    <p>Spróbuj zadać pytanie inaczej lub skontaktuj się z nami</p>
                </div>
            `;
        } else {
            message.innerHTML = `
                <div class="no-results-icon">🔍</div>
                <div class="no-results-text">
                    Brak wyników dla: "<strong>${this.escapeHtml(query)}</strong>"
                </div>
            `;
        }
        
        this.suggestionsDropdown.appendChild(message);
        this.positionDropdown();
    }
    
    async reportMissingProduct(query) {
        try {
            const response = await fetch(this.API_PREFIX + '/report-lost-demand', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    query: query,
                    email: '',
                    notify: false
                })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.showNotification('✅ Dziękujemy! Produkt został zgłoszony.');
                this.hideSuggestions();
                this.trackEvent('lost_demand_user_confirmed', {
                    product_query: query
                });
            }
        } catch (error) {
            console.error('[ERROR] Failed to report:', error);
            this.showNotification('❌ Wystąpił błąd.');
        }
    }
    
    positionDropdown() {
        const inputGroup = document.getElementById('message-form');
        if (!inputGroup) return;
        
        inputGroup.style.position = 'relative';
        
        if (this.suggestionsDropdown.parentElement !== inputGroup) {
            inputGroup.appendChild(this.suggestionsDropdown);
        }
        
        this.suggestionsDropdown.style.position = 'absolute';
        this.suggestionsDropdown.style.left = '0';
        this.suggestionsDropdown.style.right = '0';
        this.suggestionsDropdown.style.bottom = '100%';
        this.suggestionsDropdown.style.marginBottom = '4px';
        this.suggestionsDropdown.style.display = 'block';
    }
    
    hideSuggestions() {
        if (this.suggestionsDropdown) {
            this.suggestionsDropdown.style.display = 'none';
        }
    }
    
    async resetSession() {
        this.showLoading(true);
        try {
            this.cartCount = 0;
            this.updateCartCounter();
            this.searchMode = false;
            this.faqMode = false;
            this.currentContext = null;
            this.lastConfidenceLevel = 'NONE';
            this.lastQuery = '';
            
            // Reset timerów
            if (this.searchTimeout) clearTimeout(this.searchTimeout);
            if (this.finalAnalysisTimeout) clearTimeout(this.finalAnalysisTimeout);
            
            await this.startBot();
        } catch (error) {
            console.error('[ERROR] Reset failed:', error);
            this.showError('Nie udało się zresetować sesji.');
        } finally {
            this.showLoading(false);
        }
    }
    
    showError(message) {
        const errorElement = document.createElement('div');
        errorElement.className = 'message bot-message error';
        errorElement.innerHTML = `
            <div class="message-avatar">⚠️</div>
            <div class="message-content">
                <div class="message-text">${message}</div>
            </div>
        `;
        this.messagesContainer.appendChild(errorElement);
        this.scrollToBottom();
    }
    
    showTypingIndicator() {
        this.removeTypingIndicator();
        const typingElement = document.createElement('div');
        typingElement.className = 'message bot-message typing-indicator';
        typingElement.innerHTML = `
            <div class="message-avatar">🤖</div>
            <div class="message-content">
                <div class="typing-dots">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
            </div>
        `;
        this.messagesContainer.appendChild(typingElement);
        this.scrollToBottom();
    }
    
    removeTypingIndicator() {
        const typingIndicator = this.messagesContainer.querySelector('.typing-indicator');
        if (typingIndicator) {
            typingIndicator.remove();
        }
    }
    
    showLoading(show) {
        if (this.loadingOverlay) {
            this.loadingOverlay.style.display = show ? 'flex' : 'none';
        }
    }
    
    //
// START: PANCERNY SCROLL (v3.0)
//
    scrollToBottom() {
        if (this.messagesContainer) {
            setTimeout(() => {
                
                // === POCZĄTEK "HAKERSKIEJ" ŁATKI ===
                // Sprawdź, ile jest wiadomości w oknie
                const messageCount = this.messagesContainer.querySelectorAll('.message').length;
                
                // Jeśli to jest TYLKO wiadomość powitalna (1 wiadomość) LUB
                // jeśli ładuje się wskaźnik pisania (2 wiadomości),
                // ZMUSZAMY scroll na GÓRĘ.
                if (messageCount <= 2 && this.messagesContainer.querySelector('.bot-message')) {
                    this.messagesContainer.scrollTop = 0; // Wymuś GÓRĘ
                    console.log('Adept Engine: Scroll-to-top override executed.');
                } else {
                    // W każdym innym przypadku (normalna rozmowa), scrolluj na DÓŁ.
                    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
                }
                // === KONIEC "HAKERSKIEJ" ŁATKI ===
                
            }, 100);
        }
    }
//
// KONIEC: PANCERNY SCROLL (v3.0)
//
    
    updateCartCounter() {
        if (this.cartCounter) {
            this.cartCounter.textContent = `🛒 Koszyk: ${this.cartCount}`;
            this.cartCounter.style.transform = 'scale(1.2)';
            setTimeout(() => {
                this.cartCounter.style.transform = 'scale(1)';
            }, 200);
        }
    }
    
    showNotification(message) {
        const notification = document.createElement('div');
        notification.className = 'notification';
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--accent-color);
            color: var(--primary-color);
            padding: 1rem 1.5rem;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            z-index: 1001;
            animation: slideIn 0.3s ease;
            font-weight: 600;
        `;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'fadeOut 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
    
    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }
    /**
 * Toggle mobile dashboard overlay
 */
toggleMobileDashboard() {
    if (!this.dashboardOverlay) {
        this.dashboardOverlay = document.getElementById('mobileDashboardOverlay');
    }
    
    const overlay = this.dashboardOverlay;
    const content = document.getElementById('mobileDashboardContent');
    const originalDashboard = document.getElementById('dashboardColumn');
    const toggleBtn = document.getElementById('mobileDashboardToggle');
    
    if (!overlay || !content || !originalDashboard) return;
    
    if (overlay.classList.contains('active')) {
        // Ukryj overlay
        overlay.classList.remove('active');
        content.innerHTML = '';
        toggleBtn.innerHTML = '📊 Pokaż Centrum Analityczne';
    } else {
        // Pokaż overlay
        overlay.classList.add('active');
        content.innerHTML = originalDashboard.innerHTML;
        toggleBtn.innerHTML = '📊 Dashboard Otwarty';
        
        // Scroll to top overlay
        overlay.scrollTop = 0;
    }
}
}

// Initialize bot when DOM is ready
window.botUI = null;

document.addEventListener('DOMContentLoaded', () => {
    console.log('=====================================');
    console.log('🎯 Universal Soldier v5.1 - PATIENT LISTENING');
    console.log('=====================================');
    console.log('📡 Sugestie: 200ms (real-time UX)');
    console.log('📊 TCD Update: 800ms (jeden finał)');
    console.log('🎯 Live Feed: Visual feedback');
    console.log('📈 Metrics: Final queries only');
    console.log('=====================================');
    console.log('Architecture:');
    console.log('  WARSTWA 1: performSearch() → sugestie');
    console.log('  WARSTWA 2: sendFinalAnalysis() → TCD');
    console.log('  Separator: 800ms debounce');
    console.log('=====================================');
    
    window.botUI = new EcommerceBotUI();
    
    console.log('✅ Doktryna Cierpliwego Nasłuchu aktywna');
    console.log('=====================================');
    // Mobile dashboard toggle handler
document.addEventListener('click', (e) => {
    if (e.target.id === 'mobileDashboardToggle') {
        window.botUI.toggleMobileDashboard();
    }
    if (e.target.id === 'mobileDashboardClose') {
        window.botUI.toggleMobileDashboard();
    }
});

// Window resize handler
window.addEventListener('resize', () => {
    if (window.botUI) {
        window.botUI.isMobile = window.innerWidth <= 768;
    }
});
});