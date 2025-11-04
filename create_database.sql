-- ================================================================
-- SCHEMA BAZY DANYCH "OKO SAURONA" 
-- Plik: create_database.sql
-- ================================================================

-- TABELA 1: KLIENCI - Firmy korzystające z systemu
CREATE TABLE clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_name TEXT NOT NULL UNIQUE,
    api_key TEXT NOT NULL UNIQUE,
    domain TEXT,                               -- np. "auto-czesci.pl"
    industry TEXT DEFAULT 'automotive',        
    subscription_tier TEXT DEFAULT 'basic',    -- basic, premium, enterprise
    
    -- Kontakt
    contact_email TEXT,
    contact_phone TEXT,
    billing_address TEXT,
    
    -- Limity techniczne
    monthly_query_limit INTEGER DEFAULT 10000,
    current_month_queries INTEGER DEFAULT 0,
    
    -- Metadane
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Walidacja
    CONSTRAINT chk_subscription_tier 
        CHECK (subscription_tier IN ('basic', 'premium', 'enterprise'))
);

-- TABELA 2: UŻYTKOWNICY - System autoryzacji z rolami
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,               -- bcrypt hash
    salt TEXT NOT NULL,                        -- Dodatkowa warstwa bezpieczeństwa
    
    -- Role i uprawnienia (kluczowe dla 3 poziomów)
    role TEXT NOT NULL DEFAULT 'client',       -- client, admin, debug
    client_id INTEGER,                         -- NULL dla admin/debug
    
    -- Session management
    last_login TIMESTAMP,
    login_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    email_verified BOOLEAN DEFAULT FALSE,
    
    -- Audit trail
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER,                        -- ID użytkownika który utworzył konto
    
    -- Klucze obce
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id),
    
    -- Walidacja logiczna ról
    CONSTRAINT chk_user_role 
        CHECK (role IN ('client', 'admin', 'debug')),
    CONSTRAINT chk_client_role_logic 
        CHECK ((role = 'client' AND client_id IS NOT NULL) OR 
               (role IN ('admin', 'debug') AND client_id IS NULL))
);

-- TABELA 3: ZDARZENIA BIZNESOWE (rozszerzona z istniejącej "events")
CREATE TABLE business_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    
    -- Dane zapytania (jak w istniejącej tabeli events)
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    query_text TEXT NOT NULL,
    decision TEXT NOT NULL,                    -- ZNALEZIONE_PRODUKTY, UTRACONE_OKAZJE, ODFILTROWANE
    details TEXT,
    category TEXT,
    brand_type TEXT,
    potential_value INTEGER DEFAULT 0,
    explanation TEXT,
    
    -- Nowe pola dla systemu klientów
    user_session_id TEXT,                      -- Połączenie z visitor_sessions
    confidence_score REAL,                     -- 0.0 - 1.0 z AI
    is_verified BOOLEAN DEFAULT FALSE,         -- Czy zweryfikowane przez analityka
    analyst_notes TEXT,                        -- Notatki analityka do cotygodniowych raportów
    
    -- Klucze obce
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- TABELA 4: SESJE ODWIEDZAJĄCYCH (moduł sprzedażowy - wywiad ruchu)
CREATE TABLE visitor_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    session_id TEXT NOT NULL UNIQUE,           -- UUID sesji
    
    -- Dane techniczne (lepsze niż GA4)
    ip_address TEXT,
    user_agent TEXT,
    referrer TEXT,
    utm_source TEXT,
    utm_medium TEXT,
    utm_campaign TEXT,
    
    -- Timeline sesji
    entry_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    exit_time TIMESTAMP,
    session_duration INTEGER,                  -- sekundy
    
    -- Aktywność w bocie (kluczowe!)
    total_messages INTEGER DEFAULT 0,
    bot_conversation_started BOOLEAN DEFAULT FALSE,
    last_bot_message TEXT,
    conversation_abandoned_at TEXT,            -- etap rozmowy gdzie user uciekł
    
    -- Konwersje (ROI tracking)
    converted BOOLEAN DEFAULT FALSE,
    conversion_type TEXT,                      -- 'cart_add', 'email_request', 'phone_call'
    conversion_value DECIMAL(10,2),
    
    -- Geolokacja
    country TEXT,
    city TEXT,
    
    -- Klucze obce
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- TABELA 5: WIADOMOŚCI BOTA (transkrypcje rozmów)
CREATE TABLE bot_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    client_id INTEGER NOT NULL,
    
    -- Dane wiadomości
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sender TEXT NOT NULL,                      -- 'user' lub 'bot'
    message_text TEXT,
    message_type TEXT,                         -- 'text', 'button_click', 'suggestion'
    
    -- Kontekst AI (analiza jakości rozmów)
    intent_detected TEXT,
    confidence_score REAL,
    system_response_time INTEGER,              -- milisekundy (performance tracking)
    
    -- Klucze obce
    FOREIGN KEY (session_id) REFERENCES visitor_sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- ================================================================
-- INDEKSY DLA WYDAJNOŚCI (KRYTYCZNE!)
-- ================================================================

-- Indeksy dla business_events
CREATE INDEX idx_events_client_id ON business_events(client_id);
CREATE INDEX idx_events_timestamp ON business_events(timestamp);
CREATE INDEX idx_events_decision ON business_events(decision);
CREATE INDEX idx_events_session ON business_events(user_session_id);

-- Indeksy dla visitor_sessions
CREATE INDEX idx_sessions_client_id ON visitor_sessions(client_id);
CREATE INDEX idx_sessions_entry_time ON visitor_sessions(entry_time);
CREATE INDEX idx_sessions_converted ON visitor_sessions(converted);
CREATE INDEX idx_sessions_session_id ON visitor_sessions(session_id);

-- Indeksy dla bot_messages
CREATE INDEX idx_messages_session ON bot_messages(session_id);
CREATE INDEX idx_messages_timestamp ON bot_messages(timestamp);
CREATE INDEX idx_messages_client_id ON bot_messages(client_id);

-- Indeksy dla users
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_client_id ON users(client_id);

-- ================================================================
-- DANE TESTOWE (OPCJONALNE - dla developmentu)
-- ================================================================

-- Przykładowy klient
INSERT INTO clients (company_name, api_key, domain, contact_email) 
VALUES ('Auto Części Demo', 'demo_api_key_12345', 'demo-autoczesci.pl', 'demo@autoczesci.pl');

-- Przykładowy admin user
INSERT INTO users (username, email, password_hash, salt, role) 
VALUES ('admin', 'admin@adept.ai', '$2b$12$dummy_hash', 'dummy_salt', 'admin');

-- Przykładowy client user
INSERT INTO users (username, email, password_hash, salt, role, client_id) 
VALUES ('demo_user', 'demo@autoczesci.pl', '$2b$12$dummy_hash', 'dummy_salt', 'client', 1);