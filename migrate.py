#!/usr/bin/env python3
"""
🔧 SKRYPT MIGRACJI BAZY DANYCH
Tworzy nowe tabele: companies, hot_leads, log_history

UŻYCIE:
    python migrate_database.py

To jest standalone skrypt - możesz go uruchomić przed implementacją zmian w app.py
żeby przetestować czy tabele się utworzą poprawnie.
"""

import sqlite3
import json
from datetime import datetime

DATABASE_NAME = 'dashboard.db'

def create_persistent_storage_tables():
    """Tworzy tabele dla persistent storage"""
    print("🔧 Tworzę tabele persistent storage...")
    
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # 1. TABELA COMPANIES
    print("  📊 Tworzę tabelę: companies")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            city TEXT,
            country TEXT,
            first_visit TIMESTAMP NOT NULL,
            last_visit TIMESTAMP NOT NULL,
            total_queries INTEGER DEFAULT 0,
            high_intent_queries INTEGER DEFAULT 0,
            lost_opportunities INTEGER DEFAULT 0,
            engagement_score INTEGER DEFAULT 0,
            queries_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_companies_name ON companies(name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_companies_score ON companies(engagement_score)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_companies_last_visit ON companies(last_visit)')
    
    # 2. TABELA HOT_LEADS
    print("  🔥 Tworzę tabelę: hot_leads")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hot_leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company TEXT NOT NULL,
            query TEXT NOT NULL,
            score INTEGER NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_hot_leads_timestamp ON hot_leads(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_hot_leads_company ON hot_leads(company)')
    
    # 3. TABELA LOG_HISTORY
    print("  📜 Tworzę tabelę: log_history")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_type TEXT NOT NULL,
            company TEXT NOT NULL,
            query TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_history_timestamp ON log_history(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_history_type ON log_history(log_type)')
    
    conn.commit()
    conn.close()
    
    print("\n✅ Tabele utworzone pomyślnie!")


def verify_tables():
    """Weryfikuje czy tabele zostały utworzone"""
    print("\n🔍 Weryfikuję tabele...")
    
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Sprawdź wszystkie tabele
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = cursor.fetchall()
    
    print("\n📋 Wszystkie tabele w bazie:")
    for table in tables:
        print(f"  ✓ {table[0]}")
    
    # Sprawdź strukturę companies
    print("\n🏢 Struktura tabeli 'companies':")
    cursor.execute("PRAGMA table_info(companies)")
    columns = cursor.fetchall()
    for col in columns:
        print(f"  - {col[1]} ({col[2]})")
    
    # Sprawdź strukturę hot_leads
    print("\n🔥 Struktura tabeli 'hot_leads':")
    cursor.execute("PRAGMA table_info(hot_leads)")
    columns = cursor.fetchall()
    for col in columns:
        print(f"  - {col[1]} ({col[2]})")
    
    # Sprawdź strukturę log_history
    print("\n📜 Struktura tabeli 'log_history':")
    cursor.execute("PRAGMA table_info(log_history)")
    columns = cursor.fetchall()
    for col in columns:
        print(f"  - {col[1]} ({col[2]})")
    
    conn.close()
    print("\n✅ Weryfikacja zakończona!")


def test_insert():
    """Test - wstaw przykładowe dane"""
    print("\n🧪 Test wstawiania danych...")
    
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    try:
        # Test company
        now = datetime.now()
        queries = [{'text': 'test query', 'timestamp': now.isoformat(), 'decision': 'ZNALEZIONE PRODUKTY'}]
        
        cursor.execute('''
            INSERT INTO companies (name, city, country, first_visit, last_visit,
                total_queries, high_intent_queries, lost_opportunities, engagement_score, queries_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('Test Company', 'Warsaw', 'Poland', now, now, 1, 1, 0, 10, json.dumps(queries)))
        
        # Test hot lead
        cursor.execute('''
            INSERT INTO hot_leads (company, query, score, timestamp)
            VALUES (?, ?, ?, ?)
        ''', ('Test Company', 'test query', 30, now))
        
        # Test log entry
        cursor.execute('''
            INSERT INTO log_history (log_type, company, query, timestamp)
            VALUES (?, ?, ?, ?)
        ''', ('ZNALEZIONE PRODUKTY', 'Test Company', 'test query', now))
        
        conn.commit()
        
        print("  ✅ Test company dodany")
        print("  ✅ Test hot lead dodany")
        print("  ✅ Test log entry dodany")
        
        # Sprawdź ile jest rekordów
        cursor.execute('SELECT COUNT(*) FROM companies')
        count = cursor.fetchone()[0]
        print(f"\n  📊 Liczba firm w bazie: {count}")
        
        cursor.execute('SELECT COUNT(*) FROM hot_leads')
        count = cursor.fetchone()[0]
        print(f"  🔥 Liczba hot leads: {count}")
        
        cursor.execute('SELECT COUNT(*) FROM log_history')
        count = cursor.fetchone()[0]
        print(f"  📜 Liczba logów: {count}")
        
    except Exception as e:
        print(f"  ❌ Błąd testu: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        conn.close()
    
    print("\n✅ Test zakończony!")


def main():
    """Główna funkcja migracji"""
    print("=" * 60)
    print("🎯 MIGRACJA BAZY DANYCH - PERSISTENT STORAGE")
    print("=" * 60)
    
    try:
        # 1. Utwórz tabele
        create_persistent_storage_tables()
        
        # 2. Zweryfikuj
        verify_tables()
        
        # 3. Test
        response = input("\n❓ Czy chcesz przetestować wstawianie danych? (t/n): ")
        if response.lower() == 't':
            test_insert()
        
        print("\n" + "=" * 60)
        print("✅ MIGRACJA ZAKOŃCZONA POMYŚLNIE!")
        print("=" * 60)
        print("\n📋 NASTĘPNE KROKI:")
        print("1. Zaimplementuj zmiany w app.py (patrz: INSTRUKCJA_NAPRAWY.txt)")
        print("2. Zaimplementuj zmiany w admin_dashboard.js")
        print("3. Restart aplikacji")
        print("4. Test systemu")
        
    except Exception as e:
        print(f"\n❌ BŁĄD MIGRACJI: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()