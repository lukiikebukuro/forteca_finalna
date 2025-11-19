import sqlite3

def fix_database():
    print("🛠️ Naprawiam bazę danych...")
    try:
        # Połącz z Twoją bazą (sprawdź czy nazwa pliku to dashboard.db)
        conn = sqlite3.connect('dashboard.db')
        cursor = conn.cursor()
        
        # 1. Tworzenie brakującej tabeli dla admin dashboardu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_dashboard_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                state_key TEXT UNIQUE NOT NULL,
                state_data TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 2. Index dla wydajności
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_state_key ON admin_dashboard_state(state_key)')
        
        conn.commit()
        print("✅ Sukces! Tabela 'admin_dashboard_state' została dodana.")
        conn.close()
    except Exception as e:
        print(f"❌ Błąd: {e}")

if __name__ == "__main__":
    fix_database()