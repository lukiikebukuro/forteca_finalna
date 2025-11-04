"""
Skrypt do aktualizacji haseł w bazie dashboard.db
Uruchom: python update_passwords.py
"""

import sqlite3
from werkzeug.security import generate_password_hash

def update_passwords():
    """Aktualizuje hasła dla admin i demo użytkowników"""
    
    conn = sqlite3.connect('dashboard.db')
    cursor = conn.cursor()
    
    print("[UPDATE] Rozpoczynam aktualizację haseł...")
    
    # 1. Stwórz/zaktualizuj admina
    print("[UPDATE] Tworzę/aktualizuję admina...")
    admin_hash = generate_password_hash('Nokia5310!')
    
    # Sprawdź czy admin istnieje
    cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    admin_exists = cursor.fetchone()
    
    if admin_exists:
        # Zaktualizuj
        cursor.execute('''
            UPDATE users 
            SET password_hash = ?, salt = ''
            WHERE username = 'admin'
        ''', (admin_hash,))
        print("[UPDATE] Admin zaktualizowany")
    else:
        # Stwórz nowego
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, salt, role, is_active)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin', 'admin@adept.ai', admin_hash, '', 'admin', True))
        print("[UPDATE] Admin utworzony")
    
    # 2. Usuń demo_client (jeśli istnieje)
    print("[UPDATE] Usuwam starego demo_client...")
    cursor.execute('DELETE FROM users WHERE username = ?', ('demo_client',))
    
    # 3. Sprawdź czy demo już istnieje
    cursor.execute('SELECT id FROM users WHERE username = ?', ('demo',))
    demo_exists = cursor.fetchone()
    
    if demo_exists:
        # Zaktualizuj hasło demo na demo123
        print("[UPDATE] Aktualizuję hasło dla demo...")
        demo_hash = generate_password_hash('demo123')
        cursor.execute('''
            UPDATE users 
            SET password_hash = ?, salt = '', role = 'client', client_id = 1
            WHERE username = 'demo'
        ''', (demo_hash,))
    else:
        # Stwórz nowego demo użytkownika
        print("[UPDATE] Tworzę nowego użytkownika demo...")
        demo_hash = generate_password_hash('demo123')
        
        # Najpierw upewnij się że jest firma demo
        cursor.execute('SELECT id FROM clients WHERE id = 1')
        if not cursor.fetchone():
            cursor.execute('''
                INSERT INTO clients (id, company_name, domain, subscription_tier, contact_email, monthly_query_limit, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (1, 'Demo Company Ltd', 'demo-company.pl', 'premium', 'contact@demo-company.pl', 50000, True))
            print("[UPDATE] Utworzono firmę demo")
        
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, salt, role, client_id, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', ('demo', 'demo@demo-company.pl', demo_hash, '', 'client', 1, True))
        print("[UPDATE] Demo utworzone")
    
    conn.commit()
    
    # Pokaż aktualne dane logowania
    print("\n" + "="*50)
    print("[SUCCESS] ✅ Hasła zaktualizowane!")
    print("="*50)
    
    cursor.execute('SELECT username, role FROM users WHERE is_active = 1 ORDER BY role, username')
    users = cursor.fetchall()
    
    print("\n📋 Aktywni użytkownicy w systemie:")
    for username, role in users:
        if username == 'admin':
            print(f"  👤 {username} ({role}) - hasło: Nokia5310!")
        elif username == 'demo':
            print(f"  👤 {username} ({role}) - hasło: demo123")
        else:
            print(f"  👤 {username} ({role})")
    
    print("\n" + "="*50)
    
    conn.close()

if __name__ == '__main__':
    try:
        update_passwords()
    except Exception as e:
        print(f"\n❌ [ERROR] Coś poszło nie tak: {e}")
        import traceback
        traceback.print_exc()