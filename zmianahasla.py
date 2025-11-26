#!/usr/bin/env python3
"""
Skrypt do zmiany hasła użytkownika 'demo' na 'demo123'
Użycie: python3 change_demo_password.py
"""

import sqlite3
from werkzeug.security import generate_password_hash

def change_demo_password():
    """Zmienia hasło użytkownika demo na demo123"""
    try:
        # Połącz się z bazą
        conn = sqlite3.connect('dashboard.db')
        cursor = conn.cursor()
        
        # Sprawdź czy user demo istnieje
        cursor.execute("SELECT username, role FROM users WHERE username = 'demo'")
        user = cursor.fetchone()
        
        if not user:
            print("❌ Użytkownik 'demo' nie istnieje w bazie!")
            print("   Dostępni użytkownicy:")
            cursor.execute("SELECT username, role FROM users")
            for u in cursor.fetchall():
                print(f"   - {u[0]} ({u[1]})")
            conn.close()
            return
        
        print(f"✅ Znaleziono użytkownika: {user[0]} (role: {user[1]})")
        
        # Generuj nowy hash
        new_password = 'demo123'
        new_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
        
        print(f"🔐 Generuję hash dla hasła: {new_password}")
        print(f"   Hash: {new_hash[:50]}...")
        
        # Aktualizuj hasło
        cursor.execute("""
            UPDATE users 
            SET password_hash = ?,
                salt = ''
            WHERE username = 'demo'
        """, (new_hash,))
        
        conn.commit()
        
        # Sprawdź czy się udało
        cursor.execute("SELECT username FROM users WHERE username = 'demo'")
        if cursor.fetchone():
            print("=" * 60)
            print("✅ HASŁO ZMIENIONE POMYŚLNIE!")
            print("=" * 60)
            print(f"   Login: demo")
            print(f"   Hasło: {new_password}")
            print("=" * 60)
        
        conn.close()
        
    except sqlite3.Error as e:
        print(f"❌ Błąd bazy danych: {e}")
    except Exception as e:
        print(f"❌ Błąd: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("🔐 ZMIANA HASŁA UŻYTKOWNIKA 'demo'")
    print("=" * 60)
    change_demo_password()