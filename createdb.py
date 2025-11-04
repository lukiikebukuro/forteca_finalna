from app import ensure_visitor_tables_exist, ensure_tables_exist

print("== URUCHAMIAM BUDOWĘ FUNDAMENTÓW BAZY DANYCH ==")

# Tworzy tabelę 'users' i 'clients' z auth_manager.py
print("1. Tworzenie tabel autoryzacji...")
ensure_tables_exist()
print("   ✅ Tabele autoryzacji gotowe.")

# Tworzy tabelę 'visitor_sessions' z app.py
print("2. Tworzenie tabel śledzenia gości...")
ensure_visitor_tables_exist()
print("   ✅ Tabele śledzenia gotowe.")

print("== FUNDAMENTY UKOŃCZONE. BAZA DANYCH GOTOWA DO PRACY. ==")