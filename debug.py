#!/usr/bin/env python3
"""
MEGA TESTY BIZNESOWE - PANCERNA DEMONSTRACJA
100 scenariuszy testowych dla niepodważalnej prezentacji
"""

from ecommerce_bot import EcommerceBot

def test_business_scenario(bot, query, expected_result, business_value):
    """Testuje scenariusz biznesowy z wartością dla klienta"""
    try:
        analysis = bot.analyze_query_intent(query)
        
        confidence_to_result = {
            'HIGH': 'SPRZEDAŻ',
            'MEDIUM': 'SPRZEDAŻ', 
            'LOW': 'STRACONY KLIENT',
            'NO_MATCH': 'ZAPYTANIE O ROZSZERZENIE OFERTY'
        }
        
        actual_result = confidence_to_result.get(analysis['confidence_level'], 'BŁĄD SYSTEMU')
        passed = actual_result == expected_result
        
        return {
            'passed': passed,
            'actual': actual_result,
            'expected': expected_result,
            'business_value': business_value,
            'confidence': analysis['confidence_level'],
            'query': query
        }
        
    except Exception as e:
        return {
            'passed': False,
            'actual': f'BŁĄD SYSTEMU: {e}',
            'expected': expected_result,
            'business_value': business_value,
            'confidence': 'ERROR',
            'query': query
        }

def run_business_tests():
    """Uruchamia 100 testów biznesowych"""
    
    print("💰 MEGA TESTY BIZNESOWE - PANCERNA DEMONSTRACJA")
    print("100 scenariuszy dla niepodważalnej prezentacji")
    print("=" * 70)
    
    bot = EcommerceBot()
    
    # === 100 SCENARIUSZY TESTOWYCH ===
    scenarios = [
        # === PODSTAWOWA SPRZEDAŻ (1-10) ===
        ("klocki bmw e90", "SPRZEDAŻ", "189 zł - natychmiastowa sprzedaż"),
        ("filtr oleju mann", "SPRZEDAŻ", "62 zł - szybka konwersja"),
        ("akumulator varta 74ah", "SPRZEDAŻ", "420 zł - wysokomarżowy produkt"),
        ("olej castrol 5w30", "SPRZEDAŻ", "165 zł - częste zamówienie"),
        ("świeca ngk", "SPRZEDAŻ", "45 zł - łatwa sprzedaż masowa"),
        ("amortyzator bilstein", "SPRZEDAŻ", "520 zł - premium sprzedaż"),
        ("tarcza brembo 320mm", "SPRZEDAŻ", "420 zł - specjalistyczny produkt"),
        ("opony continental zimowe", "SPRZEDAŻ", "456 zł - sezonowa sprzedaż"),
        ("klocki yamaha r6", "SPRZEDAŻ", "145 zł - segment motocyklowy"),
        ("filtr powietrza k&n", "SPRZEDAŻ", "285 zł - tuning premium"),
        
        # === PODSTAWOWE LITERÓWKI (11-20) ===
        ("kloki bosch", "SPRZEDAŻ", "189 zł - jedna litera"),
        ("akumlator varta", "SPRZEDAŻ", "420 zł - brak litery"),
        ("amortyztor sachs", "SPRZEDAŻ", "425 zł - zamiana liter"),
        ("olel 5w30", "SPRZEDAŻ", "165 zł - powtórzona litera"),
        ("swica ngk", "SPRZEDAŻ", "45 zł - brak polskiego znaku"),
        ("filetr mann", "SPRZEDAŻ", "62 zł - dodatkowa litera"),
        ("opny zimowe", "SPRZEDAŻ", "456 zł - brak litery"),
        ("hamulce przod", "SPRZEDAŻ", "189 zł - brak znaku"),
        ("filtry vw", "SPRZEDAŻ", "73 zł - liczba mnoga"),
        ("klocek mercedes", "SPRZEDAŻ", "156 zł - liczba pojedyncza"),
        
        # === TRUDNE LITERÓWKI (21-30) ===
        ("klockii bmw", "SPRZEDAŻ", "189 zł - podwójne 'i'"),
        ("fiiltr mann", "SPRZEDAŻ", "62 zł - podwójne 'i' w środku"),
        ("amortyzatorr", "SPRZEDAŻ", "425 zł - podwójne 'r'"),
        ("oopony zimowe", "SPRZEDAŻ", "456 zł - podwójne 'o'"),
        ("świeeca ngk", "SPRZEDAŻ", "45 zł - podwójne 'e'"),
        ("akkumulator", "SPRZEDAŻ", "420 zł - podwójne 'k'"),
        ("tarczaa hamulcowa", "SPRZEDAŻ", "420 zł - podwójne 'a'"),
        ("olejj castrol", "SPRZEDAŻ", "165 zł - podwójne 'j'"),
        ("filltr oleju", "SPRZEDAŻ", "62 zł - podwójne 'l'"),
        ("kloccki yamaha", "SPRZEDAŻ", "145 zł - podwójne 'c'"),
        
        # === KODY PRODUKTÓW (31-40) ===
        ("0986494104", "SPRZEDAŻ", "189 zł - kod Bosch"),
        ("hu719/7x", "SPRZEDAŻ", "62 zł - kod Mann"),
        ("22-266767", "SPRZEDAŻ", "520 zł - kod Bilstein"),
        ("p83052", "SPRZEDAŻ", "156 zł - kod Brembo"),
        ("FR7DPP33", "SPRZEDAŻ", "38 zł - kod świecy"),
        ("13.0460-7218", "SPRZEDAŻ", "156 zł - kod ATE"),
        ("GDB1748", "SPRZEDAŻ", "135 zł - kod TRW"),
        ("E12", "SPRZEDAŻ", "420 zł - kod Varta"),
        ("520VX3-114", "SPRZEDAŻ", "345 zł - kod łańcucha"),
        ("TS850", "SPRZEDAŻ", "456 zł - kod Continental"),
        
        # === ZAPYTANIA KONTEKSTOWE (41-50) ===
        ("klocki do bmw", "SPRZEDAŻ", "189 zł - z przyimkiem 'do'"),
        ("filtr dla golfa", "SPRZEDAŻ", "73 zł - z przyimkiem 'dla'"),
        ("olej na zimę", "SPRZEDAŻ", "165 zł - kontekst sezonowy"),
        ("części do yamaha", "SPRZEDAŻ", "145 zł - ogólne części"),
        ("hamulce w mercedes", "SPRZEDAŻ", "156 zł - z przyimkiem 'w'"),
        ("amortyzator z przodu", "SPRZEDAŻ", "520 zł - lokalizacja"),
        ("klocki pod sprinter", "SPRZEDAŻ", "267 zł - z przyimkiem 'pod'"),
        ("świeca do civic", "SPRZEDAŻ", "52 zł - model Honda"),
        ("zimówki continental", "SPRZEDAŻ", "456 zł - potoczne"),
        ("sportowy filtr k&n", "SPRZEDAŻ", "285 zł - przymiotnik"),
        
        # === SLANG MECHANIKÓW (51-60) ===
        ("kloce bmw", "SPRZEDAŻ", "189 zł - warsztatowy slang"),
        ("amory sachs", "SPRZEDAŻ", "425 zł - skrót amortyzatorów"),
        ("aku varta", "SPRZEDAŻ", "420 zł - skrót akumulatora"),
        ("świece do benza", "SPRZEDAŻ", "45 zł - benzyna potocznie"),
        ("filtry do diesla", "SPRZEDAŻ", "62 zł - diesel potocznie"),
        ("olej do tfsi", "SPRZEDAŻ", "165 zł - typ silnika"),
        ("części beemka", "SPRZEDAŻ", "189 zł - BMW potocznie"),
        ("klocki merola", "SPRZEDAŻ", "156 zł - Mercedes potocznie"),
        ("opony na feldze", "SPRZEDAŻ", "456 zł - felgi potocznie"),
        ("akum na mróz", "SPRZEDAŻ", "420 zł - zima potocznie"),
        
        # === MIESZANE JĘZYKI (61-70) ===
        ("brake pads bmw", "SPRZEDAŻ", "189 zł - angielskie klocki"),
        ("oil filter mann", "SPRZEDAŻ", "62 zł - angielski filtr"),
        ("spark plug ngk", "SPRZEDAŻ", "45 zł - angielska świeca"),
        ("battery varta", "SPRZEDAŻ", "420 zł - angielski akumulator"),
        ("bremsen mercedes", "SPRZEDAŻ", "156 zł - niemieckie hamulce"),
        ("huile castrol", "SPRZEDAŻ", "165 zł - francuski olej"),
        ("freni brembo", "SPRZEDAŻ", "420 zł - włoskie hamulce"),
        ("filter für golf", "SPRZEDAŻ", "73 zł - niemiecki dla"),
        ("parts yamaha", "SPRZEDAŻ", "145 zł - angielskie części"),
        ("reifen continental", "SPRZEDAŻ", "456 zł - niemieckie opony"),
        
        # === SPECYFIKACJE TECHNICZNE (71-80) ===
        ("5w30 longlife", "SPRZEDAŻ", "178 zł - specyfikacja VW"),
        ("0w40 mobil1", "SPRZEDAŻ", "189 zł - pełna syntetyka"),
        ("10w40 półsyntetyk", "SPRZEDAŻ", "145 zł - półsyntetyczny"),
        ("195/65r15 zimowe", "SPRZEDAŻ", "345 zł - rozmiar opon"),
        ("225/45r17 lato", "SPRZEDAŻ", "456 zł - opony letnie"),
        ("74ah 680a varta", "SPRZEDAŻ", "420 zł - parametry aku"),
        ("60ah 540a bosch", "SPRZEDAŻ", "350 zł - akumulator"),
        ("320mm tarcze", "SPRZEDAŻ", "420 zł - średnica tarcz"),
        ("280mm przód", "SPRZEDAŻ", "385 zł - tarcze przednie"),
        ("ventylowane 312mm", "SPRZEDAŻ", "450 zł - tarcze wentylowane"),
        
        # === NONSENS DO ODFILTROWANIA (81-85) ===
        ("qwerty asdf", "STRACONY KLIENT", "0 zł - klawiatura"),
        ("pizza hamburger", "STRACONY KLIENT", "0 zł - jedzenie"),
        ("hello world", "STRACONY KLIENT", "0 zł - programowanie"),
        ("asdfghjkl", "STRACONY KLIENT", "0 zł - losowe znaki"),
        ("123456789", "STRACONY KLIENT", "0 zł - same cyfry"),
        
        # === UTRACONY POPYT - MARKI PREMIUM (86-95) ===
        ("klocki ferrari", "ZAPYTANIE O ROZSZERZENIE OFERTY", "2000 zł - supercar"),
        ("filtr tesla", "ZAPYTANIE O ROZSZERZENIE OFERTY", "300 zł - elektryki"),
        ("części genesis", "ZAPYTANIE O ROZSZERZENIE OFERTY", "500 zł - Korea premium"),
        ("klocki mclaren", "ZAPYTANIE O ROZSZERZENIE OFERTY", "3000 zł - F1 marka"),
        ("akumulator nio", "ZAPYTANIE O ROZSZERZENIE OFERTY", "800 zł - chiński EV"),
        ("olej bugatti", "ZAPYTANIE O ROZSZERZENIE OFERTY", "500 zł - hypercars"),
        ("tarcze pagani", "ZAPYTANIE O ROZSZERZENIE OFERTY", "5000 zł - włoski supercar"),
        ("świece koenigsegg", "ZAPYTANIE O ROZSZERZENIE OFERTY", "200 zł - szwedzki hypercar"),
        ("filtr rolls-royce", "ZAPYTANIE O ROZSZERZENIE OFERTY", "400 zł - luksus brytyjski"),
        ("amortyzatory bentley", "ZAPYTANIE O ROZSZERZENIE OFERTY", "2000 zł - brytyjski luksus"),
        
        # === EDGE CASES - GRANICZNE (96-100) ===
        ("", "STRACONY KLIENT", "0 zł - puste zapytanie"),
        ("a", "STRACONY KLIENT", "0 zł - pojedyncza litera"),
        ("bmw", "SPRZEDAŻ", "100 zł - sama marka"),
        ("klocki", "SPRZEDAŻ", "150 zł - sama kategoria"),
        ("bmw e90 e91 e92 e93", "SPRZEDAŻ", "189 zł - wiele kodów"),
    ]
    
    passed = 0
    failed = 0
    failed_tests = []
    
    print(f"\n📊 TESTOWANIE {len(scenarios)} SCENARIUSZY:\n")
    
    # Grupuj wyniki
    groups = {
        "PODSTAWOWA SPRZEDAŻ (1-10)": (0, 10),
        "PODSTAWOWE LITERÓWKI (11-20)": (10, 20),
        "TRUDNE LITERÓWKI (21-30)": (20, 30),
        "KODY PRODUKTÓW (31-40)": (30, 40),
        "ZAPYTANIA KONTEKSTOWE (41-50)": (40, 50),
        "SLANG MECHANIKÓW (51-60)": (50, 60),
        "MIESZANE JĘZYKI (61-70)": (60, 70),
        "SPECYFIKACJE TECHNICZNE (71-80)": (70, 80),
        "FILTROWANIE NONSENSU (81-85)": (80, 85),
        "UTRACONY POPYT PREMIUM (86-95)": (85, 95),
        "EDGE CASES (96-100)": (95, 100),
    }
    
    group_stats = {}
    
    for group_name, (start, end) in groups.items():
        print(f"\n--- {group_name} ---")
        group_passed = 0
        group_total = end - start
        
        for i in range(start, min(end, len(scenarios))):
            if i >= len(scenarios):
                break
                
            query, expected, business_value = scenarios[i]
            result = test_business_scenario(bot, query, expected, business_value)
            
            if result['passed']:
                passed += 1
                group_passed += 1
                status = "✅"
            else:
                failed += 1
                status = "❌"
                failed_tests.append({
                    'num': i+1,
                    'query': query,
                    'expected': expected,
                    'actual': result['actual']
                })
            
            print(f"{i+1:3d}. {status} '{query:30s}' → {result['actual']:30s}")
            if not result['passed']:
                print(f"      ⚠️  Oczekiwano: {expected}")
        
        percentage = (group_passed / group_total * 100) if group_total > 0 else 0
        group_stats[group_name] = (group_passed, group_total, percentage)
        print(f"\n     Grupa: {group_passed}/{group_total} ({percentage:.1f}%)")
    
    # === RAPORT KOŃCOWY ===
    print("\n" + "=" * 70)
    print("📊 RAPORT KOŃCOWY - WYNIKI TESTÓW")
    print("=" * 70)
    
    overall_percentage = (passed / len(scenarios) * 100) if len(scenarios) > 0 else 0
    print(f"\n🎯 WYNIK OGÓLNY: {passed}/{len(scenarios)} ({overall_percentage:.1f}%)")
    
    print(f"\n📈 WYNIKI PO GRUPACH:")
    for group_name, (group_passed, group_total, percentage) in group_stats.items():
        status_icon = "🟢" if percentage >= 90 else "🟡" if percentage >= 70 else "🔴"
        print(f"   {status_icon} {group_name:40s}: {percentage:5.1f}% ({group_passed}/{group_total})")
    
    # Pokaż błędne testy
    if failed_tests:
        print(f"\n❌ TESTY KTÓRE NIE PRZESZŁY ({len(failed_tests)}):")
        for test in failed_tests[:10]:  # Pokaż max 10
            print(f"   #{test['num']:3d}: '{test['query']}' - Oczekiwano: {test['expected']}, Otrzymano: {test['actual']}")
        if len(failed_tests) > 10:
            print(f"   ... i {len(failed_tests)-10} więcej")
    
    # Ocena końcowa
    print(f"\n🏆 STATUS SYSTEMU:")
    if overall_percentage >= 95:
        print("   🟢 SYSTEM GOTOWY DO PRODUKCJI!")
        print("   Perfekcyjna dokładność - można pokazać inwestorom")
    elif overall_percentage >= 90:
        print("   🟢 SYSTEM GOTOWY DO SPRZEDAŻY!")
        print("   Minimalne błędy - akceptowalne dla klientów")
    elif overall_percentage >= 80:
        print("   🟡 SYSTEM PRAWIE GOTOWY")
        print("   Wymaga drobnych poprawek")
    else:
        print("   🔴 SYSTEM WYMAGA POPRAWEK")
        print("   Za dużo błędów do wdrożenia")
    
    return passed, failed

if __name__ == "__main__":
    print("\n🚀 URUCHAMIANIE MEGA TESTÓW BIZNESOWYCH")
    print("Cel: Niepodważalna demonstracja wartości produktu")
    print("-" * 70)
    
    passed, failed = run_business_tests()
    
    print(f"\n✅ Zakończono testy: {passed} passed, {failed} failed")
    print(f"📊 Skuteczność: {(passed/(passed+failed)*100):.1f}%")