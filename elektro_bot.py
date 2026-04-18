"""
Uniwersalny Żołnierz - Silnik bota e-commerce v7.0 ELECTRONICS EDITION
System Inteligentnego Śledzenia Utraconego Popytu - CZYSTA WERSJA
ELECTRONICS - Branża RTV/AGD/IT
Adaptacja: Kompletna transplantacja z automotive -> electronics
"""
print("[BOOT] ELEKTRO_BOT.PY LOADING...")
import json
import os
import re
import time
import hashlib
import random
import requests
import uuid
from datetime import datetime
from flask import session
from difflib import SequenceMatcher
from fuzzywuzzy import fuzz, process
from typing import Tuple, List, Dict, Optional


def load_welcome_message_from_config():
    """Ładuje wiadomość powitalną z pliku JSON."""
    config_path = 'config_teksty2.json'
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
        welcome_lines = config_data.get('welcome_message_lines', [])
        return "\n".join(welcome_lines)
    except FileNotFoundError:
        print(f"BŁĄD KRYTYCZNY: Nie znaleziono pliku {config_path}. Używam domyślnego powitania.")
        return "Witaj w sklepie elektronicznym! Jak mogę Ci pomóc?"
    except Exception as e:
        print(f"BŁĄD KRYTYCZNY: Błąd podczas ładowania {config_path}: {e}")
        return "Witaj w sklepie elektronicznym! Jak mogę Ci pomóc?"

# --- ZAŁADOWANIE KONFIGURACJI PRZY STARCIE ---
GLOBAL_WELCOME_MESSAGE = load_welcome_message_from_config()
print(f"[MAIL] GLOBAL_WELCOME_MESSAGE loaded: {GLOBAL_WELCOME_MESSAGE[:100] if GLOBAL_WELCOME_MESSAGE else 'EMPTY'}...")


class EcommerceBot:
    def __init__(self):
        print("[BOT] ELEKTRO BOT __init__() STARTED!")
        self.product_database = {'products': []}  # Będzie wypełnione w initialize_data()
        self.products = []  # Alias dla kompatybilności
        self.faq_database = {}
        self.orders_database = {}
        self.current_context = None
        self.search_cache = {}
        
        # === UNIWERSALNA BAZA WIEDZY ELEKTRONICZNEJ (ROZSZERZONA) ===
        self.UNIVERSAL_ELECTRONICS_KNOWLEDGE = {
            # MARKI TELEFONÓW I SMARTFONÓW (60+ marek)
            'brands': [
                # Premium/Flagship
                'apple', 'iphone', 'samsung', 'galaxy', 'google', 'pixel',
                
                # Chińskie (popularne w EU)
                'xiaomi', 'redmi', 'poco', 'oppo', 'realme', 'oneplus', 'vivo',
                'honor', 'huawei', 'zte', 'nubia', 'meizu', 'iqoo', 'nothing',
                
                # Laptopy
                'dell', 'hp', 'lenovo', 'asus', 'acer', 'msi', 'macbook',
                'toshiba', 'fujitsu', 'microsoft', 'surface',
                'alienware', 'razer', 'gigabyte', 'rog',
                'thinkpad', 'ideapad', 'yoga', 'chromebook', 'aspire',
                'zenbook', 'vivobook', 'pavilion', 'envy', 'spectre',
                
                # Audio
                'sony', 'bose', 'sennheiser', 'jbl', 'harman', 'akg', 'audio-technica',
                'beyerdynamic', 'shure', 'beats', 'airpods', 
                'jabra', 'plantronics', 'poly', 'anker', 'soundcore', 'marshall',
                'bang olufsen', 'b&o', 'focal', 'grado', 'philips', 'panasonic',
                'skullcandy', 'jvc', 'pioneer', 'technics', 'denon', 'yamaha',
                
                # TV i Monitory
                'lg', 'sharp', 'tcl', 'hisense', 'thomson', 'grundig', 'loewe',
                'benq', 'aoc', 'viewsonic', 'iiyama', 'eizo',
                
                # Inne
                'motorola', 'moto', 'nokia', 'xperia', 'htc', 'blackberry', 
                'fairphone', 'alcatel', 'cat'
            ],
            
            # MARKI PREMIUM (20+ marek)
            'premium_brands': [
                'apple', 'samsung', 'sony', 'lg', 'bose', 'sennheiser',
                'bang olufsen', 'b&o', 'focal', 'msi', 'razer', 'alienware',
                'asus rog', 'marshall', 'bowers wilkins', 'denon', 'marantz',
                'google', 'pixel'
            ],
            
            # KATEGORIE PRODUKTÓW (150+ kategorii)
            'categories': [
                # Telefony i tablety
                'telefon', 'smartphone', 'iphone', 'smartfon', 'komórka', 'tel', 'fon',
                'tablet', 'ipad', 'czytnik', 'ebook', 'kindle',
                
                # Akcesoria mobilne
                'etui', 'case', 'futerał', 'pokrowiec', 'szkło', 'hartowane', 'folia',
                'ładowarka', 'kabel', 'powerbank', 'uchwyt', 'selfie stick', 'selfiestick',
                'adapter', 'przejściówka', 'hub', 'stacja dokująca', 'ładowarki', 'kabla',
                
                # Komputery
                'laptop', 'notebook', 'ultrabook', 'chromebook', 'macbook', 'labtop',
                'komputer', 'pc', 'desktop', 'all-in-one', 'mini pc', 'komp',
                'monitor', 'ekran', 'wyświetlacz', 'matryca', 'monit',
                'klawiatura', 'mysz', 'myszka', 'touchpad', 'trackpad', 'klaw',
                'dysk', 'ssd', 'hdd', 'pendrive', 'karta pamięci', 'pamięci',
                'ram', 'pamięć', 'procesor', 'cpu', 'karta graficzna', 'gpu',
                
                # Audio
                'słuchawki', 'headphones', 'earbuds', 'tws', 'dokanałowe', 'słuchy',
                'nauszne', 'douszne', 'bezprzewodowe', 'bluetooth', 'słuchaweczki',
                'głośnik', 'speaker', 'soundbar', 'subwoofer', 'kolumna', 'głośniki',
                'mikrofon', 'mic', 'zestaw nagłowny', 'headset', 'gaming',
                
                # TV i Video
                'telewizor', 'tv', 'television', 'smart tv', 'android tv', 'tivi', 'telewizoru',
                'projektor', 'rzutnik', 'ekran projekcyjny',
                'odtwarzacz', 'blu-ray', 'dvd', 'media player',
                'tuner', 'decoder', 'dekoder', 'android box',
                
                # Gaming
                'konsola', 'playstation', 'ps5', 'ps4', 'xbox', 'nintendo', 'switch',
                'pad', 'kontroler', 'gamepad', 'steering wheel', 'kierownica',
                'vr', 'gogle', 'oculus', 'meta quest',
                
                # Smart Home
                'smart', 'inteligentny', 'asystent', 'alexa', 'google home',
                'żarówka', 'led', 'taśma', 'strip', 'gniazdko', 'przełącznik',
                'kamera', 'monitoring', 'czujnik', 'sensor', 'alarm',
                
                # Fotografia
                'aparat', 'lustrzanka', 'bezlusterkowa', 'obiektyw', 'statyw',
                'lampa', 'ring light', 'softbox', 'karta sd'
            ],
            
            # MODELE PRODUKTÓW (200+ modeli)
            'models': [
                # iPhone
                'iphone 11', 'iphone 12', 'iphone 13', 'iphone 14', 'iphone 15', 'iphone 16',
                'iphone se', 'iphone x', 'iphone xs', 'iphone xr',
                '11 pro', '12 pro', '13 pro', '14 pro', '15 pro', '16 pro',
                'pro max', 'plus', 'mini',
                
                # Samsung Galaxy
                'galaxy s21', 'galaxy s22', 'galaxy s23', 'galaxy s24', 'galaxy s25',
                's21', 's22', 's23', 's24', 's25',
                's21 ultra', 's22 ultra', 's23 ultra', 's24 ultra',
                'galaxy z flip', 'galaxy z fold', 'z flip', 'z fold',
                'galaxy a', 'a52', 'a53', 'a54',
                
                # Google Pixel
                'pixel 6', 'pixel 7', 'pixel 8', 'pixel 9',
                'pixel 6 pro', 'pixel 7 pro', 'pixel 8 pro',
                
                # Xiaomi
                'xiaomi 12', 'xiaomi 13', 'xiaomi 14',
                'redmi note 11', 'redmi note 12', 'redmi note 13',
                'poco f4', 'poco f5', 'poco x5',
                
                # MacBook
                'macbook air', 'macbook pro',
                'm1', 'm2', 'm3', 'm4',
                'air m1', 'air m2', 'air m3',
                'pro 14', 'pro 16',
                
                # Dell
                'xps 13', 'xps 15', 'xps 17',
                'inspiron', 'latitude', 'precision',
                
                # Lenovo
                'thinkpad t14', 'thinkpad x1', 'thinkpad p1',
                't14', 't15', 'x1 carbon', 'x1 yoga',
                'legion 5', 'legion 7',
                'ideapad', 'yoga',
                
                # HP
                'elitebook', 'probook', 'zbook',
                'pavilion', 'envy', 'omen',
                '840', '850', 'g9', 'g10',
                
                # Asus
                'zenbook', 'vivobook', 'rog',
                'rog strix', 'rog zephyrus', 'tuf gaming',
                
                # Sony Słuchawki
                'wh-1000xm3', 'wh-1000xm4', 'wh-1000xm5', 'wh-1000xm6',
                'xm3', 'xm4', 'xm5',
                'wf-1000xm4', 'wf-1000xm5',
                
                # Apple Audio
                'airpods', 'airpods pro', 'airpods max',
                'airpods 2', 'airpods 3',
                'airpods pro 2', 'airpods pro 3',
                
                # Bose
                'quietcomfort', 'qc 35', 'qc 45', 'qc ultra',
                'quietcomfort 35', 'quietcomfort 45', 'quietcomfort ultra',
                
                # JBL
                'tune', 'live', 'club', 'quantum',
                'tune 510bt', 'tune 710bt', 'live 660nc',
                
                # TV Modele
                'oled55c3', 'oled65c3', 'oled77c3',
                'qe55q70c', 'qe65q70c', 'qe75qn90c',
                'kd-50x75wl', 'kd-55x75wl',
                '43p635', '55c645'
            ],
            
            # SPECYFIKACJE TECHNICZNE (100+ terminów)
            'technical_terms': [
                # Pamięć telefonów/tabletów
                '16gb', '32gb', '64gb', '128gb', '256gb', '512gb', '1tb', '2tb',
                '16g', '32g', '64g', '128g', '256g', '512g', '1t',
                
                # RAM laptopów
                '4gb ram', '8gb ram', '16gb ram', '32gb ram', '64gb ram',
                '4gb', '8gb', '16gb', '32gb', '64gb',
                
                # Storage laptopów
                '256gb ssd', '512gb ssd', '1tb ssd', '2tb ssd',
                '256ssd', '512ssd', '1tssd',
                
                # Procesory
                'intel', 'amd', 'ryzen', 'core i3', 'core i5', 'core i7', 'core i9',
                'i3', 'i5', 'i7', 'i9',
                'ryzen 3', 'ryzen 5', 'ryzen 7', 'ryzen 9',
                
                # Ekrany
                'oled', 'qled', 'neo qled', 'mini led', 'lcd', 'led', 'ips',
                'amoled', 'super amoled', 'retina',
                '4k', '8k', 'fullhd', 'full hd', 'hd', 'uhd',
                '60hz', '90hz', '120hz', '144hz', '165hz', '240hz',
                
                # Rozmiary ekranów
                '43 cale', '50 cali', '55 cali', '65 cali', '75 cali', '77 cali', '85 cali',
                '43"', '50"', '55"', '65"', '75"', '77"', '85"',
                '13 cali', '14 cali', '15 cali', '16 cali', '17 cali',
                '13.3', '14', '15.6', '16', '17.3',
                
                # Audio
                'anc', 'noise cancelling', 'bluetooth', 'bt', 'wireless', 'bezprzewodowe',
                'tws', 'true wireless', 'hi-res', 'ldac', 'aptx',
                
                # Connectivity
                'wifi', 'wi-fi', '5g', '4g', 'lte', 'usb-c', 'thunderbolt',
                'hdmi', 'displayport', 'usb 3.0', 'usb 3.1', 'usb 4.0',
                
                # Systemy
                'windows', 'macos', 'linux', 'chrome os', 'android', 'ios',
                'windows 11', 'windows 10',
                
                # Inne
                'touchscreen', 'dotykowy', '2w1', 'convertible', 'gaming',
                'biznesowy', 'do pracy', 'do gier', 'dla gracza',
                'rtx', 'gtx', 'radeon', 'geforce',
                'ssd', 'nvme', 'pcie'
            ],
            
            # WZORCE KODÓW PRODUKTÓW (REGEX)
            'product_code_patterns': [
                r'^[A-Z]{2}\d{2,}',           # MQ233, SM911
                r'^\d{4,}',                    # 12345
                r'^[A-Z]{2,}\d{2,}',          # WH1000XM5
                r'^[A-Z]\d{2,}[A-Z]',         # M2PRO
                r'^\d{2,}[A-Z]{2,}\d{2,}',   # 55Q70C
                r'^[A-Z]{2,}-\d{2,}',         # WH-1000XM5
                r'^[A-Z]\d+[A-Z]+',           # A15PRO
                r'^\d{2,}[A-Z]+\d+'          # 13PRO256
            ]
        }
        
        # === SŁOWNIK NONSENSÓW (rozszerzony dla elektroniki) ===
        self.NONSENSE_DICTIONARY = {
            'keyboard_patterns': {
                'qwerty', 'asdf', 'zxcv', 'qqqq', 'wwww', 'aaaa', 'ssss',
                'asdfgh', 'zxcvbn', 'qazwsx', 'qwertyuiop'
            },
            'conversational': {
                'nie wiem', 'co to', 'pomocy help', 'test test',
                'gdzie jest', 'jak działa', 'dlaczego', 'kiedy',
                'hello', 'world', 'testing', 'próba'
            },
            'gibberish': {
                'lorem ipsum', 'blah blah', 'ajsjdj', 'skdhfksd',
                'asdasd', 'xxxxx', 'zzzzz'
            },
            'food': {
                'pizza', 'hamburger', 'kebab', 'frytki', 'zupa',
                'pierogi', 'schabowy', 'kotlet', 'obiad', 'kolacja'
            }
        }
        
        # === PRODUCENCI (dla walidacji) ===
        self.MANUFACTURERS = {
            # Telefony
            'apple', 'samsung', 'google', 'xiaomi', 'oppo', 'realme', 'oneplus',
            'huawei', 'honor', 'motorola', 'nokia', 'sony', 'asus', 'lenovo',
            
            # Laptopy
            'dell', 'hp', 'lenovo', 'asus', 'acer', 'msi', 'apple', 'microsoft',
            'toshiba', 'fujitsu', 'alienware', 'razer', 'gigabyte',
            
            # Audio
            'sony', 'bose', 'sennheiser', 'jbl', 'apple', 'samsung',
            'jabra', 'anker', 'soundcore', 'marshall', 'beats',
            'audio-technica', 'beyerdynamic', 'shure', 'akg',
            
            # TV
            'samsung', 'lg', 'sony', 'philips', 'panasonic', 'tcl',
            'hisense', 'xiaomi', 'sharp', 'toshiba'
        }
        
        # === SLANG I POTOCZNE NAZWY ===
        self.SLANG_DICTIONARY = {
            # Telefony
            'ajfon': 'iphone',
            'aifon': 'iphone',
            'ajfony': 'iphone',
            'fon': 'telefon',
            'komurka': 'telefon',
            'tel': 'telefon',
            
            # Marki
            'sumsung': 'samsung',
            'samsug': 'samsung',
            'samsun': 'samsung',
            'samsungg': 'samsung',  # FIX: podwójna litera
            'soni': 'sony',
            'gogle': 'google',
            'googl': 'google',
            'xiaomy': 'xiaomi',
            'siaomi': 'xiaomi',
            'galexy': 'galaxy',  # FIX: literówka galaxy
            'galaksy': 'galaxy',
            'pixell': 'pixel',  # FIX: podwójna litera
            'piksel': 'pixel',
            'iphonne': 'iphone',  # FIX: podwójna litera
            
            # Laptopy
            'makbuk': 'macbook',
            'macbok': 'macbook',
            'maczek': 'macbook',
            'labtop': 'laptop',
            'lapa': 'laptop',
            'lapy': 'laptop',
            'komp': 'komputer',
            
            # Audio
            'słuchy': 'słuchawki',
            'sluchy': 'słuchawki',
            'słuchaweczki': 'słuchawki',
            'eyrpods': 'airpods',
            'airdopy': 'airpods',
            'erpods': 'airpods',
            'beaty': 'beats',
            
            # TV
            'tivi': 'telewizor',
            'tv': 'telewizor',
            
            # Inne
            'ladowarka': 'ładowarka',
            'ladowarki': 'ładowarka',
            'kejs': 'case',
            'etui': 'etui'
        }
        
        # === TERMINY WIELOJĘZYCZNE ===
        self.MULTILINGUAL_TERMS = {
            # Angielski
            'phone': 'telefon',
            'smartphone': 'smartfon',
            'laptop': 'laptop',
            'notebook': 'laptop',
            'headphones': 'słuchawki',
            'earbuds': 'słuchawki',
            'speaker': 'głośnik',
            'television': 'telewizor',
            'monitor': 'monitor',
            'keyboard': 'klawiatura',
            'mouse': 'mysz',
            
            # Niemiecki
            'handy': 'telefon',
            'kopfhörer': 'słuchawki',
            'fernseher': 'telewizor',
            'bildschirm': 'monitor',
            
            # Francuski
            'téléphone': 'telefon',
            'ordinateur': 'komputer',
            'écouteurs': 'słuchawki',
            
            # Włoski
            'telefono': 'telefon',
            'cuffie': 'słuchawki',
            'televisore': 'telewizor'
        }
        
        # === KOMPATYBILNOŚĆ WSTECZNA ===
        # Zachowaj stary AUTOMOTIVE_DICTIONARY pod inną nazwą (dla migracji)
        self.ELECTRONICS_DICTIONARY = {
            'brands': self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['brands'][:100],
            'premium_brands': self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['premium_brands'],
            'categories': self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['categories'][:50],
            'models': self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['models'][:100],
            'model_codes': self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['product_code_patterns'],
            'common_terms': self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['technical_terms'][:50]
        }
        
        print("[OK] All dictionaries loaded! Calling initialize_data()...")
        # Inicjalizacja bazy danych produktów
        try:
            self.load_products_v2()
            print("[OK] __init__() COMPLETED!")
        except Exception as e:
            print(f"[X][X][X] INITIALIZE_DATA FAILED: {e}")
            import traceback
            traceback.print_exc()
            raise


    def load_products_v2(self):
        print("[FIRE][FIRE][FIRE] INITIALIZE_DATA() METHOD CALLED! [FIRE][FIRE][FIRE]")
        """
        STRATEGIA HARDCODED - Inicjalizuje rozbudowaną bazę danych dla branży elektronicznej
        Produkty zakodowane bezpośrednio w kodzie (jak w ecommerce_bot.py dla motoryzacji)
        """
        print("[BOX] INITIALIZE_DATA() STARTED!")
        
        # PRODUKTY ELEKTRONICZNE - HARDCODED (z products.json)
        self.product_database = {
            'products': [
                # === TELEFONY - APPLE IPHONE ===
                {'id': 'iphone-13-64gb', 'name': 'Apple iPhone 13 64GB Midnight', 'category': 'telefon', 'brand': 'Apple', 'price': 3299.00, 'stock': 15, 'specs': {'storage': '64GB', 'screen': '6.1 cala', 'processor': 'A15 Bionic', 'battery': '3240mAh'}},
                {'id': 'iphone-13-128gb', 'name': 'Apple iPhone 13 128GB Starlight', 'category': 'telefon', 'brand': 'Apple', 'price': 3599.00, 'stock': 22, 'specs': {'storage': '128GB', 'screen': '6.1 cala', 'processor': 'A15 Bionic', 'battery': '3240mAh'}},
                {'id': 'iphone-13-256gb', 'name': 'Apple iPhone 13 256GB Blue', 'category': 'telefon', 'brand': 'Apple', 'price': 3999.00, 'stock': 18, 'specs': {'storage': '256GB', 'screen': '6.1 cala', 'processor': 'A15 Bionic', 'battery': '3240mAh'}},
                {'id': 'iphone-14-128gb', 'name': 'Apple iPhone 14 128GB Midnight', 'category': 'telefon', 'brand': 'Apple', 'price': 4199.00, 'stock': 25, 'specs': {'storage': '128GB', 'screen': '6.1 cala', 'processor': 'A15 Bionic', 'battery': '3279mAh'}},
                {'id': 'iphone-14-256gb', 'name': 'Apple iPhone 14 256GB Purple', 'category': 'telefon', 'brand': 'Apple', 'price': 4599.00, 'stock': 20, 'specs': {'storage': '256GB', 'screen': '6.1 cala', 'processor': 'A15 Bionic', 'battery': '3279mAh'}},
                {'id': 'iphone-14-512gb', 'name': 'Apple iPhone 14 512GB Red', 'category': 'telefon', 'brand': 'Apple', 'price': 5299.00, 'stock': 12, 'specs': {'storage': '512GB', 'screen': '6.1 cala', 'processor': 'A15 Bionic', 'battery': '3279mAh'}},
                {'id': 'iphone-15-128gb', 'name': 'Apple iPhone 15 128GB Black', 'category': 'telefon', 'brand': 'Apple', 'price': 4799.00, 'stock': 30, 'specs': {'storage': '128GB', 'screen': '6.1 cala', 'processor': 'A16 Bionic', 'battery': '3349mAh'}},
                {'id': 'iphone-15-256gb', 'name': 'Apple iPhone 15 256GB Pink', 'category': 'telefon', 'brand': 'Apple', 'price': 5199.00, 'stock': 28, 'specs': {'storage': '256GB', 'screen': '6.1 cala', 'processor': 'A16 Bionic', 'battery': '3349mAh'}},
                
                # === TELEFONY - SAMSUNG GALAXY ===
                {'id': 'galaxy-s23-128gb', 'name': 'Samsung Galaxy S23 128GB Phantom Black', 'category': 'telefon', 'brand': 'Samsung', 'price': 3699.00, 'stock': 20, 'specs': {'storage': '128GB', 'screen': '6.1 cala', 'processor': 'Snapdragon 8 Gen 2', 'battery': '3900mAh'}},
                {'id': 'galaxy-s23-256gb', 'name': 'Samsung Galaxy S23 256GB Cream', 'category': 'telefon', 'brand': 'Samsung', 'price': 3999.00, 'stock': 18, 'specs': {'storage': '256GB', 'screen': '6.1 cala', 'processor': 'Snapdragon 8 Gen 2', 'battery': '3900mAh'}},
                {'id': 'galaxy-s24-256gb', 'name': 'Samsung Galaxy S24 256GB Cobalt Violet', 'category': 'telefon', 'brand': 'Samsung', 'price': 4299.00, 'stock': 25, 'specs': {'storage': '256GB', 'screen': '6.2 cala', 'processor': 'Snapdragon 8 Gen 3', 'battery': '4000mAh'}},
                {'id': 'galaxy-s24-512gb', 'name': 'Samsung Galaxy S24 512GB Amber Yellow', 'category': 'telefon', 'brand': 'Samsung', 'price': 4799.00, 'stock': 15, 'specs': {'storage': '512GB', 'screen': '6.2 cala', 'processor': 'Snapdragon 8 Gen 3', 'battery': '4000mAh'}},
                
                # === TELEFONY - XIAOMI ===
                {'id': 'xiaomi-13-pro-256gb', 'name': 'Xiaomi 13 Pro 256GB Ceramic White', 'category': 'telefon', 'brand': 'Xiaomi', 'price': 3499.00, 'stock': 12, 'specs': {'storage': '256GB', 'screen': '6.73 cala', 'processor': 'Snapdragon 8 Gen 2', 'battery': '4820mAh'}},
                {'id': 'xiaomi-14-256gb', 'name': 'Xiaomi 14 256GB Black', 'category': 'telefon', 'brand': 'Xiaomi', 'price': 3899.00, 'stock': 20, 'specs': {'storage': '256GB', 'screen': '6.36 cala', 'processor': 'Snapdragon 8 Gen 3', 'battery': '4610mAh'}},
                
                # === TELEFONY - GOOGLE PIXEL ===
                {'id': 'pixel-8-128gb', 'name': 'Google Pixel 8 128GB Obsidian', 'category': 'telefon', 'brand': 'Google', 'price': 3299.00, 'stock': 18, 'specs': {'storage': '128GB', 'screen': '6.2 cala', 'processor': 'Google Tensor G3', 'battery': '4575mAh'}},
                {'id': 'pixel-8-256gb', 'name': 'Google Pixel 8 256GB Hazel', 'category': 'telefon', 'brand': 'Google', 'price': 3699.00, 'stock': 15, 'specs': {'storage': '256GB', 'screen': '6.2 cala', 'processor': 'Google Tensor G3', 'battery': '4575mAh'}},
                
                # === LAPTOPY - DELL ===
                {'id': 'dell-xps-13-16gb-512gb', 'name': 'Dell XPS 13 16GB RAM 512GB SSD', 'category': 'laptop', 'brand': 'Dell', 'price': 5999.00, 'stock': 8, 'specs': {'ram': '16GB', 'storage': '512GB SSD', 'screen': '13.4 cala', 'processor': 'Intel Core i7-1355U'}},
                {'id': 'dell-xps-15-32gb-1tb', 'name': 'Dell XPS 15 32GB RAM 1TB SSD', 'category': 'laptop', 'brand': 'Dell', 'price': 9999.00, 'stock': 5, 'specs': {'ram': '32GB', 'storage': '1TB SSD', 'screen': '15.6 cala', 'processor': 'Intel Core i9-13900H'}},
                
                # === LAPTOPY - LENOVO ===
                {'id': 'thinkpad-t14-8gb-256gb', 'name': 'Lenovo ThinkPad T14 8GB RAM 256GB SSD', 'category': 'laptop', 'brand': 'Lenovo', 'price': 4299.00, 'stock': 12, 'specs': {'ram': '8GB', 'storage': '256GB SSD', 'screen': '14 cale', 'processor': 'Intel Core i5-1335U'}},
                {'id': 'thinkpad-t14-16gb-512gb', 'name': 'Lenovo ThinkPad T14 16GB RAM 512GB SSD', 'category': 'laptop', 'brand': 'Lenovo', 'price': 5499.00, 'stock': 10, 'specs': {'ram': '16GB', 'storage': '512GB SSD', 'screen': '14 cale', 'processor': 'Intel Core i7-1355U'}},
                
                # === LAPTOPY - HP ===
                {'id': 'hp-elitebook-840-16gb-512gb', 'name': 'HP EliteBook 840 G10 16GB RAM 512GB SSD', 'category': 'laptop', 'brand': 'HP', 'price': 6299.00, 'stock': 7, 'specs': {'ram': '16GB', 'storage': '512GB SSD', 'screen': '14 cale', 'processor': 'Intel Core i7-1355U'}},
                
                # === LAPTOPY - APPLE MACBOOK ===
                {'id': 'macbook-air-m2-8gb-256gb', 'name': 'Apple MacBook Air M2 8GB 256GB Midnight', 'category': 'laptop', 'brand': 'Apple', 'price': 5799.00, 'stock': 15, 'specs': {'ram': '8GB', 'storage': '256GB SSD', 'screen': '13.6 cala', 'processor': 'Apple M2'}},
                {'id': 'macbook-air-m2-16gb-512gb', 'name': 'Apple MacBook Air M2 16GB 512GB Starlight', 'category': 'laptop', 'brand': 'Apple', 'price': 7599.00, 'stock': 12, 'specs': {'ram': '16GB', 'storage': '512GB SSD', 'screen': '13.6 cala', 'processor': 'Apple M2'}},
                {'id': 'macbook-pro-14-m3-18gb-512gb', 'name': 'Apple MacBook Pro 14 M3 18GB 512GB Space Black', 'category': 'laptop', 'brand': 'Apple', 'price': 9999.00, 'stock': 8, 'specs': {'ram': '18GB', 'storage': '512GB SSD', 'screen': '14.2 cala', 'processor': 'Apple M3'}},
                {'id': 'macbook-pro-16-m3-pro-36gb-512gb', 'name': 'Apple MacBook Pro 16 M3 Pro 36GB 512GB Silver', 'category': 'laptop', 'brand': 'Apple', 'price': 14999.00, 'stock': 4, 'specs': {'ram': '36GB', 'storage': '512GB SSD', 'screen': '16.2 cala', 'processor': 'Apple M3 Pro'}},
                
                # === LAPTOPY - ASUS ===
                {'id': 'asus-zenbook-14-16gb-512gb', 'name': 'Asus ZenBook 14 OLED 16GB RAM 512GB SSD', 'category': 'laptop', 'brand': 'Asus', 'price': 5299.00, 'stock': 10, 'specs': {'ram': '16GB', 'storage': '512GB SSD', 'screen': '14 cale OLED', 'processor': 'Intel Core i7-1355U'}},
                {'id': 'asus-rog-strix-32gb-1tb', 'name': 'Asus ROG Strix G16 32GB RAM 1TB SSD RTX 4070', 'category': 'laptop', 'brand': 'Asus', 'price': 8999.00, 'stock': 6, 'specs': {'ram': '32GB', 'storage': '1TB SSD', 'screen': '16 cali 165Hz', 'processor': 'Intel Core i9-13980HX'}},
                
                # === TELEWIZORY - SAMSUNG ===
                {'id': 'samsung-55-4k-qled', 'name': 'Samsung 55 cali 4K QLED QE55Q70C', 'category': 'telewizor', 'brand': 'Samsung', 'price': 3499.00, 'stock': 12, 'specs': {'screen': '55 cali', 'resolution': '4K', 'technology': 'QLED', 'refresh': '120Hz'}},
                {'id': 'samsung-65-4k-qled', 'name': 'Samsung 65 cali 4K QLED QE65Q70C', 'category': 'telewizor', 'brand': 'Samsung', 'price': 4699.00, 'stock': 10, 'specs': {'screen': '65 cali', 'resolution': '4K', 'technology': 'QLED', 'refresh': '120Hz'}},
                {'id': 'samsung-75-4k-neo-qled', 'name': 'Samsung 75 cali 4K Neo QLED QE75QN90C', 'category': 'telewizor', 'brand': 'Samsung', 'price': 8999.00, 'stock': 5, 'specs': {'screen': '75 cali', 'resolution': '4K', 'technology': 'Neo QLED', 'refresh': '144Hz'}},
                
                # === TELEWIZORY - LG ===
                {'id': 'lg-55-4k-oled', 'name': 'LG 55 cali 4K OLED OLED55C3', 'category': 'telewizor', 'brand': 'LG', 'price': 5499.00, 'stock': 8, 'specs': {'screen': '55 cali', 'resolution': '4K', 'technology': 'OLED', 'refresh': '120Hz'}},
                {'id': 'lg-65-4k-oled', 'name': 'LG 65 cali 4K OLED OLED65C3', 'category': 'telewizor', 'brand': 'LG', 'price': 7999.00, 'stock': 6, 'specs': {'screen': '65 cali', 'resolution': '4K', 'technology': 'OLED', 'refresh': '120Hz'}},
                {'id': 'lg-77-4k-oled', 'name': 'LG 77 cali 4K OLED OLED77C3', 'category': 'telewizor', 'brand': 'LG', 'price': 12999.00, 'stock': 3, 'specs': {'screen': '77 cali', 'resolution': '4K', 'technology': 'OLED', 'refresh': '120Hz'}},
                
                # === TELEWIZORY - SONY ===
                {'id': 'sony-50-4k-led', 'name': 'Sony 50 cali 4K LED KD-50X75WL', 'category': 'telewizor', 'brand': 'Sony', 'price': 2799.00, 'stock': 15, 'specs': {'screen': '50 cali', 'resolution': '4K', 'technology': 'LED', 'refresh': '60Hz'}},
                {'id': 'sony-55-4k-xr', 'name': 'Sony 55 cali 4K XR BRAVIA XR55X90L', 'category': 'telewizor', 'brand': 'Sony', 'price': 4999.00, 'stock': 10, 'specs': {'screen': '55 cali', 'resolution': '4K', 'technology': 'Full Array LED', 'refresh': '120Hz'}},
                {'id': 'sony-65-4k-xr', 'name': 'Sony 65 cali 4K XR BRAVIA XR65X90L', 'category': 'telewizor', 'brand': 'Sony', 'price': 6999.00, 'stock': 7, 'specs': {'screen': '65 cali', 'resolution': '4K', 'technology': 'Full Array LED', 'refresh': '120Hz'}},
                
                # === TELEWIZORY - TCL ===
                {'id': 'tcl-43-4k-led', 'name': 'TCL 43 cale 4K LED 43P635', 'category': 'telewizor', 'brand': 'TCL', 'price': 1699.00, 'stock': 20, 'specs': {'screen': '43 cale', 'resolution': '4K', 'technology': 'LED', 'refresh': '60Hz'}},
                {'id': 'tcl-55-4k-qled', 'name': 'TCL 55 cali 4K QLED 55C645', 'category': 'telewizor', 'brand': 'TCL', 'price': 2499.00, 'stock': 18, 'specs': {'screen': '55 cali', 'resolution': '4K', 'technology': 'QLED', 'refresh': '144Hz'}},
                
                # === SŁUCHAWKI - SONY ===
                {'id': 'sony-wh1000xm5', 'name': 'Sony WH-1000XM5 Czarne ANC', 'category': 'słuchawki', 'brand': 'Sony', 'price': 1599.00, 'stock': 25, 'specs': {'type': 'Nauszne', 'wireless': 'Bluetooth 5.2', 'anc': 'Tak', 'battery': '30h'}},
                {'id': 'sony-wh1000xm4', 'name': 'Sony WH-1000XM4 Srebrne ANC', 'category': 'słuchawki', 'brand': 'Sony', 'price': 1199.00, 'stock': 30, 'specs': {'type': 'Nauszne', 'wireless': 'Bluetooth 5.0', 'anc': 'Tak', 'battery': '30h'}},
                
                # === SŁUCHAWKI - APPLE ===
                {'id': 'airpods-pro-2', 'name': 'Apple AirPods Pro 2 USB-C', 'category': 'słuchawki', 'brand': 'Apple', 'price': 1199.00, 'stock': 40, 'specs': {'type': 'Douszne TWS', 'wireless': 'Bluetooth 5.3', 'anc': 'Tak', 'battery': '6h (30h z etui)'}},
                {'id': 'airpods-3', 'name': 'Apple AirPods 3 Lightning', 'category': 'słuchawki', 'brand': 'Apple', 'price': 799.00, 'stock': 35, 'specs': {'type': 'Douszne TWS', 'wireless': 'Bluetooth 5.0', 'anc': 'Nie', 'battery': '6h (30h z etui)'}},
                
                # === SŁUCHAWKI - BOSE ===
                {'id': 'bose-qc45', 'name': 'Bose QuietComfort 45 Czarne ANC', 'category': 'słuchawki', 'brand': 'Bose', 'price': 1399.00, 'stock': 20, 'specs': {'type': 'Nauszne', 'wireless': 'Bluetooth 5.1', 'anc': 'Tak', 'battery': '24h'}},
                {'id': 'bose-qc-ultra', 'name': 'Bose QuietComfort Ultra Białe ANC', 'category': 'słuchawki', 'brand': 'Bose', 'price': 1799.00, 'stock': 15, 'specs': {'type': 'Nauszne', 'wireless': 'Bluetooth 5.3', 'anc': 'Tak', 'battery': '24h'}},
                
                # === SŁUCHAWKI - JBL ===
                {'id': 'jbl-tune-510bt', 'name': 'JBL Tune 510BT Niebieskie', 'category': 'słuchawki', 'brand': 'JBL', 'price': 199.00, 'stock': 50, 'specs': {'type': 'Nauszne', 'wireless': 'Bluetooth 5.0', 'anc': 'Nie', 'battery': '40h'}},
                {'id': 'jbl-live-660nc', 'name': 'JBL Live 660NC Czarne ANC', 'category': 'słuchawki', 'brand': 'JBL', 'price': 599.00, 'stock': 30, 'specs': {'type': 'Nauszne', 'wireless': 'Bluetooth 5.0', 'anc': 'Tak', 'battery': '50h'}},
                
                # === SŁUCHAWKI - SENNHEISER ===
                {'id': 'sennheiser-momentum-4', 'name': 'Sennheiser Momentum 4 Czarne ANC', 'category': 'słuchawki', 'brand': 'Sennheiser', 'price': 1499.00, 'stock': 18, 'specs': {'type': 'Nauszne', 'wireless': 'Bluetooth 5.2', 'anc': 'Tak', 'battery': '60h'}},
                
                # === SŁUCHAWKI - JABRA ===
                {'id': 'jabra-elite-85h', 'name': 'Jabra Elite 85h Tytan ANC', 'category': 'słuchawki', 'brand': 'Jabra', 'price': 899.00, 'stock': 22, 'specs': {'type': 'Nauszne', 'wireless': 'Bluetooth 5.0', 'anc': 'Tak', 'battery': '36h'}}
            ]
        }
        
        # Zachowaj kompatybilność - stwórz alias
        self.products = self.product_database.get('products', [])
        
        print(f"[FIRE][FIRE][FIRE] ELEKTRO BOT PRODUCTS LOADED: {len(self.products)} [FIRE][FIRE][FIRE]")
        if len(self.products) > 0:
            print(f"[FIRE] First product: {self.products[0]['name']}")
        else:
            print("[X] WARNING: NO PRODUCTS LOADED!")
        
        # === FAQ DATABASE (opcjonalnie) ===
        self.faq_database = {}
        
        # === ORDERS DATABASE (opcjonalnie) ===
        self.orders_database = {}

    def product_config_exists_in_database(self, brand: str, model: str, storage: str = None) -> bool:
        """
        Sprawdza czy dana konfiguracja produktu istnieje w bazie.
        KLUCZOWE DLA WYKRYWANIA UTRACONEGO POPYTU!
        
        PRZYKŁADY:
        - iPhone 13 128GB -> True (mamy)
        - iPhone 13 1TB -> False (nie istnieje)
        - iPhone 14 64GB -> False (nie mamy tej konfiguracji)
        - Samsung S23 512GB -> sprawdź w bazie
        """
        if not self.products:
            return False
        
        brand_lower = brand.lower()
        model_lower = model.lower()
        storage_lower = storage.lower() if storage else None
        
        print(f"[CONFIG_CHECK] Szukam: brand={brand_lower}, model={model_lower}, storage={storage_lower}")
        
        # Przeszukaj wszystkie produkty
        for product in self.products:
            product_name = product.get('name', '').lower()
            product_brand = product.get('brand', '').lower()
            
            # 1. Sprawdź markę (musi się zgadzać!)
            brand_match = brand_lower in product_brand or brand_lower in product_name
            if not brand_match:
                continue
            
            # 2. Sprawdź model (musi być w nazwie)
            model_match = model_lower in product_name
            if not model_match:
                continue
            
            # 3. Sprawdź pamięć (jeśli podana)
            if storage_lower:
                # Sprawdź w specs.storage
                specs = product.get('specs', {})
                product_storage = specs.get('storage', '').lower()
                
                # Sprawdź też w nazwie (fallback)
                storage_in_specs = storage_lower in product_storage
                storage_in_name = storage_lower in product_name
                
                storage_match = storage_in_specs or storage_in_name
                
                if not storage_match:
                    continue  # Marka + model OK, ale pamięć NIE
            
            # Jeśli wszystko się zgadza -> istnieje!
            print(f"[CONFIG_CHECK] [OK] Znaleziono: {product_name}")
            return True
        
        # Nie znaleziono żadnego produktu z taką konfiguracją
        print(f"[CONFIG_CHECK] [X] Nie znaleziono: {brand_lower} {model_lower} {storage_lower}")
        return False
    
    def correct_query_typos(self, query: str) -> str:
        """Koryguje znane literówki w zapytaniu."""
        corrected = query
        
        # Zastosuj slang
        for typo, correct in self.SLANG_DICTIONARY.items():
            pattern = r'\b' + re.escape(typo) + r'\b'
            corrected = re.sub(pattern, correct, corrected, flags=re.IGNORECASE)
        
        # Zastosuj wielojęzyczne
        for foreign, polish in self.MULTILINGUAL_TERMS.items():
            pattern = r'\b' + re.escape(foreign) + r'\b'
            corrected = re.sub(pattern, polish, corrected, flags=re.IGNORECASE)
        
        return corrected
    
    def fix_double_letters(self, text: str) -> str:
        """
        Naprawia podwójne litery (np. 'iphonne' -> 'iphone').
        FIX: NIE psuj liczb (4000) ani kodów (wh-1000xm5)!
        """
        # Legitne podwójne litery
        legitimate_doubles = {'ll', 'pp', 'ss', 'tt', 'ff', 'oo', 'ee', 'mm', 'nn'}
        
        result = []
        i = 0
        while i < len(text):
            if i < len(text) - 1 and text[i] == text[i + 1]:
                double = text[i:i+2]
                
                # CRITICAL: NIE usuwaj podwójnych cyfr! (4000, 1000)
                if text[i].isdigit():
                    result.append(text[i])
                    result.append(text[i + 1])
                    i += 2
                # Legitna podwójna litera
                elif double in legitimate_doubles:
                    result.append(text[i])
                    result.append(text[i + 1])
                    i += 2
                else:
                    # Usuń duplikat TYLKO dla liter
                    result.append(text[i])
                    i += 2
            else:
                result.append(text[i])
                i += 1
        
        return ''.join(result)


    def has_electronics_context(self, tokens: List[str]) -> bool:
        """
        Sprawdza czy zapytanie ma kontekst elektroniczny.
        LOGIKA ELEKTRONIKI:
        - Czy zawiera markę urządzenia? (Apple, Samsung, Sony...)
        - Czy zawiera kategorię produktu? (telefon, laptop, słuchawki...)
        - Czy zawiera model? (iPhone 13, Galaxy S23, MacBook Air...)
        - Czy zawiera specyfikację? (128gb, 16gb ram, oled, anc...)
        - Czy zawiera kod produktu? (WH-1000XM5, MQ233...)
        """
        if not tokens:
            return False
        
        # Normalizuj tokeny (slang + wielojęzyczne)
        normalized_tokens = []
        for token in tokens:
            token_lower = token.lower()
            
            # Wielojęzyczne
            if token_lower in self.MULTILINGUAL_TERMS:
                token_lower = self.MULTILINGUAL_TERMS[token_lower]
            
            # Slang
            if token_lower in self.SLANG_DICTIONARY:
                token_lower = self.SLANG_DICTIONARY[token_lower]
            
            normalized_tokens.append(token_lower)
        
        # === SPRAWDZANIE KONTEKSTU ELEKTRONICZNEGO ===
        
        # 1. Czy zawiera markę?
        for token in normalized_tokens:
            if token in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['brands']:
                print(f"[CONTEXT] [OK] Znaleziono markę: {token}")
                return True
            
            # Fuzzy match dla marek (75%+ zamiast 85%)
            for brand in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['brands']:
                if fuzz.ratio(token, brand) >= 75:
                    print(f"[CONTEXT] [OK] Fuzzy marka: {token} -> {brand}")
                    return True
        
        # 2. Czy zawiera kategorię produktu?
        for token in normalized_tokens:
            if token in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['categories']:
                print(f"[CONTEXT] [OK] Znaleziono kategorię: {token}")
                return True
            
            # Fuzzy match dla kategorii (75%+ zamiast 85%)
            for category in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['categories']:
                if fuzz.ratio(token, category) >= 75:
                    print(f"[CONTEXT] [OK] Fuzzy kategoria: {token} -> {category}")
                    return True
        
        # 3. Czy zawiera model produktu?
        query_joined = ' '.join(normalized_tokens)
        for model in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['models']:
            if model in query_joined:
                print(f"[CONTEXT] [OK] Znaleziono model: {model}")
                return True
        
        # 4. Czy zawiera specyfikację techniczną?
        for token in tokens:
            token_lower = token.lower()
            
            # Pamięć: 128gb, 256gb, 512gb
            if re.match(r'^\d+(gb|g|tb|t)$', token_lower):
                print(f"[CONTEXT] [OK] Specyfikacja pamięci: {token}")
                return True
            
            # RAM: 16gb ram, 32gb
            if 'ram' in token_lower or re.match(r'^\d+gb$', token_lower):
                print(f"[CONTEXT] [OK] Specyfikacja RAM: {token}")
                return True
            
            # Ekran: oled, qled, 4k
            if token_lower in ['oled', 'qled', 'led', 'lcd', 'amoled', '4k', '8k']:
                print(f"[CONTEXT] [OK] Technologia ekranu: {token}")
                return True
            
            # Audio: anc, bluetooth
            if token_lower in ['anc', 'bluetooth', 'bt', 'tws', 'wireless']:
                print(f"[CONTEXT] [OK] Feature audio: {token}")
                return True
            
            # Rozmiar ekranu: 55 cali, 65 cali
            if re.match(r'^\d{2,3}$', token) and int(token) >= 13:
                if 'cali' in query_joined or 'cale' in query_joined or '"' in query_joined:
                    print(f"[CONTEXT] [OK] Rozmiar ekranu: {token}")
                    return True
        
        # 5. Czy zawiera kod produktu?
        for token in tokens:
            token_upper = token.upper()
            for pattern in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['product_code_patterns']:
                if re.match(pattern, token_upper):
                    print(f"[CONTEXT] [OK] Kod produktu: {token}")
                    return True
        
        # 6. Sprawdź czy istnieje w bazie produktów
        if self.products:
            for product in self.products:
                product_name_lower = product.get('name', '').lower()
                product_brand_lower = product.get('brand', '').lower()
                product_model = product.get('model', '')
                
                for token in normalized_tokens:
                    if (token in product_name_lower or 
                        token in product_brand_lower or
                        token in str(product_model).lower()):
                        print(f"[CONTEXT] [OK] Znaleziono w bazie: {token}")
                        return True
        
        print(f"[CONTEXT] [X] Brak kontekstu elektronicznego dla: {tokens}")
        return False


    def is_obvious_nonsense(self, tokens: List[str], context_score: int) -> bool:
        """
        Filtruje oczywisty nonsens PRZED analizą.
        LOGIKA ELEKTRONIKI: Łagodniejsze filtry jeśli jest kontekst elektroniczny.
        """
        if not tokens or len(tokens) == 0:
            return True
        
        query_lower = ' '.join(tokens).lower()
        
        # === WYKLUCZ SPECYFIKACJE TECHNICZNE (nigdy nie filtruj!) ===
        # Pamięć: 128gb, 256gb, 512gb
        for token in tokens:
            token_lower = token.lower()
            if re.match(r'^\d+(gb|g|tb|t)$', token_lower):
                print(f"[NONSENSE] [WARN]  Wykluczam - specyfikacja pamięci: {token}")
                return False
            
            # RAM
            if 'ram' in token_lower or re.match(r'^\d+gb$', token_lower):
                print(f"[NONSENSE] [WARN]  Wykluczam - specyfikacja RAM: {token}")
                return False
            
            # Rozmiar ekranu
            if re.match(r'^\d{2,3}$', token) and 13 <= int(token) <= 100:
                print(f"[NONSENSE] [WARN]  Wykluczam - rozmiar ekranu: {token}")
                return False
        
        # === SPRAWDŹ KONTEKST ELEKTRONICZNY ===
        has_context = self.has_electronics_context(tokens)
        
        if has_context:
            print(f"[NONSENSE] [WARN]  Ma kontekst elektroniczny - łagodniejsze filtry")
            # Jeśli jest kontekst, nie filtruj agresywnie
            return False
        
        # === FILTROWANIE NONSENSU ===
        
        # 1. Same stop words polskie
        polish_stop_words = {
            'i', 'w', 'na', 'z', 'do', 'po', 'o', 'a', 'ale', 'czy',
            'jak', 'dla', 'od', 'przy', 'bez', 'przez', 'pod', 'nad'
        }
        if all(token.lower() in polish_stop_words for token in tokens):
            print(f"[NONSENSE] [X] Same stop words")
            return True
        
        # 2. Keyboard patterns
        if any(pattern in query_lower for pattern in self.NONSENSE_DICTIONARY['keyboard_patterns']):
            print(f"[NONSENSE] [X] Keyboard pattern")
            return True
        
        # 3. Food words (ale tylko jeśli NIE ma kontekstu elektronicznego)
        if any(food in query_lower for food in self.NONSENSE_DICTIONARY['food']):
            if not has_context:
                print(f"[NONSENSE] [X] Food word bez kontekstu")
                return True
        
        # 4. Gibberish
        for gibberish in self.NONSENSE_DICTIONARY['gibberish']:
            if gibberish in query_lower:
                print(f"[NONSENSE] [X] Gibberish: {gibberish}")
                return True
        
        # 5. Powtórzenia liter (aaaa, xxxx)
        for token in tokens:
            if len(token) >= 4 and len(set(token)) == 1:
                print(f"[NONSENSE] [X] Powtórzenie litery: {token}")
                return True
        
        # 6. Conversational phrases bez kontekstu
        for phrase in self.NONSENSE_DICTIONARY['conversational']:
            if phrase in query_lower and not has_context:
                print(f"[NONSENSE] [X] Conversational bez kontekstu: {phrase}")
                return True
        
        print(f"[NONSENSE] [OK] Nie jest nonsensem")
        return False


    def is_structural_query(self, tokens: List[str]) -> bool:
        """
        Wykrywa zapytania strukturalne typu "iPhone 13 1TB" (produkt którego nie mamy).
        LOGIKA ELEKTRONIKI:
        - "iPhone 13 128GB" = mamy -> NIE structural
        - "iPhone 13 1TB" = nie mamy -> TAK structural (UTRACONY POPYT)
        - "OnePlus 12" = nie prowadzimy marki -> TAK structural
        - "Beats Studio Pro" = nie mamy tego modelu -> TAK structural
        """
        if not tokens or len(tokens) == 0:
            return False
        
        query_lower = ' '.join(tokens).lower()
        
        # === BLOKUJ NATURALNE ZAPYTANIA KONTEKSTOWE ===
        natural_context_words = {
            'do', 'dla', 'na', 'pasuje', 'czy', 'można', 'polecasz',
            'jaki', 'jaka', 'jakie', 'który', 'która', 'które',
            'kupię', 'kupie', 'szukam', 'potrzebuje', 'chcę', 'chce',
            'zimą', 'latem', 'teraz', 'tanio', 'drogo',
            'dobry', 'dobra', 'dobre', 'najlepszy', 'najlepsza',
            'pomocy', 'help', 'co', 'gdzie', 'kiedy', 'dlaczego'
        }
        
        has_context_words = any(word in query_lower for word in natural_context_words)
        
        # Jeśli są context words BEZ produktów -> blokuj (konwersacja)
        if has_context_words and not self.products:
            print(f"[STRUCTURAL] [X] Context words bez produktów - konwersacja")
            return False
        
        # Jeśli są context words + produkty -> kontynuuj (może być structural)
        
        # === KOREKTA LITERÓWEK ===
        comprehensive_typos = {
            # Telefony
            'ajfon': 'iphone', 'aifon': 'iphone', 'ipone': 'iphone',
            'sumsung': 'samsung', 'samsug': 'samsung', 'samsun': 'samsung',
            'galexy': 'galaxy', 'galaksy': 'galaxy',
            'pixell': 'pixel', 'piksel': 'pixel', 'peliks': 'pixel',
            'xiaomy': 'xiaomi', 'siaomi': 'xiaomi', 'shiaomi': 'xiaomi',
            
            # Laptopy
            'makbuk': 'macbook', 'macbok': 'macbook', 'maczek': 'macbook',
            'labtop': 'laptop', 'lapa': 'laptop', 'lapy': 'laptop',
            'thinkpadd': 'thinkpad', 'tinkpad': 'thinkpad',
            
            # Audio
            'słuchy': 'słuchawki', 'sluchy': 'słuchawki', 'sluchawki': 'słuchawki',
            'słuchaweczki': 'słuchawki',
            'eyrpods': 'airpods', 'erpods': 'airpods', 'airdopy': 'airpods',
            'airpodss': 'airpods',
            
            # TV
            'telewizorr': 'telewizor', 'tivi': 'telewizor',
            
            # Inne
            'ładowarka': 'ładowarka', 'ladowarka': 'ładowarka',
            'kabel': 'kabel', 'kabla': 'kabel',
            'etui': 'etui', 'kejs': 'case'
        }
        
        corrected_tokens = []
        for token in tokens:
            token_lower = token.lower()
            if token_lower in comprehensive_typos:
                corrected_token = comprehensive_typos[token_lower]
                print(f"[STRUCTURAL] Korekta: {token} -> {corrected_token}")
                corrected_tokens.append(corrected_token)
            else:
                corrected_tokens.append(token_lower)
        
        query_corrected = ' '.join(corrected_tokens)
        
        # === SZUKAJ KATEGORII (z fuzzy 85%+) ===
        found_category = None
        for token in corrected_tokens:
            # Dokładne dopasowanie
            if token in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['categories']:
                found_category = token
                print(f"[STRUCTURAL] [OK] Znaleziono kategorię: {token}")
                break
            
            # Fuzzy match
            for category in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['categories']:
                if fuzz.ratio(token, category) >= 85:
                    found_category = category
                    print(f"[STRUCTURAL] [OK] Fuzzy kategoria: {token} -> {category}")
                    break
            if found_category:
                break
        
        # === SZUKAJ NIEZNANEJ MARKI / NIEISTNIEJĄCEJ KONFIGURACJI ===
        unknown_brand = None
        unknown_config = None
        detected_brand = None
        detected_model = None
        detected_storage = None
        
        # === WYKRYJ MARKĘ, MODEL I PAMIĘĆ Z QUERY ===
        query_full = ' '.join(corrected_tokens)
        
        # 1. Wykryj markę (Apple, Samsung, Google, etc.)
        for token in corrected_tokens:
            if token in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['brands']:
                detected_brand = token
                break
        
        # 2. Wykryj model (iPhone 13, Galaxy S23, Pixel 8, etc.)
        # Szukaj pełnych nazw modeli w query
        for model_name in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['models']:
            if model_name in query_full:
                detected_model = model_name
                break
        
        # Jeśli nie znalazło pełnego modelu, szukaj liczb (13, 14, 15, 23, 24)
        if not detected_model:
            for token in corrected_tokens:
                # Szukaj liczb 11-99 (modele telefonów/laptopów)
                if token.isdigit() and 11 <= int(token) <= 99:
                    detected_model = token
                    break
        
        # 3. Wykryj pamięć (128gb, 256gb, 512gb, 1tb)
        for token in corrected_tokens:
            if re.match(r'^\d+(gb|tb|g|t)$', token):
                detected_storage = token
                break
        
        print(f"[STRUCTURAL] Wykryto: brand={detected_brand}, model={detected_model}, storage={detected_storage}")
        
        # === FIX #13: Sprawdź rozmiary TV! ===
        # Wykryj rozmiar ekranu (55 cali, 85 cali, 100 cali)
        detected_tv_size = None
        for token in corrected_tokens:
            if token.isdigit() and 32 <= int(token) <= 100:
                # Sprawdź czy w query jest "cali" lub "cale"
                if 'cali' in query_full or 'cale' in query_full or '"' in query_full:
                    detected_tv_size = int(token)
                    break
        
        # Jeśli wykryto rozmiar TV -> sprawdź czy mamy!
        if detected_tv_size and detected_brand and self.products:
            has_tv_size = False
            for product in self.products:
                if detected_brand in product.get('brand', '').lower():
                    # Sprawdź w specs.screen lub name
                    screen = product.get('specs', {}).get('screen', '')
                    name = product.get('name', '')
                    
                    # Szukaj rozmiaru w formacie "55 cali" lub "55"
                    if (str(detected_tv_size) in screen or 
                        str(detected_tv_size) in name):
                        has_tv_size = True
                        break
            
            if not has_tv_size:
                print(f"[STRUCTURAL] [FIRE] Nie mamy TV {detected_brand} {detected_tv_size} cali")
                return True
        
        # === FIX #11: Jeśli mamy markę + pamięć (nawet bez kategorii) -> sprawdź! ===
        # Dla zapytań typu "samsung s23 512gb" - nie ma słowa "telefon", ale to jasny intent!
        if detected_brand and detected_storage and self.products:
            # Jeśli mamy też model -> precyzyjne sprawdzenie
            if detected_model:
                exists = self.product_config_exists_in_database(
                    detected_brand, 
                    detected_model, 
                    detected_storage
                )
            # Jeśli tylko marka + pamięć -> sprawdź czy istnieje jakikolwiek produkt
            else:
                exists = self.product_config_exists_in_database(
                    detected_brand,
                    '',  # Bez modelu
                    detected_storage
                )
            
            if not exists:
                print(f"[STRUCTURAL] [FIRE] Nieistniejąca konfiguracja: {detected_brand} {detected_model} {detected_storage}")
                return True
        
        # === FIX #16: Jeśli mamy markę + model (NAWET BEZ kategorii) -> sprawdź! ===
        # Dla zapytań typu "samsung s25" lub "sony xm6" - wyraźny intent na produkt!
        if detected_brand and detected_model and self.products:
            # Sprawdź czy ten model istnieje dla tej marki
            exists = self.product_config_exists_in_database(
                detected_brand,
                detected_model,
                detected_storage  # Może być None
            )
            
            if not exists:
                print(f"[STRUCTURAL] [FIRE] Nieistniejący model: {detected_brand} {detected_model}")
                return True
        
        # === Jeśli brak kategorii I nie wykryto konfiguracji -> nie structural ===
        if not found_category:
            print(f"[STRUCTURAL] [X] Brak kategorii i brak konfiguracji do sprawdzenia")
            return False
        
        # Skip znane słowa
        known_words = (
            set(self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['brands']) |
            set(self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['categories']) |
            set(self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['technical_terms']) |
            natural_context_words |
            {'i', 'w', 'z', 'do', 'na', 'dla', 'o', 'a'}
        )
        
        for token in corrected_tokens:
            # Skip context words
            if token in natural_context_words:
                continue
            
            # === FIX #12: Sprawdź czy PROWADZIMY tę markę! ===
            # Marka może być znana (OnePlus, Huawei), ale my jej nie prowadzimy!
            if token in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['brands']:
                # Sprawdź czy marka istnieje w products.json
                if self.products:
                    brand_in_products = False
                    for product in self.products:
                        product_brand = product.get('brand', '').lower()
                        product_name = product.get('name', '').lower()
                        
                        # FIX #15: Sprawdź w brand I name!
                        # "iphone" może być w name, ale brand = "Apple"
                        if token in product_brand or token in product_name:
                            brand_in_products = True
                            break
                    
                    if not brand_in_products:
                        # Znamy markę, ale NIE PROWADZIMY!
                        unknown_brand = token
                        print(f"[STRUCTURAL] [FIRE] Marka której nie prowadzimy: {token}")
                        break
                    else:
                        # Prowadzimy tę markę - skip
                        print(f"[STRUCTURAL] Prowadzimy markę: {token}")
                        continue
                else:
                    continue
            
            # Skip kategorie
            if token in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['categories']:
                continue
            
            # Skip specyfikacje techniczne
            if token in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['technical_terms']:
                continue
            
            # Skip krótkie liczby
            if token.isdigit() and len(token) <= 2:
                continue
            
            # Skip kody produktów które istnieją
            if self.products:
                exists = False
                for product in self.products:
                    if (token in product.get('name', '').lower() or
                        token in product.get('brand', '').lower() or
                        token in str(product.get('model', '')).lower()):
                        exists = True
                        break
                if exists:
                    continue
            
            # Skip czasowniki polskie
            if token.endswith(('ować', 'ić', 'ąć', 'eć', 'yć')):
                continue
            
            # Zostaje tylko nieznane słowo!
            if len(token) >= 3:
                # === FIX #14: Sprawdź czy to literówka zanim uznasz za unknown! ===
                # Fuzzy match z markami (80%+)
                best_brand_match = 0
                for brand in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['brands']:
                    similarity = fuzz.ratio(token, brand)
                    if similarity > best_brand_match:
                        best_brand_match = similarity
                
                # Jeśli fuzzy match ≥ 80% -> to literówka, nie unknown!
                if best_brand_match >= 80:
                    print(f"[STRUCTURAL] Literówka: {token} -> {best_brand_match}% match")
                    continue
                
                # Fuzzy match z kategoriami (80%+)
                best_cat_match = 0
                for cat in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['categories']:
                    similarity = fuzz.ratio(token, cat)
                    if similarity > best_cat_match:
                        best_cat_match = similarity
                
                if best_cat_match >= 80:
                    print(f"[STRUCTURAL] Literówka kategorii: {token} -> {best_cat_match}% match")
                    continue
                
                # Sprawdź czy to marka której nie znamy
                is_likely_brand = (
                    token[0].isupper() or  # Wielka litera
                    len(token) >= 5  # Długość sugeruje markę
                )
                
                if is_likely_brand:
                    unknown_brand = token
                    print(f"[STRUCTURAL] [FIRE] Nieznana marka: {token}")
                    break
                
                # Lub nieznana konfiguracja (np. "1tb" dla iPhone 13)
                if re.match(r'^\d+(gb|tb|g|t)$', token):
                    unknown_config = token
                    print(f"[STRUCTURAL] [FIRE] Nieznana konfiguracja: {token}")
                    break
        
        # === WYNIK ===
        if unknown_brand or unknown_config:
            print(f"[STRUCTURAL] [OK] TAK - kategoria: {found_category}, unknown: {unknown_brand or unknown_config}")
            return True
        
        print(f"[STRUCTURAL] [X] NIE - wszystkie elementy znane")
        return False


    def calculate_token_validity(self, tokens: List[str]) -> float:
        """
        Oblicza średni scoring tokenów dla ELEKTRONIKI.
        LOGIKA ELEKTRONIKI:
        - Marki (Apple, Samsung): 98-100 pkt
        - Kategorie (telefon, laptop): 96 pkt
        - Modele (iPhone 13, Galaxy S23): 90-92 pkt
        - Specyfikacje (128gb, anc, oled): 85-90 pkt
        - Fuzzy match (>75%): 55-85 pkt
        """
        if not tokens:
            return 0.0
        
        token_scores = []
        
        # Literówki do korekty
        typo_corrections = {
            # Telefony
            'ajfon': 'iphone', 'aifon': 'iphone', 'ipone': 'iphone',
            'sumsung': 'samsung', 'samsug': 'samsung',
            'galexy': 'galaxy', 'pixell': 'pixel',
            'xiaomy': 'xiaomi', 'siaomi': 'xiaomi',
            
            # Laptopy
            'makbuk': 'macbook', 'labtop': 'laptop',
            'thinkpadd': 'thinkpad', 'zenbok': 'zenbook',
            
            # Audio
            'słuchy': 'słuchawki', 'sluchy': 'słuchawki',
            'eyrpods': 'airpods', 'erpods': 'airpods',
            
            # TV
            'telewizorr': 'telewizor', 'tivi': 'telewizor',
            'monitora': 'monitor', 'monit': 'monitor',
            
            # Inne
            'ladowarka': 'ładowarka', 'kabel': 'kabel'
        }
        
        for token in tokens:
            token_lower = token.lower()
            score = 0
            
            # === KOREKTA LITERÓWEK -> 85-95 pkt ===
            if token_lower in typo_corrections:
                corrected = typo_corrections[token_lower]
                score = 90
                print(f"[VALIDITY] {token} -> {corrected}: {score} pkt (literówka)")
                token_scores.append(score)
                continue
            
            # === DOKŁADNE DOPASOWANIA ===
            
            # Marki -> 98-100 pkt
            if token_lower in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['brands']:
                score = 100
                print(f"[VALIDITY] {token}: {score} pkt (marka)")
                token_scores.append(score)
                continue
            
            # Kategorie -> 96 pkt
            if token_lower in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['categories']:
                score = 96
                print(f"[VALIDITY] {token}: {score} pkt (kategoria)")
                token_scores.append(score)
                continue
            
            # Premium brands -> 98 pkt
            if token_lower in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['premium_brands']:
                score = 98
                print(f"[VALIDITY] {token}: {score} pkt (premium)")
                token_scores.append(score)
                continue
            
            # Specyfikacje techniczne -> 85-90 pkt
            if token_lower in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['technical_terms']:
                score = 88
                print(f"[VALIDITY] {token}: {score} pkt (spec)")
                token_scores.append(score)
                continue
            
            # Pamięć (128gb, 256gb) -> 90 pkt
            if re.match(r'^\d+(gb|g|tb|t)$', token_lower):
                score = 90
                print(f"[VALIDITY] {token}: {score} pkt (pamięć)")
                token_scores.append(score)
                continue
            
            # RAM (16gb ram) -> 88 pkt
            if 'ram' in token_lower:
                score = 88
                print(f"[VALIDITY] {token}: {score} pkt (RAM)")
                token_scores.append(score)
                continue
            
            # Modele - sprawdź czy występuje w modelu produktu
            query_joined = ' '.join(tokens).lower()
            found_in_model = False
            for model in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['models']:
                if model in query_joined:
                    score = 92
                    print(f"[VALIDITY] {token}: {score} pkt (model match)")
                    token_scores.append(score)
                    found_in_model = True
                    break
            if found_in_model:
                continue
            
            # === FUZZY MATCHING ===
            
            # Marki (fuzzy 75%+)
            best_brand_score = 0
            for brand in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['brands']:
                similarity = fuzz.ratio(token_lower, brand)
                if similarity > best_brand_score:
                    best_brand_score = similarity
            
            if best_brand_score >= 85:
                score = 85
                print(f"[VALIDITY] {token}: {score} pkt (fuzzy brand {best_brand_score}%)")
                token_scores.append(score)
                continue
            elif best_brand_score >= 75:
                score = 70
                print(f"[VALIDITY] {token}: {score} pkt (fuzzy brand {best_brand_score}%)")
                token_scores.append(score)
                continue
            
            # Kategorie (fuzzy 75%+)
            best_cat_score = 0
            for category in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['categories']:
                similarity = fuzz.ratio(token_lower, category)
                if similarity > best_cat_score:
                    best_cat_score = similarity
            
            if best_cat_score >= 85:
                score = 80
                print(f"[VALIDITY] {token}: {score} pkt (fuzzy category {best_cat_score}%)")
                token_scores.append(score)
                continue
            elif best_cat_score >= 75:
                score = 65
                print(f"[VALIDITY] {token}: {score} pkt (fuzzy category {best_cat_score}%)")
                token_scores.append(score)
                continue
            
            # Jeśli nic nie pasuje -> 20 pkt (neutralne)
            score = 20
            print(f"[VALIDITY] {token}: {score} pkt (nieznane)")
            token_scores.append(score)
        
        # Średnia
        avg_score = sum(token_scores) / len(token_scores) if token_scores else 0
        print(f"[VALIDITY] Średnia: {avg_score:.2f} ({len(token_scores)} tokenów)")
        return avg_score


    def get_fuzzy_product_matches_internal(self, query: str, machine_filter: Optional[str] = None) -> List[Tuple]:
        """
        Silnik wyszukiwania produktów ELEKTRONICZNYCH z fuzzy matching.
        LOGIKA ELEKTRONIKI:
        - iPhone 13 128GB -> dopasowanie marki + modelu + pamięci
        - Samsung słuchawki -> dopasowanie marki + kategorii
        - WH-1000XM5 -> dopasowanie kodu produktu
        """
        print(f"[SEARCH] FUZZY SEARCH: query='{query}', products count={len(self.products) if self.products else 0}")
        
        if not self.products:
            print("[FUZZY] [WARN]  Brak produktów w bazie")
            return []
        
        query_lower = query.lower().strip()
        query_tokens = query_lower.split()
        
        # [FIRE] NUMBER GUARD: Wyciągnij wszystkie liczby z query
        # Jeśli query ma liczby (modele, rozmiary, pamięć), produkt MUSI mieć te same liczby!
        query_numbers = set(re.findall(r'\d+', query_lower))
        
        # [FIRE] KEYWORD GUARD: Wyciągnij kluczowe słowa techniczne
        # OLED ≠ LED, QLED ≠ LED, ANC ≠ brak ANC
        # WAŻNE: Działa tylko dla PEŁNYCH specyfikacji (z liczbami/modelem)!
        critical_keywords = {
            'oled', 'qled', 'neo qled', 'led', 'lcd',  # Technologie ekranu
            'anc',  # Active Noise Cancellation
            'm1', 'm2', 'm3',  # Procesory Apple
            'rtx 4090', 'rtx 4080', 'rtx 4070', 'rtx 3060',  # Karty graficzne
            '8k', '4k',  # Rozdzielczość
        }
        query_critical = {kw for kw in critical_keywords if kw in query_lower}
        
        # [FIRE] COLOR GUARD: Wyciągnij kolory z query
        # "iPhone różowy" ≠ "iPhone midnight"
        color_keywords = {
            # Polski
            'różowy', 'pink', 'zielony', 'green', 'czerwony', 'red',
            'czarny', 'black', 'biały', 'white', 'niebieski', 'blue',
            'żółty', 'yellow', 'kremowy', 'cream', 'lawendowy', 'lavender',
            'fioletowy', 'violet', 'purple', 'szary', 'gray', 'grey',
            # Apple specific
            'midnight', 'starlight', 'sierra blue', 'alpine green', 'product red',
            # Samsung specific
            'phantom black', 'phantom white', 'phantom violet', 'lime',
            'cobalt violet', 'amber yellow',
            # Inne
            'srebrny', 'silver', 'złoty', 'gold', 'tytanowy', 'titanium'
        }
        query_colors = {color for color in color_keywords if color in query_lower}
        
        print(f"[FUZZY] Wyszukiwanie: '{query}' (tokens: {query_tokens})")
        if query_numbers:
            print(f"[NUMBER GUARD] Query zawiera liczby: {query_numbers}")
        if query_critical:
            # KEYWORD GUARD działa TYLKO jeśli query ma liczby LUB konkretny model!
            # "oled lg" (bez liczby) = szukamy listy -> NIE BLOKUJ
            # "lg 55 oled" (z liczbą) = konkretny produkt -> BLOKUJ jeśli nie ma
            has_specific_intent = bool(query_numbers) or len(query_tokens) >= 3
            if has_specific_intent:
                print(f"[KEYWORD GUARD] Query zawiera krytyczne słowa: {query_critical}")
            else:
                print(f"[KEYWORD GUARD] Pomijam (query zbyt ogólne): {query_critical}")
                query_critical = set()  # Wyłącz KEYWORD GUARD dla ogólnych zapytań
        if query_colors:
            print(f"[COLOR GUARD] Query zawiera kolory: {query_colors}")
        
        product_scores = []
        
        for product in self.products:
            # Pobierz dane produktu
            product_name = product.get('name', '').lower()
            product_brand = product.get('brand', '').lower()
            product_category = product.get('category', '').lower()
            product_model = str(product.get('model', '')).lower()
            product_id = product.get('id', '').lower()
            
            # [FIRE] NUMBER GUARD: Sprawdź liczby NAJPIERW!
            if query_numbers:
                product_numbers = set(re.findall(r'\d+', product_name))
                
                # Jeśli query ma liczby, produkt MUSI mieć WSZYSTKIE te liczby!
                if not query_numbers.issubset(product_numbers):
                    # REJECT! Liczby się nie zgadzają
                    # print(f"[NUMBER GUARD] [X] REJECT {product_name}: query={query_numbers}, product={product_numbers}")
                    continue
            
            # [FIRE] KEYWORD GUARD: Sprawdź krytyczne słowa kluczowe!
            if query_critical:
                # Jeśli query ma krytyczne słowo (np. "led"), produkt MUSI je mieć!
                # WAŻNE: Użyj word boundaries - "led" ≠ "oled"!
                product_critical = set()
                for kw in critical_keywords:
                    # Sprawdź czy słowo kluczowe występuje jako całe słowo (word boundary)
                    if re.search(r'\b' + re.escape(kw) + r'\b', product_name):
                        product_critical.add(kw)
                
                # Sprawdź czy query_critical jest podzbiorem product_critical
                if not query_critical.issubset(product_critical):
                    # REJECT! Technologia się nie zgadza (LED ≠ OLED)
                    # print(f"[KEYWORD GUARD] [X] REJECT {product_name}: query={query_critical}, product={product_critical}")
                    continue
            
            # [FIRE] COLOR GUARD: Sprawdź kolory!
            if query_colors:
                # Jeśli query ma kolor (np. "różowy"), produkt MUSI mieć ten kolor!
                product_colors = set()
                for color in color_keywords:
                    if re.search(r'\b' + re.escape(color) + r'\b', product_name):
                        product_colors.add(color)
                
                # Sprawdź czy query ma kolor którego NIE MA w produkcie
                if not query_colors.issubset(product_colors):
                    # REJECT! Kolor się nie zgadza (różowy ≠ midnight)
                    # print(f"[COLOR GUARD] [X] REJECT {product_name}: query={query_colors}, product={product_colors}")
                    continue
            
            # WAŻNE: Nie bierz pod uwagę stock, price (metadane)
            searchable_text = f"{product_name} {product_brand} {product_category} {product_model}"
            
            # Filtr kategorii
            if machine_filter and machine_filter.lower() not in product_category:
                continue
            
            score = 0
            matched_tokens = 0
            
            # === SCORING PER TOKEN ===
            for token in query_tokens:
                token_score = 0
                
                # Skip krótkie liczby bez kontekstu (eliminuje false positive na stock/price)
                if token.isdigit() and len(token) <= 2:
                    continue
                
                # 1. Dokładne dopasowanie -> 100 pkt
                if token in searchable_text:
                    token_score = 100
                    print(f"[FUZZY]   {token}: 100 pkt (exact match)")
                
                # 2. Prefix match (gal -> galaxy) -> 95 pkt
                elif any(word.startswith(token) for word in searchable_text.split()):
                    token_score = 95
                    print(f"[FUZZY]   {token}: 95 pkt (prefix)")
                
                # 3. Suffix match -> 90 pkt
                elif any(word.endswith(token) for word in searchable_text.split()):
                    token_score = 90
                    print(f"[FUZZY]   {token}: 90 pkt (suffix)")
                
                # 4. Fuzzy match (>85%) -> ~90 pkt
                else:
                    best_fuzzy = 0
                    for word in searchable_text.split():
                        similarity = fuzz.ratio(token, word)
                        if similarity > best_fuzzy:
                            best_fuzzy = similarity
                    
                    if best_fuzzy >= 85:
                        token_score = int(best_fuzzy * 0.95)  # ~80-90 pkt
                        print(f"[FUZZY]   {token}: {token_score} pkt (fuzzy {best_fuzzy}%)")
                
                if token_score > 0:
                    score += token_score
                    matched_tokens += 1
            
            # === BONUSY ===
            
            # Bonus: Marka w query
            for brand in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['brands']:
                if brand in query_lower and brand in product_brand:
                    score += 15
                    print(f"[FUZZY] Bonus marka: {brand} (+15)")
                    break
            
            # Bonus: Kategoria w query
            for category in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['categories']:
                if category in query_lower and category in product_category:
                    score += 10
                    print(f"[FUZZY] Bonus kategoria: {category} (+10)")
                    break
            
            # Bonus: Specyfikacja (128gb, 256gb, anc, oled)
            for spec in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['technical_terms']:
                if spec in query_lower and spec in product_name:
                    score += 10
                    print(f"[FUZZY] Bonus spec: {spec} (+10)")
                    break
            
            # Normalizacja (średnia)
            if matched_tokens > 0:
                normalized_score = score / len(query_tokens)
            else:
                normalized_score = 0
            
            # Próg: 35 pkt (zwiększony dla elektroniki)
            if normalized_score >= 35:
                product_scores.append((product, normalized_score))
                print(f"[FUZZY] [OK] {product_name[:50]}: {normalized_score:.1f} pkt")
        
        # Sortuj malejąco
        product_scores.sort(key=lambda x: x[1], reverse=True)
        
        print(f"[FUZZY] Znaleziono {len(product_scores)} produktów")
        return product_scores[:10]  # Top 10


    def analyze_query_intent(self, query: str, machine_filter: Optional[str] = None) -> Dict:
        """
        OPERACJA LISEK PUSTYNI - WERSJA ELEKTRONIKA
        Główny algorytm klasyfikacji zapytań dla branży RTV/AGD/IT.
        
        LOGIKA ELEKTRONIKI:
        - iPhone 13 128GB -> HIGH (mamy)
        - iPhone 13 1TB -> NO_MATCH (utracony popyt - nie istnieje)
        - ajfon 13 -> MEDIUM (literówka)
        - OnePlus 12 -> NO_MATCH (utracony popyt - nie prowadzimy marki)
        """
        query_lower = query.lower().strip()
        
        # === FIX #16: Split słów bez spacji (iphone13 -> iphone 13) ===
        import re
        query_lower = re.sub(r'([a-z])(\d)', r'\1 \2', query_lower)
        if query != query_lower:
            print(f"[ANALYZE] Split words: '{query}' -> '{query_lower}'")
        
        # === PREPROCESSING - KROK 1: Tłumacz wielojęzyczne i slang ===
        preprocessed_tokens = []
        for token in query_lower.split():
            original_token = token
            
            # Wielojęzyczne
            if token in self.MULTILINGUAL_TERMS:
                token = self.MULTILINGUAL_TERMS[token]
                print(f"[ANALYZE] Translated: {original_token} -> {token}")
            
            # Slang
            if token in self.SLANG_DICTIONARY:
                token = self.SLANG_DICTIONARY[token]
                print(f"[ANALYZE] Slang fixed: {original_token} -> {token}")
            
            preprocessed_tokens.append(token)
        
        query_lower = ' '.join(preprocessed_tokens)
        
        # === PREPROCESSING - KROK 2: Napraw podwójne litery ===
        query_before_double = query_lower
        query_lower = self.fix_double_letters(query_lower)
        if query_before_double != query_lower:
            print(f"[ANALYZE] Double letters fixed: '{query_before_double}' -> '{query_lower}'")
        
        # === PREPROCESSING - KROK 3: Korekty literówek ===
        corrected_query = self.correct_query_typos(query_lower)
        if corrected_query != query_lower:
            print(f"[ANALYZE] Typos corrected: '{query_lower}' -> '{corrected_query}'")
            query_lower = corrected_query
        
        query_tokens = query_lower.split()
        
        # DEBUG
        print(f"[ANALYZE] Query: '{query}', Tokens: {query_tokens}")
        print(f"[ANALYZE] has_electronics_context: {self.has_electronics_context(query_tokens)}")
        print(f"[ANALYZE] is_obvious_nonsense: {self.is_obvious_nonsense(query_tokens, 0)}")
        
        # === KROK 1: Filtr nonsense ===
        if self.is_obvious_nonsense(query_tokens, 0):
            return {
                'query': query,
                'tokens': query_tokens,
                'token_validity': 0,
                'best_match_score': 0,
                'confidence_level': 'LOW',
                'suggestion_type': 'nonsensical',
                'ga4_event': 'search_failure',
                'has_luxury_brand': False,
                'has_product_code': False,
                'is_structural': False,
                'is_nonsense': True,
                'matches': []
            }
        
        # === KROK 2: Sprawdź kontekst elektroniczny (ale nie odrzucaj od razu) ===
        # FIX: Zamiast odrzucać, tylko zaznaczamy czy ma kontekst
        has_electronics_ctx = self.has_electronics_context(query_tokens)
        print(f"[ANALYZE] Electronics context: {has_electronics_ctx}")
        
        # Jeśli brak kontekstu I brak dopasowania produktów = dopiero wtedy odrzuć
        # (sprawdzimy to później po wyszukiwaniu)
        
        # === KROK 2.5: Wczesne wyszukiwanie po preprocessing ===
        matches = self.get_fuzzy_product_matches_internal(query_lower, machine_filter)
        best_match_score = matches[0][1] if matches else 0
        
        if best_match_score >= 60:
            print(f"[ANALYZE] [OK] Early match: score={best_match_score}")
        
        # === KROK 3: Sprawdź token validity i structural ===
        token_validity = self.calculate_token_validity(query_tokens)
        is_structural = self.is_structural_query(query_tokens)
        
        # === WYKRYJ SPECYFIKACJE TECHNICZNE (ELEKTRONIKA) ===
        has_technical_spec = False
        has_storage_spec = False  # 128gb, 256gb
        has_ram_spec = False      # 16gb ram
        has_screen_spec = False   # oled, qled
        has_audio_spec = False    # anc, bluetooth
        has_size_spec = False     # 55 cali, 65 cali
        
        for token in query_tokens:
            token_lower = token.lower()
            
            # Pamięć (128gb, 256gb, 512gb, 1tb)
            if re.match(r'^\d+(gb|g|tb|t)$', token_lower):
                has_storage_spec = True
                has_technical_spec = True
                print(f"[ANALYZE] Spec pamięć: {token}")
            
            # RAM (16gb ram, 32gb)
            if 'ram' in token_lower or (re.match(r'^\d+gb$', token_lower) and 'ram' in query_lower):
                has_ram_spec = True
                has_technical_spec = True
                print(f"[ANALYZE] Spec RAM: {token}")
            
            # Ekran (oled, qled, 4k)
            if token_lower in ['oled', 'qled', 'neo qled', 'amoled', '4k', '8k', 'fullhd']:
                has_screen_spec = True
                has_technical_spec = True
                print(f"[ANALYZE] Spec ekran: {token}")
            
            # Audio (anc, bluetooth, tws)
            if token_lower in ['anc', 'bluetooth', 'bt', 'tws', 'wireless', 'ldac', 'aptx']:
                has_audio_spec = True
                has_technical_spec = True
                print(f"[ANALYZE] Spec audio: {token}")
            
            # Rozmiar (55 cali, 65 cali)
            if re.match(r'^\d{2,3}$', token) and int(token) >= 13:
                if 'cali' in query_lower or 'cale' in query_lower or '"' in query_lower:
                    has_size_spec = True
                    has_technical_spec = True
                    print(f"[ANALYZE] Spec rozmiar: {token}")

        
        # === KROK 4: Sprawdź czy query zawiera znane literówki ===
        known_typos_electronics = {
            'ajfon', 'aifon', 'ipone', 'sumsung', 'samsug', 'galexy',
            'makbuk', 'macbok', 'labtop', 'słuchy', 'sluchy',
            'eyrpods', 'erpods', 'airdopy', 'telewizorr', 'tivi',
            'ladowarka', 'ładowarki', 'kabel', 'kabla'
        }
        
        query_has_typos = any(token.lower() in known_typos_electronics for token in query_tokens)
        
        # Sprawdź premium brands
        has_luxury_brand = any(
            brand in query_lower 
            for brand in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['premium_brands']
        )
        
        # === KROK 5: Wykryj kody produktów ===
        potential_product_codes = []
        short_codes = []
        nonsense_codes = []
        
        for token in query_tokens:
            token_upper = token.upper()
            
            # Sprawdź czy to nie jest nonsens (same cyfry bez kontekstu)
            if (token.isdigit() and len(token) >= 6 and 
                not any(brand in query_lower for brand in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['brands']) and
                not any(cat in query_lower for cat in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['categories'])):
                nonsense_codes.append(token)
                continue
            
            # Kody produktów
            for pattern in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['product_code_patterns']:
                if re.match(pattern, token_upper):
                    potential_product_codes.append(token)
                    break
            
            # Krótkie kody (< 4 znaki)
            if len(token) >= 1 and len(token) <= 3 and token.isalnum():
                short_codes.append(token)
        
        # Jeśli same nonsense codes -> odrzuć
        if nonsense_codes and not potential_product_codes and token_validity < 30:
            return {
                'query': query,
                'tokens': query_tokens,
                'token_validity': token_validity,
                'best_match_score': 0,
                'confidence_level': 'LOW',
                'suggestion_type': 'nonsensical',
                'ga4_event': 'search_failure',
                'has_luxury_brand': False,
                'has_product_code': False,
                'is_structural': False,
                'is_nonsense': True,
                'matches': []
            }
        
        # Sprawdź czy kody istnieją w bazie
        has_nonexistent_code = False
        has_nonexistent_short_code = False
        
        if potential_product_codes and self.products:
            for code in potential_product_codes:
                code_exists = False
                for product in self.products:
                    if (code.upper() in str(product.get('model', '')).upper() or
                        code.upper() in product.get('id', '').upper() or
                        code.upper() in product.get('name', '').upper()):
                        code_exists = True
                        break
                
                if not code_exists and len(code) >= 3:
                    has_nonexistent_code = True
                    print(f"[ANALYZE] [FIRE] Nieistniejący kod: {code}")
                    break
        
        # === KROK 6: Wykryj legalne zapytania kontekstowe ===
        context_words_list = [
            'do', 'dla', 'na', 'pasuje', 'części', 'część',
            'w', 'z', 'pod', 'jaki', 'jaka', 'które',
            'dobry', 'najlepszy', 'tanio', 'polecasz', 'zł', 'złotych'
        ]
        
        has_context_words = any(
            token.lower() in context_words_list
            for token in query_tokens
        )
        
        has_known_brand = any(
            token.lower() in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['brands']
            for token in query_tokens
        )
        
        has_category = any(
            token.lower() in self.UNIVERSAL_ELECTRONICS_KNOWLEDGE['categories']
            for token in query_tokens
        )
        
        # FIX: Jeśli kontekst + (marka LUB kategoria) = zawsze legalne zapytanie!
        # Nawet jeśli best_match_score=0 (bo NUMBER GUARD/COLOR GUARD odrzuciły)
        # "iphone dla syna" = użytkownik chce LISTĘ iPhone'ów, nie Lost Demand!
        if has_context_words and (has_known_brand or has_category):
            print(f"[ANALYZE] [OK] Contextual query detected")
            
            # Jeśli są dopasowania -> HIGH/MEDIUM
            # Jeśli brak dopasowań (score=0) -> MEDIUM (pokaż listę produktów marki/kategorii)
            if best_match_score >= 70:
                confidence_level = 'HIGH'
            elif best_match_score >= 35:
                confidence_level = 'MEDIUM'
            else:
                # score < 35 (lub 0) -> MEDIUM, ale pokaż produkty z tej marki/kategorii
                confidence_level = 'MEDIUM'
            
            return {
                'query': query,
                'tokens': query_tokens,
                'token_validity': round(token_validity, 2),
                'best_match_score': round(best_match_score, 2),
                'confidence_level': confidence_level,
                'suggestion_type': 'contextual_query',
                'ga4_event': None,
                'has_luxury_brand': has_luxury_brand,
                'has_product_code': bool(potential_product_codes),
                'is_structural': is_structural,
                'is_nonsense': False,
                'matches': matches[:6] if matches else []
            }

        
        # === SPECJALNA LOGIKA DLA LITERÓWEK ===
        if is_structural and token_validity >= 70 and best_match_score < 70:
            # Mamy strukturę (kategoria + marka) ale słabe dopasowanie
            # Może to literówka która powinna zostać poprawiona
            pass
        
        # === FIX: ODRZUĆ TYLKO JEŚLI BRAK KONTEKSTU I BRAK DOPASOWANIA ===
        # Jeśli brak kontekstu elektronicznego I słabe dopasowanie -> odrzuć
        if not has_electronics_ctx and best_match_score < 30:
            print(f"[ANALYZE] [X] Brak kontekstu i dopasowania - ODRZUCAM")
            return {
                'query': query,
                'tokens': query_tokens,
                'token_validity': 0,
                'best_match_score': 0,
                'confidence_level': 'LOW',
                'suggestion_type': 'no_electronics_context',
                'ga4_event': 'search_failure',
                'has_luxury_brand': False,
                'has_product_code': False,
                'is_structural': False,
                'is_nonsense': True,
                'matches': []
            }
        
        # === KLASYFIKACJA FINALNA ===
        
        confidence_level = 'LOW'
        suggestion_type = 'unknown'
        ga4_event = None
        
        # [FIRE] PRIORYTET #0: NUMBER GUARD wykrył nieistniejący produkt!
        # Jeśli query ma kontekst elektroniczny (marka/kategoria) ALE score=0,
        # to znaczy że NUMBER GUARD odrzucił wszystkie produkty (liczby się nie zgadzają)
        # = UTRACONY POPYT!
        if has_electronics_ctx and best_match_score == 0 and (has_known_brand or has_category):
            confidence_level = 'NO_MATCH'
            suggestion_type = 'lost_demand'
            ga4_event = 'search_lost_demand'
            print(f"[ANALYZE] [FIRE] UTRACONY POPYT: NUMBER GUARD rejected all (score=0, ma kontekst)")
        
        # [FIRE] PRIORYTET #1: STRUCTURAL QUERY - ale sprawdź czy produkt istnieje!
        # Jeśli is_structural=True, to znaczy że query WYGLĄDA jak zapytanie o produkt
        # ALE trzeba sprawdzić czy ten produkt faktycznie istnieje w bazie!
        elif is_structural:
            # Jeśli mamy dobre dopasowanie (≥70) = produkt ISTNIEJE
            if best_match_score >= 70:
                confidence_level = 'HIGH'
                suggestion_type = 'exact_match'
                ga4_event = None
                print(f"[ANALYZE] [OK] STRUCTURAL + HIGH MATCH: score={best_match_score}")
            
            # Jeśli średnie dopasowanie (50-69) + tech spec = prawdopodobnie istnieje
            elif best_match_score >= 50 and has_technical_spec:
                confidence_level = 'MEDIUM'
                suggestion_type = 'technical_spec'
                ga4_event = None
                print(f"[ANALYZE] [OK] STRUCTURAL + MEDIUM: score={best_match_score}, spec=True")
            
            # Jeśli słabe dopasowanie (<50) = produkt NIE ISTNIEJE = LOST DEMAND!
            else:
                confidence_level = 'NO_MATCH'
                suggestion_type = 'lost_demand'
                ga4_event = 'search_lost_demand'
                print(f"[ANALYZE] [FIRE] UTRACONY POPYT: structural=True, score={best_match_score}")
        
        # PRIORYTET #2: NO_MATCH (nieistniejący kod)
        elif has_nonexistent_code:
            confidence_level = 'NO_MATCH'
            suggestion_type = 'nonexistent_code'
            ga4_event = 'search_lost_demand'
            print(f"[ANALYZE] [FIRE] UTRACONY POPYT: nieistniejący kod")
        
        # PRIORYTET #3: HIGH CONFIDENCE (≥60) - Dokładne dopasowanie
        elif best_match_score >= 60:
            confidence_level = 'HIGH'
            suggestion_type = 'exact_match'
            ga4_event = None
            print(f"[ANALYZE] [OK] HIGH CONFIDENCE: score={best_match_score}")
        
        # PRIORYTET #4: HIGH CONFIDENCE (≥50 + spec tech) - Specyfikacja techniczna
        elif best_match_score >= 50 and has_technical_spec:
            confidence_level = 'HIGH'
            suggestion_type = 'technical_spec'
            ga4_event = None
            print(f"[ANALYZE] [OK] HIGH (spec): score={best_match_score}, spec={has_technical_spec}")
        
        # PRIORYTET #4.5: MEDIUM CONFIDENCE (≥40 + known brand) - Dopasowanie marki
        # FIX: iPhone 13 powinien być tu (score=50, has_known_brand=True)
        elif best_match_score >= 40 and has_known_brand:
            confidence_level = 'MEDIUM'
            suggestion_type = 'brand_match'
            ga4_event = None
            print(f"[ANALYZE] [OK] MEDIUM (brand): score={best_match_score}, has_known_brand={has_known_brand}")
        
        # PRIORYTET #5: MEDIUM CONFIDENCE (≥40 + validity≥50) - Literówki poprawione
        elif best_match_score >= 40 and token_validity >= 50:
            confidence_level = 'MEDIUM'
            suggestion_type = 'fuzzy_match'
            ga4_event = 'search_typo_corrected' if query_has_typos else None
            print(f"[ANALYZE] [OK] MEDIUM: score={best_match_score}, validity={token_validity}")
        
        # PRIORYTET #6: LOW - wszystko inne
        else:
            confidence_level = 'LOW'
            suggestion_type = 'weak_match'
            ga4_event = 'search_low_confidence'
            print(f"[ANALYZE] [WARN]  LOW: score={best_match_score}, validity={token_validity}")
        
        # === RETURN RESULT ===
        return {
            'query': query,
            'tokens': query_tokens,
            'token_validity': round(token_validity, 2),
            'best_match_score': round(best_match_score, 2),
            'confidence_level': confidence_level,
            'suggestion_type': suggestion_type,
            'ga4_event': ga4_event,
            'has_luxury_brand': has_luxury_brand,
            'has_product_code': bool(potential_product_codes),
            'is_structural': is_structural,
            'is_nonsense': False,
            'matches': matches[:6] if matches else []
        }
    
    # === POMOCNICZE FUNKCJE DO INTEGRACJI ===
    
    def get_initial_greeting(self):
        """Zwraca wiadomość powitalną."""
        return {
            'text_message': GLOBAL_WELCOME_MESSAGE,
            'buttons': [
                {'text': '[PHONE] Znajdź produkt', 'action': 'search_product'}
            ]
        }
    
    def get_product_by_id(self, product_id: str):
        """Zwraca produkt po ID."""
        if not self.products:
            return None
        for product in self.products:
            if product.get('id') == product_id:
                return product
        return None
    
    def search_products(self, query: str, machine_filter: Optional[str] = None):
        """Alias dla get_fuzzy_product_matches_internal."""
        return self.get_fuzzy_product_matches_internal(query, machine_filter)

# === KONIEC KLASY EcommerceBot ===


    # === POZOSTAŁE FUNKCJE (zgodne z MOTO) ===
    
    def levenshtein_distance(self, s1: str, s2: str) -> int:
        """Oblicza odległość Levenshteina między dwoma stringami."""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def looks_like_product_query(self, tokens: List[str]) -> bool:
        """Alias dla has_electronics_context."""
        return self.has_electronics_context(tokens)
    
    def normalize_query(self, query: str) -> str:
        """Normalizuje zapytanie - usuwa znaki specjalne, małe litery."""
        query = query.lower().strip()
        query = re.sub(r'[^\w\s-]', ' ', query)
        query = re.sub(r'\s+', ' ', query)
        return query
    
    def get_fuzzy_product_matches(self, query: str, machine_filter: Optional[str] = None, 
                                  limit: int = 6, analyze_intent: bool = True) -> Tuple:
        """Wyszukiwanie produktów z analizą intencji - ZGODNE Z WATER_BOT"""
        query = self.normalize_query(query)
        
        if analyze_intent:
            analysis = self.analyze_query_intent(query, machine_filter)
            
            if analysis['confidence_level'] == 'HIGH':
                products = [(p, s) for p, s in analysis['matches'][:limit]]
            elif analysis['confidence_level'] == 'MEDIUM':
                products = [(p, s) for p, s in analysis['matches'][:limit]]
            else:
                products = [(p, s) for p, s in analysis['matches'][:3]] if analysis['matches'] else []
            
            return (
                products,
                analysis['confidence_level'],
                analysis['suggestion_type'],
                analysis
            )
        else:
            matches = self.get_fuzzy_product_matches_internal(query, machine_filter)
            return matches[:limit]
    
    def get_fuzzy_faq_matches(self, query: str, limit: int = 5) -> List[Tuple]:
        """Wyszukuje FAQ."""
        if not self.faq_database:
            return []
        
        query_lower = query.lower()
        matches = []
        
        for faq in self.faq_database:
            score = 0
            for keyword in faq['keywords']:
                if keyword in query_lower:
                    score += 100
            
            if score > 0:
                matches.append((faq, score))
        
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches[:limit]
    
    def determine_ga4_event(self, analysis: Dict) -> Optional[Dict]:
        """Określa event GA4 na podstawie analizy."""
        if not analysis.get('ga4_event'):
            return None
        
        return {
            'event_name': analysis['ga4_event'],
            'query': analysis.get('query', ''),
            'confidence': analysis.get('confidence_level', ''),
            'best_match_score': analysis.get('best_match_score', 0)
        }
    
    def extract_product_intent(self, query: str) -> str:
        """Ekstrahuje intent z zapytania."""
        query_lower = query.lower()
        
        if any(word in query_lower for word in ['kupię', 'kupie', 'szukam', 'potrzebuję']):
            return 'buying_intent'
        elif any(word in query_lower for word in ['jaki', 'który', 'polecasz']):
            return 'advisory_intent'
        elif any(word in query_lower for word in ['czy', 'pasuje', 'kompatybilny']):
            return 'compatibility_intent'
        else:
            return 'search_intent'
    
    def send_ga4_event(self, event_data: Dict) -> bool:
        """Wysyła event do GA4 (placeholder)."""
        # TODO: Implementacja GA4
        print(f"[GA4] Event: {event_data}")
        return True
    
    def search_products(self, query: str, machine_filter: Optional[str] = None) -> List:
        """Wyszukuje produkty."""
        matches = self.get_fuzzy_product_matches_internal(query, machine_filter)
        return [match[0] for match in matches]
    
    def search_faq(self, query: str) -> List:
        """Wyszukuje FAQ."""
        matches = self.get_fuzzy_faq_matches(query)
        return [match[0] for match in matches]


    def handle_button_action(self, action: str) -> Dict:
        """Obsługa akcji przycisków."""
        if action == 'main_menu':
            return {
                'text_message': 'Menu główne',
                'buttons': [
                    {'text': '[PHONE] Znajdź produkt', 'action': 'search_product'}
                ]
            }
        elif action == 'search_product':
            session['context'] = 'product_search'
            return {
                'text_message': 'Wpisz czego szukasz (np. "iPhone 13 128GB", "laptop dell", "słuchawki sony"):',
                'buttons': [],
                'enable_input': True,
                'search_mode': True,
                'input_placeholder': 'np. iPhone 13, laptop Dell, słuchawki Sony...'
            }
        elif action.startswith('show_full_card_'):
            product_id = action.replace('show_full_card_', '')
            return self.show_full_product_card(product_id)
        elif action.startswith('add_to_cart_'):
            product_id = action.replace('add_to_cart_', '')
            return self.add_to_cart(product_id)
        else:
            return {
                'text_message': 'Nieznana akcja',
                'buttons': [{'text': '↩️ Menu główne', 'action': 'main_menu'}]
            }
    
    def handle_faq(self, action: str) -> Dict:
        """Obsługa FAQ."""
        faq_mapping = {
            'faq_delivery': 'FAQ001',
            'faq_cost': 'FAQ002',
            'faq_returns': 'FAQ003',
            'faq_damaged': 'FAQ004',
            'faq_payment': 'FAQ005',
            'faq_compatibility': 'FAQ006'
        }
        
        faq_id = faq_mapping.get(action)
        if faq_id:
            faq = next((f for f in self.faq_database if f['id'] == faq_id), None)
            if faq:
                return {
                    'text_message': f"**{faq['question']}**\n\n{faq['answer']}",
                    'buttons': [
                        {'text': '❓ Inne pytanie', 'action': 'faq_search'},
                        {'text': '↩️ Menu główne', 'action': 'main_menu'}
                    ]
                }
        
        return {
            'text_message': 'Nie znaleziono odpowiedzi.',
            'buttons': [{'text': '↩️ Menu główne', 'action': 'main_menu'}]
        }
    
    def process_message(self, message: str) -> Dict:
        """Przetwarzanie wiadomości - GŁÓWNA FUNKCJA."""
        context = session.get('context', '')
        machine_filter = session.get('machine_filter')
        
        if context == 'product_search' or machine_filter:
            # Analiza zapytania
            analysis = self.analyze_query_intent(message, machine_filter)
            
            # Produkty
            products = analysis['matches'][:5]
            confidence_level = analysis['confidence_level']
            suggestion_type = analysis['suggestion_type']
            
            # GA4
            ga4_event = self.determine_ga4_event(analysis)
            if ga4_event:
                self.send_ga4_event(ga4_event)
            
            # ODPOWIEDZI NA PODSTAWIE CONFIDENCE
            if confidence_level == 'HIGH':
                if products:
                    products_text = "[OK] **Znaleźliśmy produkty:**\n\n"
                    for product, score in products:
                        products_text += f"**{product['name']}**\n"
                        products_text += f"[GRAPH] Dopasowanie: {score:.0f}% | [MONEY] {product['price']:.2f} zł\n\n"
                    
                    return {
                        'text_message': products_text,
                        'confidence_level': confidence_level,
                        'buttons': self.create_product_buttons(products)
                    }
            
            elif confidence_level == 'MEDIUM':
                if products:
                    products_text = "🤔 **Czy chodziło Ci o:**\n\n"
                    for product, score in products[:3]:
                        products_text += f"**{product['name']}**\n"
                        products_text += f"[GRAPH] Dopasowanie: {score:.0f}% | [MONEY] {product['price']:.2f} zł\n\n"
                    products_text += "\n[IDEA] *System automatycznie poprawił literówki*"
                    
                    return {
                        'text_message': products_text,
                        'confidence_level': confidence_level,
                        'buttons': self.create_product_buttons(products[:3])
                    }
            
            elif confidence_level == 'LOW':
                return {
                    'text_message': f"""❓ **Nie rozumiemy zapytania**

Sprawdź pisownię lub użyj innych słów.
Wpisana fraza: "{message}" """,
                    'confidence_level': confidence_level,
                    'buttons': [
                        {'text': '🔄 Spróbuj ponownie', 'action': 'search_product'},
                        {'text': '↩️ Menu główne', 'action': 'main_menu'}
                    ]
                }
            
            else:  # NO_MATCH - UTRACONY POPYT!
                luxury_message = ""
                if analysis.get('has_luxury_brand'):
                    luxury_message = "\n[TROPHY] **Wykryto markę premium** - zwiększony priorytet!"
                
                message_text = f"""[SEARCH] **Nie mamy tego produktu w ofercie**

Szukana fraza: "{message}"{luxury_message}

✨ **Dobra wiadomość:** Twoje zapytanie zostało zapisane! 
Jeśli wiele osób szuka tego produktu, dodamy go do naszej oferty."""
                
                return {
                    'text_message': message_text + "\n\n📧 Chcesz otrzymać powiadomienie gdy produkt będzie dostępny?",
                    'confidence_level': confidence_level,
                    'lost_demand': True,
                    'buttons': [
                        {'text': '📧 Tak, powiadom mnie', 'action': 'notify_when_available'},
                        {'text': '🔄 Szukaj czegoś innego', 'action': 'search_product'},
                        {'text': '↩️ Menu główne', 'action': 'main_menu'}
                    ]
                }
        
        # FAQ
        elif context == 'faq_search':
            faq_results = self.search_faq(message)
            
            if faq_results:
                best_match = faq_results[0]
                response = f"**{best_match['question']}**\n\n{best_match['answer']}"
                
                return {
                    'text_message': response,
                    'buttons': [
                        {'text': '❓ Zadaj inne pytanie', 'action': 'faq_search'},
                        {'text': '↩️ Menu główne', 'action': 'main_menu'}
                    ]
                }
        
        return {
            'text_message': 'Wybierz opcję:',
            'buttons': [
                {'text': '[PHONE] Szukaj produktu', 'action': 'search_product'},
                {'text': '↩️ Menu główne', 'action': 'main_menu'}
            ]
        }
    
    def create_product_buttons(self, products: List[Tuple]) -> List[Dict]:
        """Tworzy przyciski dla produktów."""
        buttons = []
        for item in products[:3]:
            if isinstance(item, tuple):
                product, score = item
                buttons.append({
                    'text': f"[CART] {product['name'][:45]}...",
                    'action': f"show_full_card_{product['id']}"
                })
        
        buttons.extend([
            {'text': '🔄 Szukaj ponownie', 'action': 'search_product'},
            {'text': '↩️ Menu główne', 'action': 'main_menu'}
        ])
        
        return buttons
    
    def show_product_details(self, product_id: str, match_score: Optional[int] = None) -> Dict:
        """Szczegóły produktu."""
        product = self.get_product_by_id(product_id)
        
        if not product:
            return {
                'text_message': 'Produkt nie znaleziony.',
                'buttons': [{'text': '↩️ Menu główne', 'action': 'main_menu'}]
            }
        
        # Sprawdź czy są specs
        specs_text = ""
        if 'specs' in product:
            specs = product['specs']
            for key, value in specs.items():
                specs_text += f"* {key}: {value}\n"
        
        return {
            'text_message': f"""[PHONE] **{product['name']}**

[MONEY] **Cena:** {product['price']:.2f} zł
[BOX] **Stan:** {product['stock']} szt.

**Specyfikacja:**
{specs_text if specs_text else 'Brak szczegółów'}""",
            'buttons': [
                {'text': f"[CART] Dodaj do koszyka", 'action': f"add_to_cart_{product['id']}"},
                {'text': '[SEARCH] Szukaj dalej', 'action': 'search_product'},
                {'text': '🏠 Menu główne', 'action': 'main_menu'}
            ]
        }
    
    def show_full_product_card(self, product_id: str) -> Dict:
        """Pokazuje pełną kartę produktu."""
        return self.show_product_details(product_id)
    
    def add_to_cart(self, product_id: str) -> Dict:
        """Dodanie do koszyka."""
        if 'cart' not in session:
            session['cart'] = []

        session['cart'].append(product_id)
        session.modified = True

        # Gold signal: jeśli poprzednie zapytanie było NO_MATCH → clicked_alternative=True
        last_no_match_session = session.get('last_no_match_qi_session')
        if last_no_match_session:
            try:
                import sqlite3
                conn = sqlite3.connect('dashboard.db')
                cur = conn.cursor()
                cur.execute('''
                    UPDATE query_intents SET clicked_alternative = 1
                    WHERE id = (
                        SELECT id FROM query_intents
                        WHERE session_id = ? AND confidence_level = 'NO_MATCH'
                        ORDER BY id DESC LIMIT 1
                    )
                ''', (last_no_match_session,))
                conn.commit()
                conn.close()
                print(f"[P3][GOLD] clicked_alternative=True for session {last_no_match_session}")
                session.pop('last_no_match_qi_session', None)
                session.modified = True
            except Exception as e:
                print(f"[P3][GOLD] Failed to update clicked_alternative: {e}")

        product = self.get_product_by_id(product_id)
        product_name = product['name'] if product else 'Produkt'

        return {
            'text_message': f"""[OK] **Dodano do koszyka!**

{product_name}""",
            'cart_updated': True,
            'buttons': [
                {'text': '[SEARCH] Kontynuuj zakupy', 'action': 'search_product'},
                {'text': '[CART] Zobacz koszyk', 'action': 'view_cart'},
                {'text': '↩️ Menu główne', 'action': 'main_menu'}
            ]
        }

# === KONIEC KLASY EcommerceBot ===