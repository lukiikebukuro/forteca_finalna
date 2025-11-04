"""
Uniwersalny Żołnierz - Silnik bota e-commerce v5.1 SURGERY FIXED
System Inteligentnego Śledzenia Utraconego Popytu - NAPRAWIONA KALIBRACJA
CZĘŚĆ 1/3 - Import i inicjalizacja
"""
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
    config_path = 'config_teksty.json'
    try:
        # Używamy 'utf-8' dla poprawnego odczytu emoji 🧪
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = json.load(f)

        # Łączymy linie z tablicy w jeden string, używając znaku nowej linii
        welcome_lines = config_data.get('welcome_message_lines', [])
        return "\n".join(welcome_lines)

    except FileNotFoundError:
        print(f"BŁĄD KRYTYCZNY: Nie znaleziono pliku {config_path}. Używam domyślnego powitania.")
        return "Błąd: Nie można załadować konfiguracji powitania."
    except Exception as e:
        print(f"BŁĄD KRYTYCZNY: Błąd podczas ładowania {config_path}: {e}")
        return "Błąd: Nie można załadować konfiguracji powitania."

# --- ZAŁADOWANIE KONFIGURACJI PRZY STARCIE ---
# Ta zmienna będzie zawierać gotowy tekst powitania
GLOBAL_WELCOME_MESSAGE = load_welcome_message_from_config()

class EcommerceBot:
    def __init__(self):
        self.product_database = {}
        self.faq_database = {}
        self.orders_database = {}
        self.current_context = None
        self.search_cache = {}
        
        # === UNIWERSALNA BAZA WIEDZY MOTORYZACYJNA (ROZSZERZONA) ===
        self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE = {
            # MARKI SAMOCHODÓW EUROPEJSKICH I ŚWIATOWYCH (300+ marek)
            'car_brands': [
                # Niemieckie
                'bmw', 'mercedes', 'mercedes-benz', 'audi', 'volkswagen', 'vw', 'opel', 'porsche',
                'mini', 'smart', 'maybach', 'brabus', 'alpina', 'wiesmann', 'gumpert', 'melkus',
                
                # Francuskie  
                'renault', 'peugeot', 'citroen', 'bugatti', 'alpine', 'ds', 'simca', 'talbot',
                
                # Włoskie
                'fiat', 'ferrari', 'lamborghini', 'maserati', 'alfa romeo', 'lancia', 'abarth',
                'pagani', 'de tomaso', 'lancia', 'iveco',
                
                # Brytyjskie
                'bentley', 'rolls-royce', 'aston martin', 'jaguar', 'land rover', 'lotus', 'mclaren',
                'mini', 'mg', 'triumph', 'tvr', 'caterham', 'morgan', 'noble', 'ginetta',
                
                # Hiszpańskie/Czeskie/Inne EU
                'seat', 'skoda', 'dacia', 'tatra', 'lada', 'uaz', 'gaz', 'moskvitch',
                
                # Amerykańskie
                'ford', 'chevrolet', 'dodge', 'chrysler', 'cadillac', 'lincoln', 'buick', 'gmc',
                'jeep', 'hummer', 'tesla', 'pontiac', 'oldsmobile', 'plymouth',
                
                # Japońskie
                'toyota', 'honda', 'nissan', 'mazda', 'mitsubishi', 'suzuki', 'subaru', 'lexus',
                'infiniti', 'acura', 'isuzu', 'daihatsu', 'scion',
                
                # Koreańskie
                'hyundai', 'kia', 'daewoo', 'ssangyong', 'genesis',
                
                # Chińskie (rosnące w EU)
                'geely', 'byd', 'mg', 'lynk', 'polestar', 'nio', 'xpeng', 'li',
                
                # Szwedzkie/Nordyckie
                'volvo', 'saab', 'koenigsegg',
                
                # Inne
                'dacia', 'lada', 'proton', 'perodua', 'tata', 'mahindra'
            ],
            
            # MARKI MOTOCYKLOWE (150+ marek)
            'motorcycle_brands': [
                'yamaha', 'honda', 'suzuki', 'kawasaki', 'ducati', 'bmw', 'ktm', 'husqvarna',
                'aprilia', 'moto guzzi', 'triumph', 'harley-davidson', 'harley', 'davidson',
                'indian', 'victory', 'buell', 'erik buell', 'zero', 'energica',
                'mv agusta', 'benelli', 'moto morini', 'bimota', 'cagiva', 'husaberg',
                'gas gas', 'sherco', 'beta', 'tm racing', 'ossa', 'montesa', 'bultaco',
                'gilera', 'piaggio', 'vespa', 'kymco', 'sym', 'pgo', 'genuine', 'lance',
                'cfmoto', 'lifan', 'zongshen', 'loncin', 'shineray', 'keeway', 'hyosung',
                'daelim', 'royal enfield', 'bajaj', 'tvs', 'hero', 'mahindra'
            ],
            
            # MARKI LUKSUSOWE/SUPERCAR (30+ marek)
            'luxury_brands': [
                'ferrari', 'lamborghini', 'porsche', 'bentley', 'rolls-royce', 'aston martin',
                'maserati', 'mclaren', 'bugatti', 'pagani', 'koenigsegg', 'lotus',
                'alfa romeo', 'jaguar', 'maybach', 'brabus', 'alpina', 'ac schnitzer',
                'hamann', 'mansory', 'gemballa', 'techart', 'ruf', 'wiesmann'
            ],
            
            # KATEGORIE CZĘŚCI (200+ kategorii)
            'part_categories': [
                # Układ hamulcowy
                'klocki', 'klocek', 'tarcza', 'tarczy', 'tarcze', 'hamulcowe', 'hamulec', 'hamulce',
                'bęben', 'szczęki', 'cylinder', 'zacisk', 'tłok', 'płyn hamulcowy', 'przewód',
                'wzmacniacz', 'abs', 'esp', 'ebd', 'ręczny',
                
                # Filtry
                'filtr', 'filtry', 'oleju', 'powietrza', 'paliwa', 'kabinowy', 'węglowy',
                'cząstek', 'dpf', 'fap', 'katalityczny', 'adblue', 'mocznik',
                
                # Zawieszenie
                'amortyzator', 'amortyzatory', 'sprężyna', 'sprężyny', 'wahacz', 'wahacze',
                'łożysko', 'piasta', 'przegub', 'stabilizator', 'tuleja', 'poduszka',
                'sworzeń', 'drążek', 'kolumna', 'mcpherson', 'multillink',
                
                # Układ zapłonowy/elektryczny
                'świeca', 'świece', 'zapłonowa', 'żarowa', 'cewka', 'zapłonu', 'rozdzielacz',
                'kondensator', 'przerywacz', 'moduł', 'ecu', 'komputer', 'sterownik',
                'sensor', 'czujnik', 'lambda', 'mas', 'map', 'ckp', 'cmp',
                
                # Akumulatory i elektryka
                'akumulator', 'akumulatory', 'bateria', 'alternator', 'rozrusznik', 'stacyjka',
                'bezpiecznik', 'przekaźnik', 'wiązka', 'kabel', 'żarówka', 'led', 'reflektor',
                'lampa', 'światło', 'kierunkowskaz', 'stop', 'cofania', 'przeciwmgielne',
                
                # Oleje i płyny
                'olej', 'oleje', 'silnikowy', 'przekładniowy', 'hydrauliczny', 'wspomagania',
                'chłodnica', 'płyn', 'płyny', 'antyfriz', 'koncentrat', 'gotowy',
                'syntetyczny', 'półsyntetyczny', 'mineralny', 'longlife',
                
                # Układ napędowy
                'łańcuch', 'napędowy', 'rozrząd', 'rozrządu', 'pasek', 'timing', 'rolka',
                'napinacz', 'sprzęgło', 'tarcza sprzęgła', 'docisk', 'łożysko sprzęgła',
                'skrzynia', 'biegów', 'manual', 'automatyczna', 'cvt', 'dsg', 'tiptronic',
                
                # Układ wydechowy
                'wydech', 'tłumik', 'katalizator', 'dpf', 'fap', 'rura', 'kolektor',
                'downpipe', 'manifold', 'lambda', 'egr', 'zawór', 'turbo', 'intercooler',
                
                # Karoseria
                'błotnik', 'zderzak', 'maska', 'klapa', 'drzwi', 'próg', 'słupek',
                'dach', 'spoiler', 'grill', 'atrapa', 'lusterko', 'szyba', 'okno',
                'uszczelka', 'guma', 'listwy', 'chromowane', 'plastikowe',
                
                # Opony i koła
                'opona', 'opony', 'koło', 'koła', 'felga', 'felgi', 'zimowe', 'letnie',
                'całoroczne', 'wielosezonowe', 'sportowe', 'terenowe', 'runflat', 'tubeless',
                'aluminiowe', 'stalowe', 'truck', 'przemysłowe', 'rolnicze',
                
                # Układ chłodzenia
                'chłodnica', 'termostat', 'pompa', 'wody', 'wentylator', 'czujnik temperatury',
                'śruba spustowa', 'korek', 'wąż', 'przewód chłodzenia', 'zbiornik',
                'wyrównawczy', 'ekspansyjny', 'ciśnieniowy'
            ],
            
            # MODELE SAMOCHODÓW (500+ modeli)
            'car_models': [
                # BMW
                'e30', 'e36', 'e46', 'e90', 'e91', 'e92', 'e93', 'f30', 'f31', 'f32', 'f33', 'f34', 'g20', 'g21',
                'e39', 'e60', 'e61', 'f10', 'f11', 'g30', 'g31', 'e38', 'e65', 'e66', 'f01', 'f02', 'g11', 'g12',
                'e23', 'e32', 'e34', 'e37', 'e38', 'e53', 'e70', 'e71', 'f15', 'f16', 'g01', 'g02', 'g05',
                
                # Mercedes
                'w124', 'w202', 'w203', 'w204', 'w205', 'w206', 'w210', 'w211', 'w212', 'w213', 'w220', 'w221', 'w222',
                'w140', 'w126', 'w123', 'w201', 'w163', 'w164', 'w166', 'w251', 'w169', 'w176', 'w177', 'w245', 'w246', 'w247',
                
                # Audi  
                'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8',
                'tt', 'r8', 'rs3', 'rs4', 'rs5', 'rs6', 'rs7', 'rs8', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8',
                'b5', 'b6', 'b7', 'b8', 'b9', 'c4', 'c5', 'c6', 'c7', 'c8', 'd2', 'd3', 'd4', 'd5',
                
                # VW
                'golf', 'polo', 'passat', 'bora', 'jetta', 'vento', 'scirocco', 'corrado', 'beetle', 'lupo',
                'fox', 'up', 'tiguan', 'touran', 'touareg', 'sharan', 'eos', 'phaeton', 'arteon',
                'caddy', 'transporter', 't4', 't5', 't6', 'crafter', 'amarok',
                
                # Toyota
                'corolla', 'yaris', 'auris', 'avensis', 'camry', 'prius', 'rav4', 'land cruiser', 'hilux',
                'aygo', 'iq', 'verso', 'previa', 'sienna', 'highlander', 'sequoia', 'tacoma', 'tundra',
                'e90', 'e100', 'e110', 'e120', 'e130', 'e140', 'e150', 'e160', 'e170', 'e180', 'e210',
                
                # Ford
                'focus', 'fiesta', 'mondeo', 'fusion', 'escort', 'sierra', 'granada', 'scorpio',
                'ka', 'puma', 'cougar', 'probe', 'mustang', 'taurus', 'crown', 'kuga', 'edge',
                'transit', 'courier', 'ranger', 'f150', 'f250', 'f350', 'expedition', 'explorer',
                
                # Opel
                'astra', 'corsa', 'vectra', 'insignia', 'omega', 'calibra', 'tigra', 'gt', 'speedster',
                'meriva', 'zafira', 'antara', 'frontera', 'mokka', 'grandland', 'crossland',
                'vivaro', 'movano', 'combo', 'arena',
                
                # Pozostałe marki z popularnymi modelami
                'clio', 'megane', 'scenic', 'laguna', 'espace', 'kangoo', 'trafic', 'master', 'captur', 'kadjar',
                '206', '207', '208', '306', '307', '308', '406', '407', '408', '508', '607', '807', '3008', '5008',
                'partner', 'berlingo', 'jumpy', 'jumper', 'boxer', 'expert', 'dispatch',
                'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c8', 'xsara', 'picasso', 'berlingo', 'nemo',
                'ibiza', 'cordoba', 'leon', 'toledo', 'altea', 'alhambra', 'arosa', 'mii', 'ateca', 'tarraco',
                'fabia', 'octavia', 'superb', 'felicia', 'roomster', 'yeti', 'kodiaq', 'karoq', 'scala', 'kamiq',
                'sandero', 'logan', 'duster', 'lodgy', 'dokker', 'stepway',
                'punto', 'panda', 'uno', 'tipo', 'tempra', 'bravo', 'brava', 'stilo', 'croma', 'doblo', 'ducato',
                'civic', 'accord', 'jazz', 'insight', 'legend', 'prelude', 'nsx', 'crv', 'hrv', 'pilot', 'ridgeline',
                'i10', 'i20', 'i30', 'i40', 'getz', 'accent', 'elantra', 'sonata', 'tucson', 'santa', 'terracan', 'galloper',
                'picanto', 'rio', 'ceed', 'cerato', 'optima', 'magentis', 'sorento', 'sportage', 'carnival', 'pregio',
                'micra', 'almera', 'primera', 'maxima', 'sunny', 'bluebird', 'skyline', 'patrol', 'terrano', 'navara',
                'mx5', 'mx6', 'rx7', 'rx8', '323', '626', '929', 'xedos', 'premacy', 'tribute', 'cx3', 'cx5', 'cx7', 'cx9',
                'colt', 'lancer', 'galant', 'eclipse', 'pajero', 'shogun', 'l200', 'outlander', 'asx', 'carisma',
                'impreza', 'legacy', 'outback', 'forester', 'tribeca', 'justy', 'svx', 'brat', 'wrx', 'sti'
            ],
            
            # MODELE MOTOCYKLI (200+ modeli)
            'motorcycle_models': [
                # Yamaha
                'r1', 'r6', 'r3', 'r125', 'r15', 'yzf', 'fz1', 'fz6', 'fz8', 'fz09', 'fz10', 'fz25',
                'mt01', 'mt03', 'mt07', 'mt09', 'mt10', 'mt125', 'xj6', 'xj900', 'xjr', 'fazer',
                'tdm', 'tdm850', 'tdm900', 'xt', 'xt660', 'wr', 'wr125', 'wr250', 'wr450',
                'tmax', 't-max', 'xmax', 'x-max', 'majesty', 'aerox', 'jog', 'vino', 'zuma',
                
                # Honda
                'cbr', 'cbr125', 'cbr250', 'cbr300', 'cbr600', 'cbr650', 'cbr900', 'cbr929', 'cbr954', 'cbr1000',
                'cb', 'cb125', 'cb250', 'cb300', 'cb500', 'cb600', 'cb650', 'cb750', 'cb900', 'cb1000', 'cb1100',
                'hornet', 'hornet600', 'hornet900', 'vtec', 'vfr', 'vfr400', 'vfr750', 'vfr800', 'vfr1200',
                'varadero', 'xl', 'xl125', 'xl600', 'xl650', 'xl700', 'xl1000', 'transalp', 'africa twin',
                'shadow', 'rebel', 'fury', 'stateline', 'interstate', 'sabre', 'aero',
                'pcx', 'sh', 'vision', 'lead', 'dio', 'beat', 'click', 'wave', 'sonic',
                
                # Suzuki
                'gsx', 'gsxr', 'gsxr125', 'gsxr250', 'gsxr600', 'gsxr750', 'gsxr1000', 'gsx1250', 'gsx1400',
                'bandit', 'bandit400', 'bandit600', 'bandit650', 'bandit1200', 'bandit1250',
                'sv', 'sv650', 'sv1000', 'gladius', 'inazuma', 'tu', 'tu250', 'gz', 'gz125', 'gz250',
                'vstrom', 'v-strom', 'vstrom650', 'vstrom1000', 'dl', 'dl650', 'dl1000',
                'hayabusa', 'bking', 'b-king', 'katana', 'gsf', 'gsf600', 'gsf1200', 'gsf1250',
                'burgman', 'address', 'lets', 'uh', 'an', 'ay', 'uc'
            ],
            
            # TERMINY TECHNICZNE (100+ terminów)
            'technical_terms': [
                'przód', 'tył', 'przedni', 'tylny', 'lewy', 'prawy', 'środkowy', 'górny', 'dolny',
                'diesel', 'benzyna', 'lpg', 'cng', 'hybrid', 'elektryczny', 'wodorowy',
                'tdi', 'tsi', 'tfsi', 'fsi', 'cdi', 'hdi', 'tdci', 'dci', 'jtd', 'crdi',
                'turbo', 'twin-turbo', 'biturbo', 'supercharger', 'kompressor', 'aspirated',
                'manual', 'automatyczna', 'cvt', 'dsg', 'tiptronic', 'multitronic', 'xtronic',
                'quattro', 'xdrive', '4motion', '4wd', 'awd', 'rwd', 'fwd', 'haldex',
                'sport', 'racing', 'premium', 'luxury', 'heavy', 'duty', 'performance', 'eco',
                'komplet', 'zestaw', 'para', 'sztuka', 'szt', 'piece', 'set', 'kit',
                'oryginał', 'oem', 'oe', 'genuine', 'aftermarket', 'zamiennik', 'replacement',
                'tuning', 'styling', 'carbon', 'aluminium', 'steel', 'plastic', 'rubber',
                'zimowe', 'letnie', 'całoroczne', 'wielosezonowe', 'all-season', 'winter', 'summer'
            ],
            
            # KODY PRODUKTÓW - WZORCE (rozszerzone)
            'product_code_patterns': [
                r'^[A-Z]\d{2,}',         # np. A123, B45
                r'^\d{4,}',              # np. 12345
                r'^[A-Z]{2,}\d{2,}',     # np. OEM123
                r'^[A-Z]\d+[A-Z]+',      # np. A123BC
                r'^\d+[A-Z]+\d*',        # np. 123ABC, 123ABC456
                r'^[A-Z]+\d+[A-Z]*',     # np. ABC123, ABC123D
                r'^[A-Z]-\d+',           # np. A-123
                r'^\d+-\d+',             # np. 123-456
                r'^[A-Z]{1,3}\d{1,4}[A-Z]{0,3}$'  # np. A4, C200, BMW320
            ]
        }
        
        # === SŁOWNIK NONSENSU (NOWY ZASÓB) ===
        self.NONSENSE_DICTIONARY = {
            'keyboard_patterns': [
                'qwerty', 'qwert', 'asdf', 'asdfg', 'zxcv', 'zxcvb', 'qwe', 'asd', 'zxc',
                'qaz', 'wsx', 'edc', 'rfv', 'tgb', 'yhn', 'ujm', 'ik', 'ol', 'mnb',
                'qqqq', 'wwww', 'eeee', 'rrrr', 'tttt', 'yyyy', 'uuuu', 'iiii', 'oooo', 'pppp',
                'asdasd', 'qweqwe', 'zxczxc', 'fghfgh', 'jkljkl', 'dfgdfg', 'cvbcvb'
            ],
            'conversational_phrases': [
                'nie wiem', 'co to', 'jak to', 'gdzie jest', 'kiedy będzie', 'czy można',
                'dlaczego nie', 'co jest', 'pomocy help', 'co szukam', 'help me', 'pomoc',
                'test test', 'przykład przykład', 'nic nic', 'cokolwiek cokolwiek',
                'nie rozumiem', 'co mam', 'jak mam', 'gdzie mam', 'kiedy mam',
                'czy jest', 'czy ma', 'czy będzie', 'czy można', 'czy warto',
                'hello world', 'test123', 'testing', 'próba próba', 'sprawdzam',
                'działa to', 'nie działa', 'zepsuło się', 'co tu', 'jak tu',
                'gdzie są', 'kiedy są', 'jak działa', 'co robi', 'dlaczego tak'
            ],
            'gibberish_patterns': [
                'lorem ipsum', 'dolor sit', 'consectetur', 'adipiscing', 'elit sed',
                'blah blah', 'bla bla', 'tra la la', 'na na na', 'he he he',
                'ajsjdj', 'lkjlkj', 'mnmnmn', 'xcvxcv', 'bnbnbn', 'fghfgh',
                'asasas', 'dedede', 'fgfgfg', 'hjhjhj', 'klklkl', 'zazaza',
                'xyzxyz', 'abcabc', 'defdef', 'ghighi', 'jkljkl', 'mnomno'
            ],
            'test_words': [
                'test', 'testing', 'próba', 'sprawdzenie', 'check', 'verify',
                'demo', 'sample', 'example', 'przykład', 'wzór', 'szablon',
                'debug', 'error', 'błąd', 'problem', 'issue', 'bug'
            ],
            'single_chars_and_numbers': [
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
                '11', '22', '33', '44', '55', '66', '77', '88', '99', '00'
            ],
            'english_nonsense': [
                'hello', 'world', 'test', 'check', 'sample', 'example', 'demo',
                'please', 'thanks', 'okay', 'yes', 'no', 'maybe', 'sure'
            ],
            'food_words': [
                'pizza', 'hamburger', 'burger', 'food', 'eat', 'drink', 'meal',
                'restaurant', 'kitchen', 'cook', 'recipe', 'ingredients'
            ]
        }
        self.PARTS_MANUFACTURERS = {
            'brembo', 'ate', 'trw', 'ferodo', 'textar', 'bosch', 'pagid', 
            'zimmermann', 'jurid', 'bendix', 'akebono', 'ebc', 'mann', 
            'mahle', 'hengst', 'ufi', 'knecht', 'purflux', 'champion', 
            'fram', 'wix', 'k&n', 'bilstein', 'sachs', 'kyb', 'monroe', 
            'koni', 'eibach', 'h&r', 'ngk', 'denso', 'beru', 'magneti',
            'varta', 'exide', 'yuasa', 'centra', 'moll', 'continental', 
            'michelin', 'bridgestone', 'goodyear', 'pirelli', 'dunlop', 
            'hankook', 'nokian', 'falken', 'yokohama', 'castrol', 'mobil', 
            'shell', 'total', 'motul', 'liqui', 'moly', 'febi', 'gsp'
        }

        # === SŁOWNIK SLANGU MECHANIKÓW ===
        self.SLANG_DICTIONARY = {
            'amory': 'amortyzator', 'aku': 'akumulator', 'akum': 'akumulator',
            'beemka': 'bmw', 'merola': 'mercedes', 'merol': 'mercedes',
            'diesla': 'diesel', 'diesl': 'diesel', 'benza': 'benzyna',
            'zimówki': 'zimowe', 'zimówka': 'zimowe', 'feldze': 'felgi',
            'felga': 'felgi', 'części': 'części', 'czesci': 'części',
            'kloce': 'klocki', 'amory': 'amortyzator', 'świece': 'świeca','longlife': 'longlife',  # To nie jest unknown brand!
    'półsyntetyk': 'półsyntetyczny',
    'syntetyk': 'syntetyczny',
    'lato': 'letnie',
    'zima': 'zimowe',
    'mróz': 'zima',
    'benz': 'benzyna',
    'benza': 'benzyna',
    'zimówki': 'zimowe',
    'zimówka': 'zimowe'
        }
        
        # === SŁOWNIK WIELOJĘZYCZNY ===
        self.MULTILINGUAL_TERMS = {
            'brake': 'hamulce', 'pads': 'klocki', 'oil': 'olej',
            'filter': 'filtr', 'battery': 'akumulator', 'spark': 'świeca',
            'plug': 'świeca', 'parts': 'części', 'für': 'dla',
            'reifen': 'opony', 'bremsen': 'hamulce', 'huile': 'olej',
            'freni': 'hamulce', 'freno': 'hamulce'
        }
        
        # === WZORCE PODWÓJNYCH LITER ===
        self.DOUBLE_LETTER_PATTERNS = [
            ('kk', 'k'), ('ll', 'l'), ('rr', 'r'), ('tt', 't'),
            ('cc', 'c'), ('ii', 'i'), ('oo', 'o'), ('aa', 'a'),
            ('ee', 'e'), ('zz', 'z'), ('ss', 's'), ('mm', 'm')
        ]    
        
        # === POŁĄCZENIE STARYCH I NOWYCH SŁOWNIKÓW ===
        # Zachowaj stary AUTOMOTIVE_DICTIONARY dla kompatybilności wstecznej
        self.AUTOMOTIVE_DICTIONARY = {
            'brands': self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands'][:50],  # Pierwsze 50 dla kompatybilności
            'luxury_brands': self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['luxury_brands'],
            'categories': self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories'][:30],  # Pierwsze 30
            'car_models': self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_models'][:50],  # Pierwsze 50
            'model_codes': self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['product_code_patterns'],
            'common_terms': self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['technical_terms'][:30],  # Pierwsze 30
            'motorcycle_terms': self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands'] + self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_models'][:20]
        }
        
        # Słownik polski rozszerzony
        self.POLISH_DICTIONARY = {
            'część', 'części', 'samochód', 'auto', 'pojazd', 'silnik', 'motor',
            'skrzynia', 'bieg', 'biegi', 'koło', 'koła', 'opona', 'opony',
            'szyba', 'szyby', 'lusterko', 'lusterka', 'drzwi', 'maska', 'bagażnik',
            'kierownica', 'deska', 'rozdzielcza', 'fotel', 'fotele', 'siedzenie', 'siedzenia',
            'zderzak', 'zderzaki', 'błotnik', 'błotniki', 'reflektor', 'reflektory',
            'lampa', 'lampy', 'światło', 'światła', 'wycieraczka', 'wycieraczki',
            'pióro', 'pióra', 'klapa', 'klapy', 'próg', 'progi', 'słupek', 'słupki',
            'zimowe', 'letnie', 'całoroczne', 'wielosezonowe', 'sportowe', 'terenowe',
            'miejskie', 'szosowe', 'nowe', 'używane', 'oryginalne', 'zamiennikowe',
            'tanie', 'drogie', 'dobre', 'najlepsze', 'polecane', 'popularne'
        }
        
        
        
        self.initialize_data()
    
    def initialize_data(self):
        """
        STRATEGIA 50/50 - Inicjalizuje rozbudowaną bazę danych dla branży motoryzacyjnej
        ZASÓB A (50%): Faktyczne produkty w systemie
        ZASÓB B (50%): Słownik wiedzy dla looks_like_product_query
        """
        
        # ZASÓB A (50%) - FAKTYCZNE PRODUKTY W SYSTEMIE (rozszerzone z 30 do 80+ produktów)
        self.product_database = {
            'products': [
                # === SAMOCHODY OSOBOWE - KLOCKI HAMULCOWE ===
                {'id': 'KH001', 'name': 'Klocki hamulcowe przód Bosch BMW E90 320i', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'Bosch', 'model': '0986494104', 'price': 189.00, 'stock': 45},
                {'id': 'KH002', 'name': 'Klocki hamulcowe tył ATE Mercedes W204 C200', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'ATE', 'model': '13.0460-7218', 'price': 156.00, 'stock': 38},
                {'id': 'KH003', 'name': 'Klocki hamulcowe Ferodo Audi A4 B8 2.0 TDI', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'Ferodo', 'model': 'FDB4050', 'price': 245.00, 'stock': 22},
                {'id': 'KH004', 'name': 'Klocki hamulcowe TRW VW Golf VII 1.4 TSI', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'TRW', 'model': 'GDB1748', 'price': 135.00, 'stock': 67},
                {'id': 'KH005', 'name': 'Klocki hamulcowe Brembo Toyota Corolla E12', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'Brembo', 'model': 'P83052', 'price': 156.00, 'stock': 73},
                {'id': 'KH006', 'name': 'Klocki hamulcowe przód Textar Ford Focus MK3', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'Textar', 'model': '2456701', 'price': 178.00, 'stock': 41},
                {'id': 'KH007', 'name': 'Klocki hamulcowe ceramiczne ATE BMW M3 E92', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'ATE', 'model': '13.0470-7241', 'price': 845.00, 'stock': 8},
                {'id': 'KH008', 'name': 'Klocki hamulcowe Pagid Opel Astra J 1.7 CDTI', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'Pagid', 'model': 'T1323', 'price': 167.00, 'stock': 29},
                {'id': 'KH009', 'name': 'Klocki hamulcowe Zimmermann Skoda Octavia III 1.6 TDI', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'Zimmermann', 'model': '23914.165.1', 'price': 142.00, 'stock': 54},
                {'id': 'KH010', 'name': 'Klocki hamulcowe Ate Renault Megane III 1.5 dCi', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'ATE', 'model': '13.0460-7265', 'price': 134.00, 'stock': 47},
                
                # TARCZE HAMULCOWE (rozszerzone)
                {'id': 'TH001', 'name': 'Tarcza hamulcowa przednia Brembo BMW E90 320mm', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'Brembo', 'model': '09.9772.11', 'price': 420.00, 'stock': 18},
                {'id': 'TH002', 'name': 'Tarcza hamulcowa tylna ATE Mercedes W204 300mm', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'ATE', 'model': '24.0330-0184', 'price': 285.00, 'stock': 25},
                {'id': 'TH003', 'name': 'Tarcza hamulcowa Zimmermann VW Golf VII przód 312mm', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'Zimmermann', 'model': '100.3234.20', 'price': 198.00, 'stock': 34},
                {'id': 'TH004', 'name': 'Tarcza hamulcowa perforowana Pagid Audi A6 C7 345mm', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'Pagid', 'model': '54877PRO', 'price': 567.00, 'stock': 12},
                {'id': 'TH005', 'name': 'Tarcza hamulcowa TRW Toyota Avensis T27 294mm', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'TRW', 'model': 'DF6123S', 'price': 156.00, 'stock': 31},
                
                # FILTRY (rozszerzone)
                {'id': 'FO001', 'name': 'Filtr oleju Mann HU719/7x BMW N47 N57 diesel', 'category': 'filtry', 'machine': 'osobowy', 'brand': 'Mann', 'model': 'HU719/7x', 'price': 62.00, 'stock': 120},
                {'id': 'FO002', 'name': 'Filtr oleju Mahle OX371D Mercedes OM651 2.2 CDI', 'category': 'filtry', 'machine': 'osobowy', 'brand': 'Mahle', 'model': 'OX371D', 'price': 45.00, 'stock': 89},
                {'id': 'FO003', 'name': 'Filtr oleju Bosch F026407022 VW 1.9 2.0 TDI', 'category': 'filtry', 'machine': 'osobowy', 'brand': 'Bosch', 'model': 'F026407022', 'price': 38.00, 'stock': 156},
                {'id': 'FO004', 'name': 'Filtr oleju Hengst H90W04 Audi A3 8P 1.9 TDI', 'category': 'filtry', 'machine': 'osobowy', 'brand': 'Hengst', 'model': 'H90W04', 'price': 41.00, 'stock': 78},
                {'id': 'FO005', 'name': 'Filtr oleju UFI 25.073.00 Fiat Punto 1.3 Multijet', 'category': 'filtry', 'machine': 'osobowy', 'brand': 'UFI', 'model': '25.073.00', 'price': 34.00, 'stock': 95},
                {'id': 'FP001', 'name': 'Filtr paliwa Bosch F026402836 PSA 1.6 2.0 HDI', 'category': 'filtry', 'machine': 'osobowy', 'brand': 'Bosch', 'model': 'F026402836', 'price': 89.00, 'stock': 85},
                {'id': 'FP002', 'name': 'Filtr paliwa Mann WK830/7 BMW E90 320d', 'category': 'filtry', 'machine': 'osobowy', 'brand': 'Mann', 'model': 'WK830/7', 'price': 76.00, 'stock': 67},
                {'id': 'FA001', 'name': 'Filtr powietrza K&N 33-2990 sportowy uniwersalny', 'category': 'filtry', 'machine': 'uniwersalny', 'brand': 'K&N', 'model': '33-2990', 'price': 285.00, 'stock': 35},
                {'id': 'FA002', 'name': 'Filtr powietrza Mann C2774/1 BMW E90 E91 E92', 'category': 'filtry', 'machine': 'osobowy', 'brand': 'Mann', 'model': 'C2774/1', 'price': 67.00, 'stock': 89},
                {'id': 'FA003', 'name': 'Filtr powietrza Mahle LX1006 Mercedes W204 C220 CDI', 'category': 'filtry', 'machine': 'osobowy', 'brand': 'Mahle', 'model': 'LX1006', 'price': 58.00, 'stock': 72},
                {'id': 'FK001', 'name': 'Filtr kabinowy węglowy Mann CUK2939 Audi A4 A6', 'category': 'filtry', 'machine': 'osobowy', 'brand': 'Mann', 'model': 'CUK2939', 'price': 95.00, 'stock': 68},
                {'id': 'FK002', 'name': 'Filtr kabinowy Bosch 1987432414 VW Golf VII Passat B8', 'category': 'filtry', 'machine': 'osobowy', 'brand': 'Bosch', 'model': '1987432414', 'price': 73.00, 'stock': 84},
                
                # AMORTYZATORY (rozszerzone)
                {'id': 'AM001', 'name': 'Amortyzator przód Bilstein B4 VW Golf VII 1.4 TSI', 'category': 'zawieszenie', 'machine': 'osobowy', 'brand': 'Bilstein', 'model': '22-266767', 'price': 520.00, 'stock': 15},
                {'id': 'AM002', 'name': 'Amortyzator tył KYB Excel-G Ford Focus MK3 1.6', 'category': 'zawieszenie', 'machine': 'osobowy', 'brand': 'KYB', 'model': '349034', 'price': 385.00, 'stock': 24},
                {'id': 'AM003', 'name': 'Amortyzator przód Sachs Opel Astra J 1.7 CDTI', 'category': 'zawieszenie', 'machine': 'osobowy', 'brand': 'Sachs', 'model': '314896', 'price': 425.00, 'stock': 19},
                {'id': 'AM004', 'name': 'Amortyzator sportowy Koni Yellow BMW E46 330i', 'category': 'zawieszenie', 'machine': 'osobowy', 'brand': 'Koni', 'model': '8741-1394SPORT', 'price': 1250.00, 'stock': 6},
                {'id': 'AM005', 'name': 'Amortyzator Monroe G8069 Toyota Corolla E12 1.4 VVTi', 'category': 'zawieszenie', 'machine': 'osobowy', 'brand': 'Monroe', 'model': 'G8069', 'price': 298.00, 'stock': 33},
                
                # ŚWIECE (rozszerzone)
                {'id': 'SZ001', 'name': 'Świeca zapłonowa NGK Laser Iridium ILZKR7B11', 'category': 'zapłon', 'machine': 'osobowy', 'brand': 'NGK', 'model': 'ILZKR7B11', 'price': 45.00, 'stock': 280},
                {'id': 'SZ002', 'name': 'Świeca zapłonowa Bosch Platinum Plus FR7DPP33', 'category': 'zapłon', 'machine': 'osobowy', 'brand': 'Bosch', 'model': 'FR7DPP33', 'price': 38.00, 'stock': 320},
                {'id': 'SZ003', 'name': 'Świeca żarowa Beru PSG006 Mercedes 2.2 CDI', 'category': 'zapłon', 'machine': 'osobowy', 'brand': 'Beru', 'model': 'PSG006', 'price': 78.00, 'stock': 145},
                {'id': 'SZ004', 'name': 'Świeca zapłonowa Champion RC9YC uniwersalna', 'category': 'zapłon', 'machine': 'uniwersalny', 'brand': 'Champion', 'model': 'RC9YC', 'price': 22.00, 'stock': 450},
                {'id': 'SZ005', 'name': 'Świeca zapłonowa Denso IK20TT Honda Civic 1.8 VTEC', 'category': 'zapłon', 'machine': 'osobowy', 'brand': 'Denso', 'model': 'IK20TT', 'price': 52.00, 'stock': 167},
                
                # AKUMULATORY (rozszerzone)
                {'id': 'AK001', 'name': 'Akumulator Varta Blue Dynamic 74Ah 680A E12', 'category': 'elektryka', 'machine': 'osobowy', 'brand': 'Varta', 'model': 'E12', 'price': 420.00, 'stock': 38},
                {'id': 'AK002', 'name': 'Akumulator Bosch S4 Silver 60Ah 540A S4005', 'category': 'elektryka', 'machine': 'osobowy', 'brand': 'Bosch', 'model': 'S4005', 'price': 350.00, 'stock': 45},
                {'id': 'AK003', 'name': 'Akumulator Exide Premium 95Ah 800A EA955', 'category': 'elektryka', 'machine': 'osobowy', 'brand': 'Exide', 'model': 'EA955', 'price': 567.00, 'stock': 23},
                {'id': 'AK004', 'name': 'Akumulator Yuasa YBX3000 45Ah 330A YBX3012', 'category': 'elektryka', 'machine': 'osobowy', 'brand': 'Yuasa', 'model': 'YBX3012', 'price': 289.00, 'stock': 41},
                
                # OLEJE (rozszerzone)
                {'id': 'OL001', 'name': 'Olej silnikowy Castrol Edge 5W30 Titanium FST 5L', 'category': 'oleje', 'machine': 'osobowy', 'brand': 'Castrol', 'model': 'Edge 5W30', 'price': 165.00, 'stock': 92},
                {'id': 'OL002', 'name': 'Olej silnikowy Mobil 1 ESP 0W40 syntetyczny 4L', 'category': 'oleje', 'machine': 'osobowy', 'brand': 'Mobil', 'model': 'ESP 0W40', 'price': 189.00, 'stock': 78},
                {'id': 'OL003', 'name': 'Olej silnikowy Shell Helix Ultra 5W40 API SN 5L', 'category': 'oleje', 'machine': 'osobowy', 'brand': 'Shell', 'model': 'Helix Ultra', 'price': 145.00, 'stock': 110},
                {'id': 'OL004', 'name': 'Olej silnikowy Total Quartz 9000 0W30 longlife 4L', 'category': 'oleje', 'machine': 'osobowy', 'brand': 'Total', 'model': 'Quartz 9000', 'price': 178.00, 'stock': 65},
                {'id': 'OL005', 'name': 'Olej silnikowy Motul 8100 X-cess 5W40 5L', 'category': 'oleje', 'machine': 'osobowy', 'brand': 'Motul', 'model': '8100 X-cess', 'price': 234.00, 'stock': 47},
                {'id': 'OL006', 'name': 'Olej przekładniowy Liqui Moly Top Tec ATF 1200 1L', 'category': 'oleje', 'machine': 'osobowy', 'brand': 'Liqui Moly', 'model': 'Top Tec ATF', 'price': 89.00, 'stock': 156},
                
                # OPONY (nowe)
                {'id': 'OP001', 'name': 'Opona Continental ContiWinterContact TS850 205/55R16', 'category': 'opony', 'machine': 'osobowy', 'brand': 'Continental', 'model': 'TS850', 'price': 456.00, 'stock': 28},
                {'id': 'OP002', 'name': 'Opona Michelin Pilot Sport 4 225/45R17 94Y', 'category': 'opony', 'machine': 'osobowy', 'brand': 'Michelin', 'model': 'Pilot Sport 4', 'price': 678.00, 'stock': 34},
                {'id': 'OP003', 'name': 'Opona Bridgestone Turanza T005 195/65R15 91H', 'category': 'opony', 'machine': 'osobowy', 'brand': 'Bridgestone', 'model': 'Turanza T005', 'price': 345.00, 'stock': 67},
                
                # WAHACZE I PRZEGUBY (nowe)
                {'id': 'WA001', 'name': 'Wahacz przedni lewy Febi BMW E90 E91 31126760269', 'category': 'zawieszenie', 'machine': 'osobowy', 'brand': 'Febi', 'model': '40760', 'price': 234.00, 'stock': 19},
                {'id': 'PR001', 'name': 'Przegub napędowy zewnętrzny GSP VW Golf V 1.9 TDI', 'category': 'napęd', 'machine': 'osobowy', 'brand': 'GSP', 'model': '601023', 'price': 189.00, 'stock': 42},
                
                # === MOTOCYKLE (rozszerzone) ===
                {'id': 'MKH001', 'name': 'Klocki hamulcowe EBC Yamaha R6 2003-2016 przód', 'category': 'hamulce', 'machine': 'motocykl', 'brand': 'EBC', 'model': 'FA252HH', 'price': 145.00, 'stock': 32},
                {'id': 'MKH002', 'name': 'Klocki hamulcowe Brembo Honda CBR600RR 2005-2016', 'category': 'hamulce', 'machine': 'motocykl', 'brand': 'Brembo', 'model': '07BB26RC', 'price': 178.00, 'stock': 27},
                {'id': 'MKH003', 'name': 'Klocki hamulcowe TRW Suzuki GSX-R1000 2009-2016', 'category': 'hamulce', 'machine': 'motocykl', 'brand': 'TRW', 'model': 'MCB748SRQ', 'price': 156.00, 'stock': 38},
                {'id': 'MLN001', 'name': 'Łańcuch napędowy DID 520VX3 Yamaha R6 gold', 'category': 'napęd', 'machine': 'motocykl', 'brand': 'DID', 'model': '520VX3-114', 'price': 345.00, 'stock': 38},
                {'id': 'MLN002', 'name': 'Łańcuch RK Racing 525XSO Honda CBR1000RR', 'category': 'napęd', 'machine': 'motocykl', 'brand': 'RK', 'model': '525XSO-120', 'price': 567.00, 'stock': 23},
                {'id': 'MFO001', 'name': 'Filtr oleju HiFlo Honda CBR600RR 2003-2018', 'category': 'filtry', 'machine': 'motocykl', 'brand': 'HiFlo', 'model': 'HF303RC', 'price': 34.00, 'stock': 125},
                {'id': 'MOP001', 'name': 'Opona motocyklowa Michelin Pilot Road 4 120/70ZR17', 'category': 'opony', 'machine': 'motocykl', 'brand': 'Michelin', 'model': 'Pilot Road 4', 'price': 234.00, 'stock': 45},
                
                # === SAMOCHODY DOSTAWCZE (rozszerzone) ===
                {'id': 'DKH001', 'name': 'Klocki hamulcowe Textar Mercedes Sprinter 906 przód', 'category': 'hamulce', 'machine': 'dostawczy', 'brand': 'Textar', 'model': '2430801', 'price': 267.00, 'stock': 34},
                {'id': 'DKH002', 'name': 'Klocki hamulcowe Ferodo VW Crafter 2006-2016 tył', 'category': 'hamulce', 'machine': 'dostawczy', 'brand': 'Ferodo', 'model': 'FDB4114', 'price': 298.00, 'stock': 26},
                {'id': 'DFO001', 'name': 'Filtr oleju Mann W712/94 Sprinter Vito 2.2 CDI', 'category': 'filtry', 'machine': 'dostawczy', 'brand': 'Mann', 'model': 'W712/94', 'price': 78.00, 'stock': 89},
                {'id': 'DFO002', 'name': 'Filtr oleju Mahle OX254D Iveco Daily 3.0 HTP', 'category': 'filtry', 'machine': 'dostawczy', 'brand': 'Mahle', 'model': 'OX254D', 'price': 67.00, 'stock': 75},
                {'id': 'DAM001', 'name': 'Amortyzator przód Monroe Ford Transit MK7 2006-2014', 'category': 'zawieszenie', 'machine': 'dostawczy', 'brand': 'Monroe', 'model': '743049SP', 'price': 456.00, 'stock': 18},
                
                # === CZĘŚCI LUKSUSOWE (nowe - ZASÓB A zawiera też marki luksusowe) ===
                {'id': 'LK001', 'name': 'Klocki hamulcowe Brembo Porsche 911 997 Turbo carbon ceramic', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'Brembo', 'model': 'P50086', 'price': 2340.00, 'stock': 4},
                {'id': 'LK002', 'name': 'Klocki hamulcowe Pagid Lamborghini Gallardo LP560', 'category': 'hamulce', 'machine': 'osobowy', 'brand': 'Pagid', 'model': 'RSC1', 'price': 1890.00, 'stock': 3},
                
                # === UNIWERSALNE CZĘŚCI TUNINGOWE (nowe) ===
                {'id': 'TU001', 'name': 'Filtr powietrza sportowy K&N RU-3530 uniwersalny stożek', 'category': 'filtry', 'machine': 'uniwersalny', 'brand': 'K&N', 'model': 'RU-3530', 'price': 189.00, 'stock': 67},
                {'id': 'TU002', 'name': 'Intercooler Mishimoto uniwersalny 600x300x76mm', 'category': 'chłodzenie', 'machine': 'uniwersalny', 'brand': 'Mishimoto', 'model': 'MMINT-UNI-23', 'price': 1234.00, 'stock': 12}
            ],
            'categories': {
                'hamulce': 'Układ hamulcowy',
                'filtry': 'Filtry',
                'zawieszenie': 'Zawieszenie',
                'zapłon': 'Układ zapłonowy',
                'elektryka': 'Elektryka',
                'oleje': 'Oleje i płyny',
                'napęd': 'Układ napędowy',
                'opony': 'Opony i koła',
                'chłodzenie': 'Układ chłodzenia'
            },
            'machines': {
                'osobowy': 'Samochód osobowy',
                'dostawczy': 'Samochód dostawczy',
                'motocykl': 'Motocykl',
                'uniwersalny': 'Uniwersalne'
            }
        }
        
        # Kompletna baza FAQ (bez zmian)
        self.faq_database = [
            # DOSTAWA
            {
                'id': 'FAQ001',
                'keywords': ['dostawa', 'wysyłka', 'kiedy', 'czas dostawy', 'kurier', 'paczka'],
                'question': 'Jaki jest czas dostawy części samochodowych?',
                'answer': 'Dostawa kurierem: 24h dla produktów na stanie\nPaczkomaty: 1-2 dni robocze\nDostawa zagraniczna: 3-5 dni',
                'category': 'dostawa'
            },
            {
                'id': 'FAQ002',
                'keywords': ['koszt dostawy', 'ile kosztuje', 'darmowa', 'przesyłka'],
                'question': 'Ile kosztuje dostawa?',
                'answer': 'Standardowa dostawa: 15 zł\nDarmowa dostawa od 300 zł\nPaczkomaty: 12 zł',
                'category': 'dostawa'
            },
            
            # ZWROTY
            {
                'id': 'FAQ003',
                'keywords': ['zwrot', 'reklamacja', 'wymiana', 'gwarancja'],
                'question': 'Jak zwrócić lub wymienić część?',
                'answer': '14 dni na zwrot bez podania przyczyny\nDarmowa wymiana na inną część\n24 miesiące gwarancji producenta',
                'category': 'zwroty'
            },
            {
                'id': 'FAQ004',
                'keywords': ['uszkodzony', 'wadliwy', 'nie działa', 'zepsuty'],
                'question': 'Co zrobić gdy część jest uszkodzona?',
                'answer': 'Zgłoś w ciągu 24h od otrzymania\nWyślij zdjęcia uszkodzenia\nOdbierzemy i wyślemy nową część gratis',
                'category': 'zwroty'
            }
        ]
        
        # Przykładowe zamówienia (bez zmian)
        self.orders_database = {
            'MOT-2024001': {
                'status': 'W drodze',
                'details': 'Dostawa jutro do 12:00',
                'tracking': 'DPD: 0123456789',
                'items': ['Klocki hamulcowe Bosch BMW E90']
            }
        }


    
    def levenshtein_distance(self, s1: str, s2: str) -> int:
        """Oblicza odległość Levenshteina między dwoma stringami"""
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
    
    def has_automotive_context(self, tokens: List[str]) -> bool:
        """
        NAPRAWIONA - z rozszerzonym słownikiem części samochodowych + OBSŁUGA KODÓW PRODUKTÓW
        """
        normalized_tokens = []
        for token in tokens:
            token_lower = token.lower()
            
            # Sprawdź słownik wielojęzyczny (jeśli istnieje)
            if hasattr(self, 'MULTILINGUAL_TERMS') and token_lower in self.MULTILINGUAL_TERMS:
                normalized_tokens.append(self.MULTILINGUAL_TERMS[token_lower])
            # Sprawdź slang (jeśli istnieje)
            elif hasattr(self, 'SLANG_DICTIONARY') and token_lower in self.SLANG_DICTIONARY:
                normalized_tokens.append(self.SLANG_DICTIONARY[token_lower])
            else:
                normalized_tokens.append(token)  # Zachowaj oryginał
        
        # Dodaj znormalizowane tokeny do oryginalnych (sprawdzamy oba zestawy)
        tokens = tokens + normalized_tokens
        # === KONIEC NOWEGO KODU ===
        
        for token in tokens:
            token_lower = token.lower()
            
            # Sprawdź w istniejących słownikach
            if (token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands'] or
                token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands'] or
                token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['luxury_brands'] or
                token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories'] or
                token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_models'] or
                token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_models'] or
                token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['technical_terms']):
                return True
            
            # ROZSZERZONY słownik części karoseryjnych
            karoseria_parts = {
                'drzwi', 'klapka', 'klapa', 'maska', 'zderzak', 'błotnik', 'próg', 'słupek',
                'dach', 'podłoga', 'rama', 'chassis', 'nadwozie', 'karoseria', 'boczek',
                'rant', 'listwy', 'nakładki', 'osłony', 'panele', 'elementy'
            }
            
            if token_lower in karoseria_parts:
                return True
            
            # Sprawdź znane literówki
            if token_lower in {'kloki', 'swica', 'swieca', 'akumlator', 'filetr', 'amortyztor', 'olel'}:
                return True
            
            # NOWE: Sprawdź kody produktów z Twojej bazy
            product_codes_from_database = [
                '0986494104', '13.0460-7218', 'fdb4050', 'gdb1748', 'p83052', '2456701',
                '13.0470-7241', 't1323', '23914.165.1', '13.0460-7265', '09.9772.11',
                '24.0330-0184', '100.3234.20', '54877pro', 'df6123s', 'hu719/7x',
                'ox371d', 'f026407022', 'h90w04', '25.073.00', 'f026402836', 'wk830/7',
                '33-2990', 'c2774/1', 'lx1006', 'cuk2939', '1987432414', '22-266767',
                '349034', '314896', '8741-1394sport', 'g8069', 'ilzkr7b11', 'fr7dpp33',
                'psg006', 'rc9yc', 'ik20tt'
            ]
            
            # Sprawdź dokładne dopasowanie kodu
            if token_lower in [code.lower() for code in product_codes_from_database]:
                return True
            
            # Sprawdź częściowe dopasowanie kodu
            for code in product_codes_from_database:
                if (len(token) >= 4 and 
                    (token_lower in code.lower() or code.lower() in token_lower)):
                    return True
            
            # NOWE: Sprawdź wzorce kodów produktów (regex)
            if any(re.match(pattern, token.upper()) for pattern in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['product_code_patterns']):
                return True
            
            # NOWE: Sprawdź specyfikacje techniczne
            technical_specs = {
                '5w30', '0w40', '5w40', '10w40', '0w30', '15w40',
                '74ah', '60ah', '95ah', '45ah', '680a', '540a', '800a', '330a',
                '320mm', '300mm', '312mm', '345mm', '294mm',
                '205/55r16', '225/45r17', '195/65r15', '120/70zr17'
            }
            
            if token_lower in technical_specs:
                return True
            
            # Sprawdź wzorce specyfikacji (regex)
            spec_patterns = [
                r'^\d+w\d+$',        # 5w30, 0w40
                r'^\d+ah$',          # 74ah, 60ah  
                r'^\d+a$',           # 680a, 540a
                r'^\d+mm$',          # 320mm, 300mm
                r'^\d+/\d+r\d+$',    # 205/55r16
                r'^\d+/\d+zr\d+$'    # 120/70zr17
            ]
            
            if any(re.match(pattern, token_lower) for pattern in spec_patterns):
                return True
            
            # Fuzzy match dla głównych kategorii
            main_categories = ['klocki', 'filtr', 'amortyzator', 'świeca', 'akumulator', 'olej', 'opony']
            for category in main_categories:
                if len(token) >= 4 and fuzz.ratio(token_lower, category) >= 85:
                    return True
            
            tire_pattern = r'^\d{3}/\d{2}[rR]\d{2}$'
            for token in tokens:
                if re.match(tire_pattern, token):
                    return True
        
        return False
    
    
    def is_structural_query(self, tokens: List[str]) -> bool:
        """
        FINALNA NAPRAWA - Inteligentna klasyfikacja z wykluczeniem naturalnych zapytań
        """
        has_category = False
        has_unknown_brand = False
        
        print(f"[STRUCTURAL DEBUG] Tokens: {tokens}")
        
        # === KOMPLETNY SŁOWNIK NATURALNYCH ZAPYTAŃ KONTEKSTOWYCH ===
        natural_context_words = {
            # Przyimki podstawowe
            'do', 'dla', 'na', 'w', 'z', 'ze', 'od', 'po', 'przed', 'za', 'pod', 'nad', 'przy', 'przez',
            
            # Pytania o kompatybilność i dopasowanie
            'pasuje', 'pasują', 'można', 'czy', 'jakiś', 'jaki', 'jakie', 'które', 'która', 'który',
            'dopasowanie', 'kompatybilny', 'kompatybilna', 'kompatybilne', 'pasujący', 'pasująca', 'pasujące',
            'czy', 'może', 'będzie', 'da', 'daje', 'się', 'idealny', 'idealna', 'idealne',
            
            # Kontekst czasowy i sezonowy
            'zimą', 'latem', 'sezon', 'roku', 'teraz', 'obecnie', 'jesienią', 'wiosną',
            'zimowy', 'letni', 'jesienny', 'wiosenny', 'sezonowy', 'sezonowe', 'sezonowa',
            
            # Słowa określające ilość i rodzaj
            'jeden', 'jedna', 'jedno', 'kilka', 'pare', 'parę', 'komplet', 'zestaw', 'sztuka', 'szt',
            'dwa', 'dwie', 'trzy', 'cztery', 'pięć', 'sześć', 'wszystkie', 'każdy', 'każda', 'każde',
            
            # Ogólne kategorie i określenia
            'części', 'część', 'akcesoria', 'wyposażenie', 'element', 'komponenty', 'komponent',
            'produkt', 'produkty', 'towar', 'towary', 'rzecz', 'rzeczy', 'typ', 'rodzaj', 'model',
            
            # Słowa związane z zakupem i wyborem
            'kupię', 'kupi', 'kupić', 'kupno', 'zakup', 'zakupy', 'wybór', 'wybieram', 'szukam', 'potrzebuję',
            'potrzebny', 'potrzebna', 'potrzebne', 'chcę', 'chce', 'mam', 'ma', 'będę', 'będzie',
            
            # Pytania o cenę i dostępność
            'ile', 'kosztuje', 'koszt', 'cena', 'ceny', 'tani', 'tania', 'tanie', 'drogi', 'droga', 'drogie',
            'dostępny', 'dostępna', 'dostępne', 'jest', 'są', 'będzie', 'będą', 'mają', 'ma',
            
            # Słowa związane z montażem i instalacją
            'montaż', 'montażu', 'montować', 'instalacja', 'instalować', 'wymiana', 'wymiany', 'wymienić',
            'naprawy', 'naprawa', 'naprawić', 'serwis', 'przegląd', 'diagnostyka',
            
            # Określenia stanu i jakości
            'nowy', 'nowa', 'nowe', 'używany', 'używana', 'używane', 'oryginalny', 'oryginalna', 'oryginalne',
            'zamiennik', 'zamienniki', 'odpowiednik', 'jakość', 'dobry', 'dobra', 'dobre', 'najlepszy', 'najlepsza',
            
            # Lokalizacja i pozycja
            'gdzie', 'miejsce', 'pozycja', 'strona', 'góra', 'dół', 'środek', 'bok', 'krawędź',
            
            # Czasowniki pomocnicze
            'mieć', 'mam', 'ma', 'mają', 'będę', 'będzie', 'będą', 'mogę', 'może', 'można',
            'powinien', 'powinna', 'powinno', 'musi', 'trzeba', 'należy', 'warto',
            
            # Słowa pytające
            'co', 'gdzie', 'kiedy', 'jak', 'dlaczego', 'po', 'co', 'skąd', 'dokąd', 'czemu'
        }
        
        # Sprawdź czy zapytanie zawiera naturalne słowa kontekstowe
        context_words_found = [token.lower() for token in tokens if token.lower() in natural_context_words]
        
        # KLUCZOWA ZMIANA: Sprawdź czy są też słowa produktowe
        has_product_context = any(
            token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands'] or
            token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands'] or
            token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['luxury_brands'] or
            token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories'] or
            token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_models'] or
            token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_models']
            for token in tokens
        )
        
        # Blokuj TYLKO jeśli są context words ALE NIE MA kontekstu produktowego
        if context_words_found and not has_product_context:
            print(f"[STRUCTURAL DEBUG] Found natural context words WITHOUT product context: {context_words_found}")
            print(f"[STRUCTURAL DEBUG] This is a pure conversational query, not product search")
            return False
        elif context_words_found and has_product_context:
            print(f"[STRUCTURAL DEBUG] Found context words: {context_words_found}, but also product context - allowing")
            # Kontynuuj normalnie - to może być zapytanie typu "klocki do bmw"
        
        # === MEGA SŁOWNIK LITERÓWEK - ZASTOSUJ PRZED KLASYFIKACJĄ ===
        comprehensive_typos = {
            # Świece - wszystkie warianty
            'swiczka': 'świeca', 'swica': 'świeca', 'swieca': 'świeca', 'swieczka': 'świeca',
            'świczka': 'świeca', 'swiecz': 'świeca', 'swiec': 'świeca', 'świece': 'świeca',
            'swiecy': 'świeca', 'swiecami': 'świeca', 'swieczkam': 'świeca',
            
            # Klocki - wszystkie warianty
            'kloki': 'klocki', 'klocek': 'klocki', 'kloce': 'klocki', 'kloci': 'klocki',
            'klockei': 'klocki', 'klocke': 'klocki', 'klockami': 'klocki', 'klockow': 'klocki',
            'klocków': 'klocki', 'klocek': 'klocki',
            
            # Filtry - maksymalne pokrycie
            'filetr': 'filtr', 'filtry': 'filtr', 'filtery': 'filtr', 'filet': 'filtr',
            'filttr': 'filtr', 'filrt': 'filtr', 'flitr': 'filtr', 'fltr': 'filtr',
            'filtrem': 'filtr', 'filtrow': 'filtr', 'filtra': 'filtr', 'filtrów': 'filtr',
            
            # Amortyzatory
            'amortyztor': 'amortyzator', 'amortyzatory': 'amortyzator', 'amortyzzator': 'amortyzator',
            'amortyzatr': 'amortyzator', 'amortyzato': 'amortyzator', 'amortyzatorow': 'amortyzator',
            'amortyzatorów': 'amortyzator', 'amortyztory': 'amortyzator',
            
            # Akumulatory
            'akumlator': 'akumulator', 'akumualtor': 'akumulator', 'akumualator': 'akumulator',
            'akumultor': 'akumulator', 'akumultator': 'akumulator', 'bateri': 'akumulator',
            'bateria': 'akumulator', 'batterya': 'akumulator', 'akumulatory': 'akumulator',
            'akumulatorów': 'akumulator', 'akumulatorem': 'akumulator',
            
            # Hamulce
            'hamulec': 'hamulce', 'hamulcowy': 'hamulcowe', 'hamulcwe': 'hamulcowe',
            'hamulcow': 'hamulcowe', 'hamulcowe': 'hamulce', 'hamulcami': 'hamulce',
            'hamulców': 'hamulce', 'hamowania': 'hamulce', 'hamulcowych': 'hamulcowe',
            
            # Opony
            'opon': 'opony', 'opny': 'opony', 'opona': 'opony', 'opone': 'opony',
            'oponami': 'opony', 'oponę': 'opony', 'opnych': 'opony', 'oponach': 'opony',
            
            # Marki z literówkami
            'bosh': 'bosch', 'boach': 'bosch', 'boschem': 'bosch', 'boscha': 'bosch',
            'sacsh': 'sachs', 'sach': 'sachs', 'sachsem': 'sachs', 'sachsa': 'sachs',
            'bmv': 'bmw', 'bmew': 'bmw', 'bmw-em': 'bmw', 'bmw-a': 'bmw',
            'toyoya': 'toyota', 'toyata': 'toyota', 'toyotą': 'toyota', 'toyoty': 'toyota',
            'mercedesbenz': 'mercedes', 'mercedes-benz': 'mercedes', 'mercedesem': 'mercedes',
            'mercedesa': 'mercedes', 'mercedesy': 'mercedes',
            
            # Skróty marek
            'vw': 'volkswagen', 'volkswage': 'volkswagen', 'folkswaen': 'volkswagen',
            'mb': 'mercedes', 'merc': 'mercedes', 'merka': 'mercedes',
            'yam': 'yamaha', 'yamha': 'yamaha', 'yamahy': 'yamaha', 'yamahe': 'yamaha',
            
            # Części dodatkowe
            'tarcze': 'tarcza', 'tarczy': 'tarcza', 'tarcy': 'tarcza', 'tarzca': 'tarcza',
            'tarcami': 'tarcza', 'tarczami': 'tarcza', 'tarczę': 'tarcza',
            'sprężyny': 'sprężyna', 'sprężyn': 'sprężyna', 'sprezyna': 'sprężyna',
            'sprezyny': 'sprężyna', 'sprezyn': 'sprężyna', 'sprężynami': 'sprężyna',
            'lanczuch': 'łańcuch', 'łancuch': 'łańcuch', 'lancuch': 'łańcuch',
            'lancuchem': 'łańcuch', 'łańcuchem': 'łańcuch',
            
            # Pozycje
            'przod': 'przód', 'przedni': 'przód', 'przednia': 'przód', 'przednie': 'przód',
            'tylny': 'tył', 'tylni': 'tył', 'tylna': 'tył', 'tylne': 'tył',
            'lewy': 'lewy', 'prawy': 'prawy', 'lewa': 'lewy', 'prawa': 'prawy',
            
            # Oleje i płyny
            'oleju': 'olej', 'oleje': 'olej', 'olel': 'olej', 'olejow': 'olej',
            'olejów': 'olej', 'olejami': 'olej', 'olejem': 'olej',
            'powietza': 'powietrza', 'powietrz': 'powietrza', 'powietra': 'powietrza',
            'powietrzem': 'powietrza', 'powietrzu': 'powietrza',
            
            # Sezonowe
            'zimow': 'zimowe', 'zimowy': 'zimowe', 'zimowa': 'zimowe', 'zimowych': 'zimowe',
            'letni': 'letnie', 'letnia': 'letnie', 'letnich': 'letnie', 'letnimi': 'letnie',
            'letnią': 'letnie', 'zimową': 'zimowe', 'zimowymi': 'zimowe',
            
            # Techniczne terminy
            'napędowy': 'napęd', 'napedowy': 'napęd', 'napędowe': 'napęd',
            'zapłonowa': 'zapłon', 'zaplonowa': 'zapłon', 'zapłonowe': 'zapłon',
            'silnikowy': 'olej', 'silnikowego': 'olej', 'silnikowe': 'olej',
            'chłodzenia': 'chłodnica', 'chlodzenia': 'chłodnica', 'chłodzenie': 'chłodnica',
            'wspomagania': 'wspomaganie', 'wspomaganie': 'kierownica'
        }
        
        # Zastosuj korekcje literówek PRZED sprawdzaniem kategorii
        corrected_tokens = []
        for token in tokens:
            token_lower = token.lower()
            if token_lower in comprehensive_typos:
                corrected_tokens.append(comprehensive_typos[token_lower])
                print(f"[STRUCTURAL DEBUG] Corrected typo: {token} -> {comprehensive_typos[token_lower]}")
            else:
                corrected_tokens.append(token_lower)
        
        # === SPRAWDZENIE KATEGORII (z poprawionymi tokenami) ===
        for token in corrected_tokens:
            if (token in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories'] or
                token in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['technical_terms']):
                has_category = True
                print(f"[STRUCTURAL DEBUG] Found category: {token}")
                break
            
            # Fuzzy matching dla kategorii
            if len(token) >= 4:
                for category in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories']:
                    if len(category) >= 4:
                        similarity = fuzz.ratio(token, category)
                        if similarity >= 85:
                            has_category = True
                            print(f"[STRUCTURAL DEBUG] Found category via fuzzy: {token} -> {category} ({similarity}%)")
                            break
                if has_category:
                    break
        
        # === SPRAWDZENIE NIEZNANYCH MAREK ===
        for token in tokens:
            token_lower = token.lower()
            
            # Skip wszystkie znane słowa i konteksty
            if (token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands'] or
                token_lower in self.PARTS_MANUFACTURERS or
                token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands'] or
                token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['luxury_brands'] or
                token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories'] or
                token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['technical_terms'] or
                token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_models'] or
                token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_models'] or
                token_lower in self.POLISH_DICTIONARY or
                token_lower in comprehensive_typos or
                token_lower in natural_context_words):
                continue
            
            # Skip kody produktów
            if any(re.match(pattern, token.upper()) for pattern in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['product_code_patterns']):
                continue
            
            # Zaostrzone kryteria dla nieznanych marek
            if (len(token) >= 3 and len(token) <= 15 and 
                token.isalpha() and
                not any(pattern in token_lower for pattern in self.NONSENSE_DICTIONARY['keyboard_patterns']) and
                token_lower not in self.NONSENSE_DICTIONARY['test_words'] and
                not token_lower.endswith('ować') and
                not token_lower.endswith('ić') and
                not token_lower.endswith('ąć') and
                not token_lower.endswith('nąć')):
                has_unknown_brand = True
                print(f"[STRUCTURAL DEBUG] Found potential unknown brand: {token}")
                break
        
        result = has_category and has_unknown_brand
        print(f"[STRUCTURAL DEBUG] Final result: category={has_category}, unknown_brand={has_unknown_brand}, structural={result}")
        return result
    def correct_query_typos(self, query: str) -> str:
        """
        Agresywna korekcja literówek przed wyszukiwaniem
        """
        corrections = {
            'swica': 'świeca', 'swieca': 'świeca', 'kloki': 'klocki',
            'filetr': 'filtr', 'amortyztor': 'amortyzator',
            'akumlator': 'akumulator', 'olel': 'olej', 'opny': 'opony','oopony': 'opony',
        'ooopony': 'opony', 
        'akum': 'akumulator',
        'świece': 'świeca',
        'benz': 'benzyna',
        'benza': 'benzyna'
        }
        
        tokens = query.lower().split()
        corrected = []
        
        for token in tokens:
            corrected.append(corrections.get(token, token))
        
        return ' '.join(corrected)
    
    def fix_double_letters(self, query: str) -> str:
        """
        Naprawia podwójne litery w literówkach
        """
        fixed = query.lower()
        words = fixed.split()
        fixed_words = []
        
        for word in words:
            # Sprawdź każdy wzorzec podwójnych liter
            fixed_word = word
            for double, single in self.DOUBLE_LETTER_PATTERNS:
                if double in word:
                    # Spróbuj naprawić
                    test_word = word.replace(double, single)
                    
                    # Sprawdź czy po poprawce to znana kategoria
                    if (test_word in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories'] or
                        test_word in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands'] or
                        test_word in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands']):
                        fixed_word = test_word
                        break
                    
                    # Sprawdź fuzzy matching
                    for category in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories']:
                        if fuzz.ratio(test_word, category) >= 90:
                            fixed_word = test_word
                            break
            
            fixed_words.append(fixed_word)
        
        return ' '.join(fixed_words)

    # DOKŁADNE MIEJSCE WKLEJENIA I MODYFIKACJI

# 1. ZNAJDŹ METODĘ calculate_token_validity (około linii 350-450)
# 2. ZAMIEŃ ISTNIEJĄCY SŁOWNIK common_typos NA TEN ROZSZERZONY:

    def calculate_token_validity(self, query_tokens: List[str]) -> float:
        """
        ULEPSZONA WERSJA - Maksymalnie agresywna korekcja literówek
        """
        if not query_tokens:
            return 0
        
        validity_scores = []
        
        # Ten sam rozszerzony słownik co w is_structural_query
        mega_typos = {
            # Świece
            'swica': 'świeca', 'swieca': 'świeca', 'swiczka': 'świeca', 'swiecka': 'świeca',
            'swieczka': 'świeca', 'swieczkia': 'świeca', 'świczka': 'świeca', 'swiecz': 'świeca',
            'swiec': 'świeca', 'świece': 'świeca', 'swiecy': 'świeca', 'swiecami': 'świeca',
            
            # Klocki
            'kloki': 'klocki', 'klocek': 'klocki', 'kloce': 'klocki', 'kloci': 'klocki',
            'klockei': 'klocki', 'klocke': 'klocki', 'klockami': 'klocki', 'klockow': 'klocki',
            'klocków': 'klocki',
            
            # Filtry
            'filetr': 'filtr', 'filtry': 'filtr', 'filtery': 'filtr', 'filet': 'filtr',
            'filttr': 'filtr', 'filrt': 'filtr', 'flitr': 'filtr', 'fltr': 'filtr',
            'filtrem': 'filtr', 'filtrow': 'filtr', 'filtra': 'filtr', 'filtrów': 'filtr',
            
            # Amortyzatory
            'amortyztor': 'amortyzator', 'amortyzatory': 'amortyzator', 'amortyzzator': 'amortyzator',
            'amortyzatr': 'amortyzator', 'amortyzato': 'amortyzator', 'amortyzatorow': 'amortyzator',
            'amortyzatorów': 'amortyzator',
            
            # Akumulatory
            'akumlator': 'akumulator', 'akumualtor': 'akumulator', 'akumualator': 'akumulator',
            'akumultor': 'akumulator', 'akumultator': 'akumulator', 'bateri': 'akumulator',
            'bateria': 'akumulator', 'batterya': 'akumulator', 'akumulatory': 'akumulator',
            'akumulatorów': 'akumulator',
            
            # Hamulce
            'hamulec': 'hamulce', 'hamulcowy': 'hamulcowe', 'hamulcwe': 'hamulcowe',
            'hamulcow': 'hamulcowe', 'hamulcowe': 'hamulce', 'hamulcami': 'hamulce',
            'hamulców': 'hamulce', 'hamowania': 'hamulce',
            
            # Opony
            'opon': 'opony', 'opny': 'opony', 'opona': 'opony', 'opone': 'opony',
            'oponami': 'opony', 'oponę': 'opony', 'opnych': 'opony',
            
            # Marki
            'bosh': 'bosch', 'boach': 'bosch', 'boschem': 'bosch',
            'sacsh': 'sachs', 'sach': 'sachs', 'sachsem': 'sachs',
            'bmv': 'bmw', 'bmew': 'bmw', 'bmw-em': 'bmw',
            'toyoya': 'toyota', 'toyata': 'toyota', 'toyotą': 'toyota',
            'mercedesbenz': 'mercedes', 'mercedes-benz': 'mercedes', 'mercedesem': 'mercedes',
            'vw': 'volkswagen', 'volkswage': 'volkswagen', 'folkswaen': 'volkswagen',
            'mb': 'mercedes', 'merc': 'mercedes',
            'yam': 'yamaha', 'yamha': 'yamaha', 'yamahy': 'yamaha',
            
            # Części
            'tarcze': 'tarcza', 'tarczy': 'tarcza', 'tarcy': 'tarcza', 'tarzca': 'tarcza',
            'sprężyny': 'sprężyna', 'sprężyn': 'sprężyna', 'sprezyna': 'sprężyna',
            'sprezyny': 'sprężyna', 'lanczuch': 'łańcuch', 'łancuch': 'łańcuch',
            
            # Pozycje
            'przod': 'przód', 'przedni': 'przód', 'przednia': 'przód',
            'tylny': 'tył', 'tylni': 'tył', 'tylna': 'tył',
            
            # Techniczne
            'oleju': 'olej', 'oleje': 'olej', 'olel': 'olej', 'olejow': 'olej',
            'powietza': 'powietrza', 'powietrz': 'powietrza', 'powietra': 'powietrza',
            'zimow': 'zimowe', 'zimowy': 'zimowe', 'zimowa': 'zimowe',
            'letni': 'letnie', 'letnia': 'letnie', 'letnich': 'letnie',
            'napędowy': 'napęd', 'napedowy': 'napęd',
            'zapłonowa': 'zapłon', 'zaplonowa': 'zapłon',
            'silnikowy': 'olej', 'silnikowego': 'olej'
        }
        
        for token in query_tokens:
            token_lower = token.lower()
            score = 0
            
            # KROK 1: AGRESYWNA KOREKCJA LITERÓWEK
            if token_lower in mega_typos:
                corrected_token = mega_typos[token_lower]
                print(f"[VALIDITY DEBUG] Typo corrected: {token} -> {corrected_token}")
                
                if corrected_token in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories']:
                    score = 95
                elif corrected_token in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands']:
                    score = 98
                elif corrected_token in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands']:
                    score = 96
                elif corrected_token in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['luxury_brands']:
                    score = 96
                elif corrected_token in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['technical_terms']:
                    score = 90
                else:
                    score = 85
            
            # KROK 2: DOKŁADNE DOPASOWANIA
            elif token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands']:
                score = 100
            elif token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands']:
                score = 98
            elif token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['luxury_brands']:
                score = 98
            elif token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories']:
                score = 96
            elif token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_models']:
                score = 92
            elif token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_models']:
                score = 90
            elif token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['technical_terms']:
                score = 88
            elif any(re.match(pattern, token.upper()) for pattern in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['product_code_patterns']):
                score = 85
            elif token_lower in self.POLISH_DICTIONARY:
                score = 75
            
            # KROK 3: FUZZY MATCHING
            else:
                best_match_score = 0
                
                priority_words = (
                    self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands'] +
                    self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands'] +
                    self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['luxury_brands'] +
                    self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories']
                )
                
                for known_word in priority_words:
                    if len(token) >= 3 and len(known_word) >= 3:
                        distance = self.levenshtein_distance(token_lower, known_word)
                        similarity = max(0, 100 - (distance * 12))  # Bardziej tolerancyjne
                        best_match_score = max(best_match_score, similarity)
                
                if best_match_score >= 75:
                    score = min(85, best_match_score)
                elif best_match_score >= 60:
                    score = min(70, best_match_score)
                elif best_match_score >= 45:
                    score = min(55, best_match_score)
                else:
                    score = 0
            
            validity_scores.append(score)
            print(f"[VALIDITY DEBUG] Token '{token}' scored: {score}")
        
        final_score = sum(validity_scores) / len(validity_scores)
        print(f"[VALIDITY DEBUG] Final average score: {final_score}")
        return final_score
    
    
    def looks_like_product_query(self, tokens: List[str]) -> bool:
        """
        NAPRAWIONA - INTELIGENTNA DRUGA BRAMKA
        Z ULEPSZONYM FUZZY MATCHING DLA KATEGORII
        """
        if not tokens:
            return False
        
        # Pojedyncze słowo
        if len(tokens) == 1:
            token = tokens[0].lower()
            
            # Odrzuć same liczby
            if token.isdigit():
                return False
            
            # ZASÓB B: Sprawdź dokładne dopasowania
            if (token in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands'] or
                token in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands'] or
                token in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['luxury_brands'] or
                token in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories'] or
                token in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_models'] or
                token in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_models']):
                return True
            
            # FUZZY MATCHING dla kategorii
            best_category_match = 0
            for category in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories']:
                similarity = fuzz.ratio(token, category)
                best_category_match = max(best_category_match, similarity)
            
            if best_category_match >= 85:  # 85% podobieństwa dla kategorii
                return True
            
            # FUZZY MATCHING dla marek
            best_brand_match = 0
            all_brands = (self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands'] + 
                         self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands'] + 
                         self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['luxury_brands'])
            
            for brand in all_brands:
                similarity = fuzz.ratio(token, brand)
                best_brand_match = max(best_brand_match, similarity)
            
            if best_brand_match >= 80:  # 80% podobieństwa dla marek
                return True
            
            # Jeśli to sensowne słowo 3+ liter - może być produktem
            if (len(token) >= 3 and token.isalpha() and 
                not any(p in token for p in self.NONSENSE_DICTIONARY['keyboard_patterns']) and
                token not in self.NONSENSE_DICTIONARY['test_words']):
                return True
            return False
        
        # Wielosłowne zapytanie
        if len(tokens) >= 2:
            # Ma strukturę produktową
            has_noun_structure = any(len(t) >= 3 and t.isalpha() for t in tokens)
            
            # ZASÓB B: Ma słowo które może być marką (z fuzzy matching)
            has_potential_brand = False
            
            for token in tokens:
                if not token:
                    continue
                    
                token_lower = token.lower()
                
                # Dokładne dopasowania
                if (token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands'] or
                    token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands'] or
                    token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['luxury_brands'] or
                    token[0].isupper()):
                    has_potential_brand = True
                    break
                
                # FUZZY MATCHING dla marek
                all_brands = (self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands'] + 
                             self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands'] + 
                             self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['luxury_brands'])
                
                for brand in all_brands:
                    if fuzz.ratio(token_lower, brand) >= 80:
                        has_potential_brand = True
                        break
                
                if has_potential_brand:
                    break
                
                # Sensowne słowo jako potencjalna marka
                if (len(token) >= 3 and token.isalpha() and 
                    token_lower not in self.NONSENSE_DICTIONARY['test_words']):
                    has_potential_brand = True
                    break
            
            # ZASÓB B: Ma słowo które może być częścią (z fuzzy matching)
            has_potential_part = False
            
            for token in tokens:
                token_lower = token.lower()
                
                # Dokładne dopasowania
                if (token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories'] or
                    token_lower in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['technical_terms'] or
                    (len(token) >= 4 and token.isalpha() and token_lower in self.POLISH_DICTIONARY)):
                    has_potential_part = True
                    break
                
                # FUZZY MATCHING dla kategorii
                for category in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories']:
                    if fuzz.ratio(token_lower, category) >= 85:
                        has_potential_part = True
                        break
                
                if has_potential_part:
                    break
            
            return has_noun_structure and (has_potential_brand or has_potential_part)
        
        return False
    
    def is_obvious_nonsense(self, tokens: List[str], token_validity: float) -> bool:
        """
        NAPRAWIONA - KOMPLETNY FILTR NONSENSU
        Z ORYGINALNĄ LOGIKĄ + NOWYM FILTREM KONTEKSTU MOTORYZACYJNEGO + OBSŁUGA KODÓW PRODUKTÓW
        """
        if not tokens:
            return True
        
        query_text = ' '.join(tokens).lower()
        
        # KROK 1: Wyklucz kody techniczne oleju
        technical_codes = ['5w30', '0w40', '5w40', '10w40', '0w30', '15w40', 'w30', 'w40', 'w50']
        if any(code in query_text for code in technical_codes):
            return False
        
        # KROK 1.5: NOWE - Wyklucz kody produktów z Twojej bazy
        product_codes_from_database = [
            # Kody z Twojej bazy produktów
            '0986494104', '13.0460-7218', 'fdb4050', 'gdb1748', 'p83052', '2456701',
            '13.0470-7241', 't1323', '23914.165.1', '13.0460-7265', '09.9772.11',
            '24.0330-0184', '100.3234.20', '54877pro', 'df6123s', 'hu719/7x',
            'ox371d', 'f026407022', 'h90w04', '25.073.00', 'f026402836', 'wk830/7',
            '33-2990', 'c2774/1', 'lx1006', 'cuk2939', '1987432414', '22-266767',
            '349034', '314896', '8741-1394sport', 'g8069', 'ilzkr7b11', 'fr7dpp33',
            'psg006', 'rc9yc', 'ik20tt', 'e12', 's4005', 'ea955', 'ybx3012',
            'edge', '5w30', 'esp', '0w40', 'helix', 'ultra', 'quartz', '9000',
            '8100', 'x-cess', 'top', 'tec', 'atf', '1200', 'ts850', 'pilot',
            'sport', '4', 'turanza', 't005', '40760', '601023', 'fa252hh',
            '07bb26rc', 'mcb748srq', '520vx3-114', '525xso-120', 'hf303rc',
            'pilot', 'road', '4', '2430801', 'fdb4114', 'w712/94', 'ox254d',
            '743049sp', 'p50086', 'rsc1', 'ru-3530', 'mmint-uni-23'
        ]
        
        # Sprawdź czy zawiera kod produktu z bazy
        for token in tokens:
            token_lower = token.lower()
            if any(code.lower() in token_lower or token_lower in code.lower() for code in product_codes_from_database):
                return False
        
        # KROK 1.6: Sprawdź wzorce kodów produktów (regex)
        for token in tokens:
            if any(re.match(pattern, token.upper()) for pattern in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['product_code_patterns']):
                return False
        
        # NOWA LOGIKA: Sprawdź kontekst motoryzacyjny PRZED filtrowaniem
        has_auto_context = self.has_automotive_context(tokens)
        
        # Słownik znanych literówek kategorii
        category_typos = {
            'amortyztor': 'amortyzator',
            'filetr': 'filtr', 
            'filtery': 'filtr',
            'swica': 'świeca',
            'swieca': 'świeca',
            'akumlator': 'akumulator',
            'kloki': 'klocki',
            'hamulcowy': 'hamulcowe',
            'hamulec': 'hamulce',
            'tarcze': 'tarcza',
            'tarczy': 'tarcza',
            'świece': 'świeca',
            'swiec': 'świeca',
            'sprężyny': 'sprężyna',
            'sprężyn': 'sprężyna',
            'amortyzatory': 'amortyzator',
            'tarzca': 'tarcza'
        }
        
        # Sprawdź czy ma znane literówki kategorii
        has_auto_category_typo = any(token.lower() in category_typos for token in tokens)
        
        # Jeśli ma kontekst auto lub znaną literówkę, zastosuj łagodniejsze filtry
        if has_auto_context or has_auto_category_typo:
            # Zastosuj tylko najostrzejsze filtry
            harsh_nonsense_patterns = [
                'qwerty asdf', 'asdf qwerty', 'qwe asd', 'asd qwe',
                'hello world', 'pizza hamburger', 'test test'
            ]
            
            if any(combo in query_text for combo in harsh_nonsense_patterns):
                return True
            
            # Sprawdź absurdalne kombinacje jak "klocki do pizzy"
            if 'do' in tokens:
                try:
                    do_index = tokens.index('do')
                    if (do_index > 0 and do_index < len(tokens)-1):
                        after_do = tokens[do_index+1]
                        food_endings = ['pizzy', 'kawy', 'herbaty', 'chleba', 'komputera', 'telefonu', 'lodówki']
                        if after_do in food_endings:
                            return True
                except ValueError:
                    pass
            
            return False  # Nie filtruj jeśli ma kontekst auto
        
        # === PRIORYTET 1: POLSKIE STOP WORDS BEZ KONTEKSTU AUTO ===
        polish_stopwords = {
            'jestem', 'jest', 'to', 'na', 'w', 'do', 'z', 'i', 'a', 'o', 'że', 'się',
            'nie', 'ale', 'jak', 'co', 'czy', 'gdzie', 'kiedy', 'dlaczego', 'bardzo',
            'też', 'już', 'tylko', 'może', 'będzie', 'można', 'mam', 'ma'
        }
        
        # Jeśli całe zapytanie to stop words
        if all(token.lower() in polish_stopwords for token in tokens):
            return True
        
        # Jeśli zapytanie składa się z samych stop words i bardzo krótkich słów
        if all(token.lower() in polish_stopwords or len(token) <= 2 for token in tokens):
            return True
        
        # === MINIMUM LENGTH CHECK ===
        if len(query_text) < 3:
            return True
        
        # === BARDZO KRÓTKIE TOKENY BEZ KONTEKSTU ===
        very_short_tokens = [t for t in tokens if len(t) <= 2]
        if len(very_short_tokens) >= len(tokens) // 2:
            return True
        
        # === PRIORYTET 2: KEYBOARD PATTERNS ===
        keyboard_combinations = [
            'qwerty asdf', 'asdf qwerty', 'qwe asd', 'asd qwe',
            'zxc vbn', 'vbn zxc', 'dfg hjk', 'hjk dfg',
            'asdfgh jklm', 'qwerty zxcv'
        ]
        if any(combo in query_text for combo in keyboard_combinations):
            return True
        
        # ROZSZERZONE keyboard patterns
        keyboard_patterns_extended = self.NONSENSE_DICTIONARY['keyboard_patterns'] + [
            'jklm', 'hjkl', 'yuio', 'uiop', 'mnbv', 'lkjh'
        ]
        
        keyboard_count = sum(1 for token in tokens 
                           if any(pattern in token.lower() for pattern in keyboard_patterns_extended))
        if keyboard_count >= 2:
            return True
        
        # === PRIORYTET 3: MIESZANE JĘZYKI Z NONSENSEM ===
        english_nonsense = ['hello', 'world', 'test', 'check', 'sample', 'demo']
        
        # Hello/world bez kontekstu auto = nonsens
        if any(word in [t.lower() for t in tokens] for word in english_nonsense):
            return True
        
        # === PRIORYTET 4: FOOD + NONSENS ===
        food_words = ['pizza', 'hamburger', 'burger', 'food', 'eat', 'meal', 'restaurant', 'cook']
        has_food = any(word in [t.lower() for t in tokens] for word in food_words)
        
        if has_food:
            return True
        
        # === PRIORYTET 5: FRAZY KONWERSACYJNE ===
        if any(phrase in query_text for phrase in self.NONSENSE_DICTIONARY['conversational_phrases']):
            return True
        
        # === PRIORYTET 6: POWTÓRZENIA I GIBBERISH ===
        for token in tokens:
            token_lower = token.lower()
            
            # Powtórzenia liter
            if len(set(token_lower)) == 1 and len(token_lower) > 3:
                return True
                
            # Gibberish patterns
            if any(pattern in token_lower for pattern in self.NONSENSE_DICTIONARY['gibberish_patterns']):
                return True
        
        # === PRIORYTET 7: SAME LICZBY BEZ KONTEKSTU - POPRAWIONE ===
        if len(tokens) <= 3 and all(token.isdigit() for token in tokens):
            total_digits = sum(len(token) for token in tokens)
            # ZMIANA: Nie filtruj długich kodów produktów (mogą być OEM)
            if total_digits >= 12:  # Tylko bardzo długie bezsensowne ciągi
                return True
            elif total_digits <= 4:  # Krótkie liczby = prawdopodobnie nonsens
                return True
        
        return False

    

    def get_fuzzy_product_matches_internal(self, query: str, machine_filter: Optional[str] = None) -> List[Tuple]:
        """NAPRAWIONA - Algorytm który WYKLUCZA metadane i poprawnie matchuje"""
        matches = []
        query_tokens = query.lower().split()
        
        for product in self.product_database['products']:
            if machine_filter and product['machine'] != machine_filter and product['machine'] != 'uniwersalny':
                continue
            
            # KLUCZOWA NAPRAWA: Tylko istotne pola dla matchowania
            # WYKLUCZA: stock, price, id (metadane)
            product_text = f"{product['name']} {product['brand']} {product['model']} {product['category']}"
            product_tokens = product_text.lower().split()
            
            # NOWY ALGORYTM - Precyzyjne dopasowanie per token
            token_scores = []
            
            for q_token in query_tokens:
                best_token_match = 0
                
                # NAPRAWKA: Wykluczenie matchowania liczb do stock/price
                if q_token.isdigit() and len(q_token) <= 3:
                    # Krótkie liczby (jak "89") mogą być przypadkowe
                    # Sprawdź czy to prawdopodobnie część kodu produktu
                    has_letters_context = any(
                        not token.isdigit() and len(token) > 1 
                        for token in query_tokens
                    )
                    if not has_letters_context:
                        # Sama liczba bez kontekstu - skip
                        continue
                
                # Sprawdź każdy token produktu
                for p_token in product_tokens:
                    # NAPRAWKA: Nie dopasowuj prostych liczb do stocku
                    if q_token.isdigit() and p_token.isdigit() and len(q_token) <= 3:
                        continue  # Skip przypadkowe dopasowania liczb
                    
                    if q_token == p_token:
                        # Dokładne dopasowanie = 100%
                        best_token_match = 100
                        break
                    elif p_token.startswith(q_token) and len(q_token) >= 2:
                        # Prefix match (np. "gol" -> "golf")
                        match_ratio = len(q_token) / len(p_token)
                        best_token_match = max(best_token_match, 95 * match_ratio)
                    elif q_token.startswith(p_token) and len(p_token) >= 2:
                        # Suffix match
                        match_ratio = len(p_token) / len(q_token)
                        best_token_match = max(best_token_match, 90 * match_ratio)
                    else:
                        # Fuzzy match - tylko dla sensownych podobieństw
                        similarity = fuzz.ratio(q_token, p_token)
                        if similarity > 85:  # Podwyższony próg
                            best_token_match = max(best_token_match, similarity * 0.95)
                        elif similarity > 75:
                            best_token_match = max(best_token_match, similarity * 0.85)
                
                token_scores.append(best_token_match)
            
            # Oblicz wynik końcowy tylko jeśli są sensowne dopasowania
            if not token_scores or all(score == 0 for score in token_scores):
                continue
                
            # Średnia ważona
            base_score = sum(token_scores) / len(token_scores)
            
            # Bonus za precyzję - bez zmian
            if len(query_tokens) > 1:
                if all(score > 70 for score in token_scores):
                    base_score *= 1.3
                elif all(score > 60 for score in token_scores):
                    base_score *= 1.2
                elif all(score > 50 for score in token_scores):
                    base_score *= 1.1
                elif any(score < 20 for score in token_scores):
                    base_score *= 0.8
            
            # Dodatkowe bonusy kontekstowe - bez zmian
            bonus = 0
            brand_lower = product['brand'].lower()
            if brand_lower in query or query in brand_lower:
                bonus += 15
            
            model_lower = product['model'].lower()
            for q_token in query_tokens:
                if len(q_token) > 2 and q_token in model_lower:
                    bonus += 10
                    break
            
            category = product['category'].lower()
            for q_token in query_tokens:
                if q_token in category:
                    bonus += 10
                    break
            
            final_score = min(100, base_score + bonus)
            
            # PODWYŻSZONY PRÓG - eliminuje słabe dopasowania
            if final_score >= 35:  # Zwiększone z 25
                matches.append((product, round(final_score)))
        
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches

    def analyze_query_intent(self, query: str, machine_filter: Optional[str] = None) -> Dict:
        """
        OPERACJA LISEK PUSTYNI - Z OBSŁUGĄ LITERÓWEK I ZAPYTAŃ KONTEKSTOWYCH
        KLUCZOWE ZMIANY: Obniżone progi klasyfikacji + specjalna ścieżka dla specyfikacji technicznych
        """
        query_lower = query.lower().strip()
        
        # === NOWY PREPROCESSING - KROK 1: Tłumacz wielojęzyczne i slang ===
        preprocessed_tokens = []
        for token in query_lower.split():
            original_token = token
            # Tłumacz terminy wielojęzyczne
            if hasattr(self, 'MULTILINGUAL_TERMS') and token in self.MULTILINGUAL_TERMS:
                token = self.MULTILINGUAL_TERMS[token]
                print(f"[ANALYZE DEBUG] Translated: {original_token} -> {token}")
            # Popraw slang
            if hasattr(self, 'SLANG_DICTIONARY') and token in self.SLANG_DICTIONARY:
                token = self.SLANG_DICTIONARY[token]
                print(f"[ANALYZE DEBUG] Slang fixed: {original_token} -> {token}")
            preprocessed_tokens.append(token)
        
        # Złóż z powrotem
        query_lower = ' '.join(preprocessed_tokens)
        
        # === NOWY PREPROCESSING - KROK 2: Napraw podwójne litery ===
        if hasattr(self, 'fix_double_letters'):
            query_before_double = query_lower
            query_lower = self.fix_double_letters(query_lower)
            if query_before_double != query_lower:
                print(f"[ANALYZE DEBUG] Double letters fixed: '{query_before_double}' -> '{query_lower}'")
        
        # === NOWY PREPROCESSING - KROK 3: Zastosuj istniejące korekty literówek ===
        corrected_query = self.correct_query_typos(query_lower)
        if corrected_query != query_lower:
            print(f"[ANALYZE DEBUG] Typos corrected: '{query_lower}' -> '{corrected_query}'")
            query_lower = corrected_query
        
        query_tokens = query_lower.split()
        
        # DEBUG
        print(f"[ANALYZE DEBUG] Query: '{query}', Tokens: {query_tokens}")
        print(f"[ANALYZE DEBUG] has_automotive_context: {self.has_automotive_context(query_tokens)}")
        print(f"[ANALYZE DEBUG] is_obvious_nonsense: {self.is_obvious_nonsense(query_tokens, 0)}")
        
        # KROK 1: Filtr nonsense
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
        
        # KROK 2: Filtr kontekstu motoryzacyjnego
        if not self.has_automotive_context(query_tokens):
            return {
                'query': query,
                'tokens': query_tokens,
                'token_validity': 0,
                'best_match_score': 0,
                'confidence_level': 'LOW',
                'suggestion_type': 'no_automotive_context',
                'ga4_event': 'search_failure',
                'has_luxury_brand': False,
                'has_product_code': False,
                'is_structural': False,
                'is_nonsense': True,
                'matches': []
            }
        
        # === NOWY KROK 2.5: Wczesne wyszukiwanie produktów po preprocessing ===
        matches = self.get_fuzzy_product_matches_internal(query_lower, machine_filter)
        best_match_score = matches[0][1] if matches else 0
        
        # Jeśli po preprocessing znaleźliśmy dobre dopasowanie, zwróć od razu
        if best_match_score >= 60:
            print(f"[ANALYZE DEBUG] Early match found after preprocessing: score={best_match_score}")
        
        # KROK 3: Sprawdź token validity i structural
        token_validity = self.calculate_token_validity(query_tokens)
        is_structural = self.is_structural_query(query_tokens)
        
        # === OPERACJA LISEK PUSTYNI - WYKRYJ SPECYFIKACJE TECHNICZNE ===
        has_technical_spec = False
        has_tire_size = False
        has_oil_spec = False
        has_season_word = False
        
        for token in query_tokens:
            token_lower = token.lower()
            
            # Rozmiary opon (195/65r15, 225/45r17)
            if re.match(r'^\d{3}/\d{2}[rR]\d{2}$', token):
                has_tire_size = True
                has_technical_spec = True
                print(f"[LISEK DEBUG] Wykryto rozmiar opon: {token}")
            
            # Specyfikacje olejów (5w30, 0w40)
            if re.match(r'^\d+w\d+$', token_lower):
                has_oil_spec = True
                has_technical_spec = True
                print(f"[LISEK DEBUG] Wykryto specyfikację oleju: {token}")
            
            # Słowa sezonowe i techniczne
            if token_lower in ['longlife', 'półsyntetyczny', 'syntetyczny', 'letnie', 'zimowe', 'lato', 'zima']:
                has_season_word = True
                has_technical_spec = True
                print(f"[LISEK DEBUG] Wykryto słowo techniczne: {token}")
        
        # KROK 4: Sprawdź czy query zawiera znane literówki
        known_typos = {
            'swiczka', 'opon', 'przod', 'powietza', 'tarzca', 'sprezyny', 'bateri', 
            'lanczuch', 'swieczka', 'kloce', 'zimow', 'fltr', 'klockei', 'świczka',
            'amortyzzator', 'akumualtor', 'filttr', 'olel', 'amortyztor', 'filetr',
            'swica', 'swieca', 'akumlator', 'kloki', 'hamulcwe', 'tarcze', 'tarczy',
            'świece', 'swiec', 'sprężyny', 'sprężyn', 'opny', 'opona', 'bosh', 'sacsh',
            'bmv', 'toyoya', 'zimowy', 'oleju', 'oleje', 'tylny', 'przedni', 'filet',
            'filrt', 'flitr', 'hamulec', 'hamulcowy', 'hamulcow'
        }
        
        query_has_typos = any(token.lower() in known_typos for token in query_tokens)
        
        has_luxury_brand = any(
            brand in query_lower 
            for brand in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['luxury_brands']
        )
        
        potential_product_codes = []
        short_codes = []
        nonsense_codes = []
        
        for token in query_tokens:
            token_upper = token.upper()
            
            if (token.isdigit() and len(token) >= 6 and 
                not any(brand in query_lower for brand in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands']) and
                not any(cat in query_lower for cat in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories'])):
                nonsense_codes.append(token)
                continue
                
            if (re.match(r'^[A-Z]\d{2,}', token_upper) or      
                re.match(r'^\d{4,}', token) or                  
                re.match(r'^[A-Z]{2,}\d{2,}', token_upper)):
                potential_product_codes.append(token)
            elif (len(token) >= 1 and len(token) <= 3 and 
                  (token.isdigit() or (token.isalnum() and any(c.isdigit() for c in token)))):
                short_codes.append(token)
        
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
        
        has_nonexistent_code = False
        has_nonexistent_short_code = False
        
        if potential_product_codes:
            for code in potential_product_codes:
                code_exists = False
                for product in self.product_database['products']:
                    if (code.upper() in product['model'].upper() or 
                        code.upper() in product['id'] or
                        code.upper() in product['name'].upper()):
                        code_exists = True
                        break
                
                if not code_exists and len(code) >= 3:
                    has_nonexistent_code = True
                    break
        
        if short_codes and len(query_tokens) >= 2:
            has_known_context = any(
                token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands'] or
                token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories'] or
                token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['luxury_brands']
                for token in query_tokens
            )
            
            if has_known_context:
                for code in short_codes:
                    code_exists = False
                    for product in self.product_database['products']:
                        if (code.upper() in product['model'].upper() or 
                            code.upper() in product['id'] or
                            code.upper() in product['name'].upper()):
                            code_exists = True
                            break
                    
                    if not code_exists:
                        has_nonexistent_short_code = True
                        break
        
        # KROK 4.5: NOWY - Wykryj legalne zapytania kontekstowe
        context_words_list = ['do', 'dla', 'na', 'pasuje', 'części', 'część', 'zimę', 'zimą', 'latem', 'w', 'z', 'pod']
        has_context_words = any(
            token.lower() in context_words_list
            for token in query_tokens
        )
        
        has_known_brand = any(
            token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands'] or
            token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_models'] or
            token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands']
            for token in query_tokens
        )
        
        has_part = any(
            token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['part_categories']
            for token in query_tokens
        )
        
        # Jeśli ma context words + (brand LUB part) = legalne zapytanie kontekstowe
        if has_context_words and (has_known_brand or has_part) and best_match_score >= 35:
            print(f"[ANALYZE DEBUG] Detected contextual query: context={has_context_words}, brand={has_known_brand}, part={has_part}, score={best_match_score}")
            confidence_level = 'MEDIUM' if best_match_score >= 50 else 'HIGH' if best_match_score >= 70 else 'MEDIUM'
            suggestion_type = 'contextual_query'
            ga4_event = None
            
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
        
        # SPECJALNA LOGIKA DLA LITERÓWEK Z KOREKTY STRUKTURALNEJ
        if (is_structural and token_validity >= 70 and best_match_score < 70):
            category_typos = {
                'amortyztor': 'amortyzator',
                'swica': 'świeca',
                'swieca': 'świeca', 
                'akumlator': 'akumulator',
                'filetr': 'filtr',
                'kloki': 'klocki'
            }
            
            has_category_typo = any(token.lower() in category_typos for token in query_tokens)
            has_known_brand_structural = any(
                token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['car_brands'] or
                token.lower() in self.UNIVERSAL_AUTOMOTIVE_KNOWLEDGE['motorcycle_brands']
                for token in query_tokens
            )
            
            if has_category_typo and has_known_brand_structural:
                corrected_query = query_lower
                for typo, correct in category_typos.items():
                    corrected_query = corrected_query.replace(typo, correct)
                
                corrected_matches = self.get_fuzzy_product_matches_internal(corrected_query, machine_filter)
                corrected_best_score = corrected_matches[0][1] if corrected_matches else 0
                
                if corrected_best_score >= 60:
                    confidence_level = 'HIGH'
                    suggestion_type = 'typo_corrected_structural'
                    ga4_event = 'search_typo_corrected'
                    matches = corrected_matches
                    best_match_score = corrected_best_score
                    
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
        
        # === OPERACJA LISEK PUSTYNI - GŁÓWNA KLASYFIKACJA Z OBNIŻONYMI PROGAMI ===
        
        # STRATEGIA 1: Specjalne traktowanie specyfikacji technicznych
        if has_technical_spec and best_match_score >= 35:
            print(f"[LISEK DEBUG] Specyfikacja techniczna wykryta - obniżony próg aktywowany")
            if best_match_score >= 65:  # OBNIŻONE z 90
                confidence_level = 'HIGH'
                suggestion_type = 'technical_specification_match'
                ga4_event = None
            else:
                confidence_level = 'MEDIUM'
                suggestion_type = 'technical_specification_partial'
                ga4_event = 'search_typo_corrected'
            
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
        
        # STRATEGIA 2: Standardowa klasyfikacja z obniżonymi progami
        if best_match_score >= 75:  # OBNIŻONE z 90
            confidence_level = 'HIGH'
            suggestion_type = 'exact_match'
            ga4_event = None
        elif is_structural:
            confidence_level = 'NO_MATCH'
            suggestion_type = 'structural_missing'
            ga4_event = 'search_lost_demand'
        elif has_nonexistent_code and token_validity >= 40:
            confidence_level = 'NO_MATCH'
            suggestion_type = 'product_code_missing'
            ga4_event = 'search_lost_demand'
        elif has_nonexistent_short_code and token_validity >= 70:
            confidence_level = 'NO_MATCH'
            suggestion_type = 'short_code_missing'
            ga4_event = 'search_lost_demand'
        elif potential_product_codes and best_match_score >= 40:
            confidence_level = 'MEDIUM'
            suggestion_type = 'code_found'
            ga4_event = 'search_typo_corrected'
        elif has_luxury_brand and best_match_score < 60:
            confidence_level = 'NO_MATCH'
            suggestion_type = 'luxury_brand_missing'
            ga4_event = 'search_lost_demand'
        elif best_match_score >= 65:  # OBNIŻONE z 80
            confidence_level = 'HIGH'
            suggestion_type = 'good_match'
            ga4_event = None
        elif best_match_score >= 55 and token_validity >= 50:  # OBNIŻONE z 70
            confidence_level = 'MEDIUM'
            suggestion_type = 'typo_correction'
            ga4_event = 'search_typo_corrected'
        elif query_has_typos and best_match_score >= 25:
            confidence_level = 'MEDIUM'
            suggestion_type = 'typo_correction'
            ga4_event = 'search_typo_corrected'
        elif (len(query_tokens) >= 2 and 
              token_validity >= 70 and 
              best_match_score < 55 and  # OBNIŻONE z 70
              not potential_product_codes and
              not short_codes):
            confidence_level = 'NO_MATCH'
            suggestion_type = 'model_missing'
            ga4_event = 'search_lost_demand'
        elif token_validity >= 35:
            confidence_level = 'NO_MATCH'
            suggestion_type = 'product_missing'
            ga4_event = 'search_lost_demand'
        elif token_validity >= 20:
            confidence_level = 'NO_MATCH'
            suggestion_type = 'unknown_brand'
            ga4_event = 'search_lost_demand'
        else:
            confidence_level = 'LOW'
            suggestion_type = 'nonsensical'
            ga4_event = 'search_failure'
        
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
    
    
    def normalize_query(self, query: str) -> str:
        """Normalizacja zapytania z obsługą literówek"""
        query = query.lower().strip()
        
        # Podstawowe korekty literówek
        typo_corrections = {
            'kloki': 'klocki',
            'klocek': 'klocki',
            'filtr': 'filtr',
            'filetr': 'filtr',
            'amortyztor': 'amortyzator',
            'swica': 'świeca',
            'swieca': 'świeca',
            'gol': 'golf',
            'vw': 'volkswagen',
            'mb': 'mercedes',
            'yam': 'yamaha',
            'sprin': 'sprinter'
        }
        
        for typo, correction in typo_corrections.items():
            query = query.replace(typo, correction)
        
        return ' '.join(query.split())
    
    def get_fuzzy_product_matches(self, query: str, machine_filter: Optional[str] = None, 
                                  limit: int = 6, analyze_intent: bool = True) -> Tuple:
        """Ulepszona funkcja dopasowania z analizą intencji"""
        query = self.normalize_query(query)
        
        if analyze_intent:
            # Pełna analiza intencji
            analysis = self.analyze_query_intent(query)
            
            # Filtruj wyniki na podstawie confidence level
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
            # Stare zachowanie dla kompatybilności wstecznej
            matches = self.get_fuzzy_product_matches_internal(query, machine_filter)
            return matches[:limit]
    
    def get_fuzzy_faq_matches(self, query: str, limit: int = 5) -> List[Tuple]:
        """FAQ z predykcją znak-po-znaku + progresywny scoring"""
        query = self.normalize_query(query).lower()
        
        if len(query) < 2:
            return []
        
        matches = []
        
        for faq in self.faq_database:
            question_lower = faq['question'].lower()
            keywords_lower = [k.lower() for k in faq['keywords']]
            
            best_score = 0
            
            if query in question_lower:
                base = (len(query) / len(question_lower)) * 100
                if question_lower.startswith(query):
                    best_score = min(100, base + 30)
                else:
                    best_score = min(100, base + 15)
            
            for keyword in keywords_lower:
                if query in keyword:
                    base = (len(query) / len(keyword)) * 100
                    if keyword.startswith(query):
                        score = min(95, base + 25)
                    else:
                        score = min(90, base + 10)
                    best_score = max(best_score, score)
            
            if best_score == 0:
                if len(query) >= 4:
                    question_score = fuzz.partial_ratio(query, question_lower)
                    if question_score > 65:
                        best_score = question_score * 0.85
            
            if best_score >= 35:
                matches.append((faq, round(best_score)))
        
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches[:limit]
    
    def determine_ga4_event(self, analysis: Dict) -> Optional[Dict]:
        """Określa które zdarzenie GA4 wysłać na podstawie analizy"""
        if not analysis['ga4_event']:
            return None
        
        event_data = {
            'event': analysis['ga4_event'],
            'params': {
                'query': analysis['query'],
                'token_validity': analysis['token_validity'],
                'best_match_score': analysis['best_match_score'],
                'confidence_level': analysis['confidence_level']
            }
        }
        
        # Dodaj specyficzne parametry dla różnych eventów
        if analysis['ga4_event'] == 'search_lost_demand':
            potential_product = self.extract_product_intent(analysis['query'])
            event_data['params']['potential_product'] = potential_product
            event_data['params']['priority'] = 'HIGH'
            if analysis.get('has_luxury_brand'):
                event_data['params']['luxury_brand'] = True
        
        elif analysis['ga4_event'] == 'search_failure':
            event_data['params']['reason'] = 'nonsensical_query'
        
        elif analysis['ga4_event'] == 'search_typo_corrected':
            if analysis['matches']:
                event_data['params']['suggested_product'] = analysis['matches'][0][0]['name']
        
        return event_data
    
    def extract_product_intent(self, query: str) -> str:
        """Próbuje wyekstrahować intencję produktu z zapytania"""
        tokens = query.lower().split()
        product_hints = []
        
        for token in tokens:
            if token in self.AUTOMOTIVE_DICTIONARY['categories']:
                product_hints.append(token)
            elif token in self.AUTOMOTIVE_DICTIONARY['brands']:
                product_hints.append(token)
            elif token in self.AUTOMOTIVE_DICTIONARY['luxury_brands']:
                product_hints.append(token)
        
        return ' '.join(product_hints) if product_hints else query
    
    def send_ga4_event(self, event_data: Dict) -> bool:
        """Wysyła zdarzenie do GA4"""
        try:
            GA4_MEASUREMENT_ID = "G-ECOMMERCE123"
            GA4_API_SECRET = "YOUR_API_SECRET_HERE"
            
            session_data = f"universal_soldier_{int(time.time() // 3600)}"
            client_id = hashlib.md5(session_data.encode()).hexdigest()
            
            url = "https://www.google-analytics.com/mp/collect"
            params = {
                'measurement_id': GA4_MEASUREMENT_ID,
                'api_secret': GA4_API_SECRET
            }
            
            payload = {
                "client_id": client_id,
                "events": [{
                    "name": event_data['event'],
                    "params": event_data['params']
                }]
            }
            
            response = requests.post(url, params=params, json=payload, timeout=5)
            
            if response.status_code == 204:
                print(f"[GA4] ✅ Event sent: {event_data['event']} for query: '{event_data['params']['query']}'")
                return True
            else:
                print(f"[GA4] ❌ Failed to send event. Status: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[GA4] 💥 Error sending event: {e}")
            return False
        
    def search_products(self, query: str, machine_filter: Optional[str] = None) -> List:
        """Wyszukiwanie produktów (kompatybilność wsteczna)"""
        result = self.get_fuzzy_product_matches(query, machine_filter, analyze_intent=False)
        if isinstance(result, tuple):
            return [product for product, score in result[0]]
        else:
            return [product for product, score in result]
    
    def search_faq(self, query: str) -> List:
        """Wyszukiwanie FAQ"""
        results = self.get_fuzzy_faq_matches(query, limit=10)
        return [faq for faq, score in results]
    
    def get_initial_greeting(self) -> Dict:
        """Powitanie"""
        
        # Używamy globalnej zmiennej wczytanej z config_teksty.json
        # zamiast "hardcoded" tekstu.
        
        return {
            'text_message': GLOBAL_WELCOME_MESSAGE,
            'buttons': [
                {'text': '🔧 Znajdź część', 'action': 'search_product'},
                {'text': '📦 Status zamówienia', 'action': 'order_status'},
                {'text': '❓ Mam pytanie', 'action': 'faq_search'},
                {'text': '🚚 Dostawa i koszty', 'action': 'faq_delivery'},
                {'text': '↩️ Zwroty i gwarancja', 'action': 'faq_returns'},
                {'text': '📞 Kontakt', 'action': 'contact'}
            ]
        }
    
    def handle_button_action(self, action: str) -> Dict:
        """Obsługa akcji przycisków"""
        session['context'] = action
        
        if action == 'search_product':
            return {
                'text_message': """🔧 **Wyszukiwarka części**

Wybierz typ pojazdu:""",
                'buttons': [
                    {'text': '🚗 Samochód osobowy', 'action': 'machine_osobowy'},
                    {'text': '🚐 Dostawczy', 'action': 'machine_dostawczy'},
                    {'text': '🏍️ Motocykl', 'action': 'machine_motocykl'},
                    {'text': '↩️ Powrót', 'action': 'main_menu'}
                ]
            }
        
        elif action.startswith('machine_'):
            machine_type = action.replace('machine_', '')
            session['machine_filter'] = machine_type
            
            return {
                'text_message': f"""✅ **Wybrany typ: {machine_type}**

Wpisz czego szukasz. System inteligentnie rozpozna Twoje zapytanie!""",
                'enable_input': True,
                'input_placeholder': 'np. klocki bosch, filtr mann...',
                'search_mode': True
            }
        
        elif action == 'faq_search':
            return {
                'text_message': """❓ **Centrum pomocy**

Zadaj pytanie:""",
                'enable_input': True,
                'input_placeholder': 'np. jak sprawdzić czy część pasuje...',
                'faq_mode': True
            }
        
        elif action == 'main_menu':
            return self.get_initial_greeting()
        
        elif action.startswith('faq_'):
            return self.handle_faq(action)
        
        elif action.startswith('show_full_card_'):
            product_id = action.replace('show_full_card_', '')
            return self.show_full_product_card(product_id)
        
        elif action.startswith('product_details_'):
            product_id = action.replace('product_details_', '')
            return self.show_product_details(product_id)
        
        elif action.startswith('add_to_cart_'):
            product_id = action.replace('add_to_cart_', '')
            return self.add_to_cart(product_id)
        
        elif action == 'notify_when_available':
            return {
                'text_message': """📧 **Powiadomienie o dostępności**

Zapisaliśmy Twoje zapytanie. Powiadomimy Cię gdy produkt będzie dostępny!""",
                'buttons': [
                    {'text': '🔄 Szukaj czegoś innego', 'action': 'search_product'},
                    {'text': '↩️ Menu główne', 'action': 'main_menu'}
                ]
            }
        
        return {
            'text_message': 'Wybierz opcję:',
            'buttons': [{'text': '↩️ Menu główne', 'action': 'main_menu'}]
        }
    
    def handle_faq(self, action: str) -> Dict:
        """Obsługa FAQ"""
        faq_mapping = {
            'faq_delivery': 'FAQ001',
            'faq_returns': 'FAQ002'
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
        """Przetwarzanie wiadomości z NAPRAWIONĄ inteligentną analizą"""
        context = session.get('context', '')
        
        if session.get('machine_filter'):
            machine_filter = session.get('machine_filter')
            
            # NAPRAWKA: Bezpośrednio użyj analyze_query_intent
            analysis = self.analyze_query_intent(message, machine_filter)
            
            # Wyciągnij dane z analizy
            products = analysis['matches'][:5]  # To już jest lista (product, score)
            confidence_level = analysis['confidence_level']
            suggestion_type = analysis['suggestion_type']
            
            # Wyślij odpowiednie zdarzenie GA4
            ga4_event = self.determine_ga4_event(analysis)
            if ga4_event:
                self.send_ga4_event(ga4_event)
            
            # NAPRAWIONE ODPOWIEDZI NA PODSTAWIE CONFIDENCE LEVEL
            if confidence_level == 'HIGH':
                if products:
                    products_text = "✅ **Znaleźliśmy produkty:**\n\n"
                    for product, score in products:
                        products_text += f"**{product['name']}**\n"
                        products_text += f"📊 Dopasowanie: {score}% | 💰 {product['price']:.2f} zł\n\n"
                    
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
                        products_text += f"📊 Dopasowanie: {score}% | 💰 {product['price']:.2f} zł\n\n"
                    products_text += "\n💡 *System automatycznie poprawił literówki*"
                    
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
            
            else:  # NO_MATCH - PRAWDZIWY UTRACONY POPYT!
                # NOWA obsługa dla różnych typów brakujących produktów
                if analysis.get('suggestion_type') == 'structural_missing':
                    message_text = f"""🔍 **Produkt spoza naszej oferty**

Szukana fraza: "{message}"
📊 System wykrył: kategoria + nieznana marka

✨ **Zapisaliśmy Twoje zapytanie!** 
Jeśli więcej osób będzie szukać tej marki, rozważymy dodanie do oferty."""
                else:
                    # Specjalna wiadomość dla marek luksusowych
                    luxury_message = ""
                    if analysis.get('has_luxury_brand'):
                        luxury_message = "\n🏎️ **Wykryto markę premium** - zwiększony priorytet!"
                    
                    message_text = f"""🔍 **Nie mamy tego produktu w ofercie**

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
        
        # Obsługa FAQ
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
                {'text': '🔧 Szukaj części', 'action': 'search_product'},
                {'text': '↩️ Menu główne', 'action': 'main_menu'}
            ]
        }
    
    def create_product_buttons(self, products: List[Tuple]) -> List[Dict]:
        """Tworzy przyciski dla produktów - BEZPOŚREDNIO DO PEŁNEJ KARTY"""
        buttons = []
        for item in products[:3]:
            if isinstance(item, tuple):
                product, score = item
                # Usuń score, kieruj bezpośrednio do pełnej karty
                buttons.append({
                    'text': f"🛒 {product['name'][:45]}...",
                    'action': f"show_full_card_{product['id']}"
                })
        
        buttons.extend([
            {'text': '🔄 Szukaj ponownie', 'action': 'search_product'},
            {'text': '↩️ Menu główne', 'action': 'main_menu'}
        ])
        
        return buttons
    
    def show_product_details(self, product_id: str, match_score: Optional[int] = None) -> Dict:
        """Szczegóły produktu"""
        product = None
        for p in self.product_database['products']:
            if p['id'] == product_id:
                product = p
                break
        
        if not product:
            return {
                'text_message': 'Produkt nie znaleziony.',
                'buttons': [{'text': '↩️ Menu główne', 'action': 'main_menu'}]
            }
        
        return {
            'text_message': f"""🔧 **{product['name']}**

💰 **Cena:** {product['price']:.2f} zł netto
📦 **Stan:** {product['stock']} szt.""",
            'buttons': [
                {'text': f"🛒 Dodaj do koszyka", 'action': f"add_to_cart_{product['id']}"},
                {'text': '🔍 Szukaj dalej', 'action': 'search_product'},
                {'text': '🏠 Menu główne', 'action': 'main_menu'}
            ]
        }
    
    def show_full_product_card(self, product_id: str) -> Dict:
        """Pokazuje pełną kartę produktu bez pośrednich kroków"""
        product = None
        for p in self.product_database['products']:
            if p['id'] == product_id:
                product = p
                break
        
        if not product:
            return {
                'text_message': 'Produkt nie znaleziony.',
                'buttons': [{'text': '↩️ Menu główne', 'action': 'main_menu'}]
            }
        
        return {
            'text_message': f"""🔧 {product['name']}

💰 Cena: {product['price']:.2f} zł netto
📦 Stan: {product['stock']} szt.""",
            'buttons': [
                {'text': '🛒 Dodaj do koszyka', 'action': f"add_to_cart_{product['id']}"},
                {'text': '🔍 Szukaj dalej', 'action': 'search_product'},
                {'text': '🏠 Menu główne', 'action': 'main_menu'}
            ]
        }
    
    def add_to_cart(self, product_id: str) -> Dict:
        """Dodanie do koszyka"""
        if 'cart' not in session:
            session['cart'] = []
        
        session['cart'].append(product_id)
        session.modified = True
        
        return {
            'text_message': f"""✅ **Dodano do koszyka!**""",
            'cart_updated': True,
            'buttons': [
                {'text': '🔍 Kontynuuj zakupy', 'action': 'search_product'},
                {'text': '↩️ Menu główne', 'action': 'main_menu'}
            ]
        }
