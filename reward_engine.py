from dataclasses import dataclass
from typing import Optional, List, Tuple
import math
import re
import logging

# Configure logging
logger = logging.getLogger(__name__)


# ========================================
# SEMANTIC VALIDATOR (AI Data Quality)
# ========================================

class SemanticValidator:
    """
    Waliduje czy zapytanie jest semantycznie sensowne i warte zapisania do AI training.

    Odrzuca:
    - Losowe znaki (asdfgh, qwerty)
    - Niekompletne prefiksy (<3 znaki)
    - Nieistniejące produkty (iPhone 30, Galaxy S99)
    - Jedzenie i inne kategorie spoza domeny

    Akceptuje:
    - Literówki w istniejących produktach
    - Nieznane marki (to jest Lost Demand!)
    - Specyfikacje których nie mamy
    """

    def __init__(self):
        # Wzorce nonsensów
        self.keyboard_patterns = [
            r'^[asdfghjkl]+$',
            r'^[qwertyuiop]+$',
            r'^[zxcvbnm]+$',
            r'^[0-9]+$',  # Same cyfry
            r'^(.)\1{3,}$',  # Powtórzone znaki (aaaa, bbbb)
        ]

        # Słowa z innych domen (nie e-commerce automotive/electronics)
        self.food_words = {
            'pizza', 'hamburger', 'kanapka', 'kawa', 'herbata', 'piwo', 'wino',
            'chleb', 'masło', 'ser', 'mleko', 'jajka', 'mięso', 'kurczak',
            'sushi', 'kebab', 'burger', 'frytki', 'cola', 'pepsi'
        }

        self.nonsense_words = {
            'hello', 'world', 'test', 'testing', 'foo', 'bar', 'baz',
            'lorem', 'ipsum', 'dolor', 'sit', 'amet', 'dupa', 'kurwa',
            'abc', 'xyz', 'aaa', 'bbb', 'ccc'
        }

        # Znane marki (dla walidacji "czy istnieje na świecie")
        self.known_auto_brands = {
            'bmw', 'mercedes', 'audi', 'volkswagen', 'vw', 'opel', 'ford',
            'toyota', 'honda', 'mazda', 'nissan', 'hyundai', 'kia', 'skoda',
            'seat', 'peugeot', 'renault', 'citroen', 'fiat', 'alfa', 'volvo',
            'porsche', 'ferrari', 'lamborghini', 'maserati', 'jaguar', 'bentley',
            'rolls-royce', 'aston', 'mclaren', 'bugatti', 'pagani', 'koenigsegg',
            'tesla', 'rivian', 'lucid', 'nio', 'byd', 'genesis', 'lexus',
            'infiniti', 'acura', 'cadillac', 'chevrolet', 'dodge', 'jeep',
            'yamaha', 'honda', 'kawasaki', 'suzuki', 'ducati', 'harley',
            'bosch', 'mann', 'mahle', 'bilstein', 'sachs', 'brembo', 'ate',
            'trw', 'ferodo', 'textar', 'valeo', 'denso', 'ngk', 'champion',
            'varta', 'exide', 'banner', 'continental', 'michelin', 'bridgestone',
            'pirelli', 'goodyear', 'dunlop', 'hankook', 'yokohama', 'castrol',
            'mobil', 'shell', 'total', 'elf', 'motul', 'liqui', 'k&n'
        }

        self.known_electronics_brands = {
            'apple', 'iphone', 'ipad', 'macbook', 'samsung', 'galaxy', 'lg',
            'sony', 'panasonic', 'philips', 'xiaomi', 'huawei', 'oppo', 'vivo',
            'oneplus', 'realme', 'motorola', 'nokia', 'asus', 'acer', 'lenovo',
            'dell', 'hp', 'microsoft', 'surface', 'google', 'pixel', 'amazon',
            'kindle', 'echo', 'bose', 'jbl', 'harman', 'sennheiser', 'sony',
            'beats', 'airpods', 'marshall', 'bang', 'olufsen', 'denon', 'yamaha',
            'nvidia', 'amd', 'intel', 'corsair', 'logitech', 'razer', 'steelseries'
        }

        # Nierealistyczne numery modeli (dla telefonów/samochodów)
        self.unrealistic_model_patterns = {
            'iphone': (1, 16),      # iPhone 1-16 realistyczne
            'galaxy s': (1, 25),    # Galaxy S1-S25
            'galaxy a': (1, 80),    # Galaxy A-series
            'pixel': (1, 10),       # Pixel 1-10
            'bmw': (1, 8),          # BMW seria 1-8
        }

        logger.info("[SEMANTIC] SemanticValidator initialized")

    def validate(self, query: str, confidence_level: str = None) -> Tuple[bool, str]:
        """
        Sprawdza czy zapytanie jest sensowne semantycznie.

        Returns:
            Tuple[bool, str]: (is_valid, reason)
            - True, "OK" - zapytanie czyste, warte zapisania
            - False, reason - zapytanie odrzucone z podanym powodem
        """
        if not query:
            return False, "EMPTY_QUERY"

        query_lower = query.lower().strip()

        # 1. Minimalna długość
        if len(query_lower) < 3:
            return False, "TOO_SHORT"

        # 2. Wzorce klawiaturowe
        for pattern in self.keyboard_patterns:
            if re.match(pattern, query_lower):
                return False, "KEYBOARD_PATTERN"

        # 3. Słowa nonsensowne
        tokens = query_lower.split()
        if len(tokens) == 1 and tokens[0] in self.nonsense_words:
            return False, "NONSENSE_WORD"

        # 4. Jedzenie (nie nasza domena)
        food_found = [t for t in tokens if t in self.food_words]
        if food_found and not self._has_domain_context(tokens):
            return False, f"FOOD_DOMAIN:{','.join(food_found)}"

        # 5. Nierealistyczne modele (iPhone 30, Galaxy S99)
        unrealistic = self._check_unrealistic_model(query_lower)
        if unrealistic:
            return False, f"UNREALISTIC_MODEL:{unrealistic}"

        # 6. Jeśli NO_MATCH ale ma kontekst domenowy - to jest Lost Demand (OK!)
        if confidence_level == 'NO_MATCH':
            if self._has_domain_context(tokens):
                return True, "VALID_LOST_DEMAND"
            else:
                # NO_MATCH bez kontekstu domenowego = prawdopodobnie śmieć
                return False, "NO_MATCH_NO_CONTEXT"

        return True, "OK"

    def _has_domain_context(self, tokens: List[str]) -> bool:
        """Sprawdza czy zapytanie ma kontekst automotive lub electronics."""
        all_brands = self.known_auto_brands | self.known_electronics_brands

        # Automotive keywords
        auto_keywords = {
            'klocki', 'hamulce', 'filtr', 'olej', 'opony', 'akumulator',
            'amortyzator', 'tarcze', 'świece', 'rozrząd', 'sprzęgło',
            'alternator', 'rozrusznik', 'chłodnica', 'pompa', 'wycieraczki'
        }

        # Electronics keywords
        electronics_keywords = {
            'telefon', 'smartfon', 'laptop', 'tablet', 'telewizor', 'tv',
            'słuchawki', 'głośnik', 'monitor', 'klawiatura', 'mysz',
            'ładowarka', 'kabel', 'etui', 'folia', 'powerbank'
        }

        for token in tokens:
            if token in all_brands:
                return True
            if token in auto_keywords:
                return True
            if token in electronics_keywords:
                return True

        return False

    def _check_unrealistic_model(self, query: str) -> Optional[str]:
        """Sprawdza czy numer modelu jest realistyczny."""

        for prefix, (min_num, max_num) in self.unrealistic_model_patterns.items():
            # Szukaj wzorców typu "iphone 30", "galaxy s99"
            pattern = rf'{prefix}\s*(\d+)'
            match = re.search(pattern, query)
            if match:
                model_num = int(match.group(1))
                if model_num > max_num:
                    return f"{prefix}_{model_num}"

        return None

    def get_ai_ready_flag(self, query: str, confidence_level: str) -> bool:
        """
        Zwraca flagę AI_READY dla zapytania.
        True = można użyć do trenowania AI
        False = śmieć, nie używać
        """
        is_valid, _ = self.validate(query, confidence_level)
        return is_valid


# Singleton instance
semantic_validator = SemanticValidator()

@dataclass
class UserSession:
    """
    [LEGACY] Reprezentuje sesję użytkownika do obliczania Reward Signal.
    To jest nasz 'atom' danych szkoleniowych dla CHATBOT interactions.
    ZACHOWANE DLA KOMPATYBILNOŚCI WSTECZNEJ.
    """
    session_id: str
    duration_seconds: float
    total_messages: int
    final_action: str  # 'purchase', 'cart_add', 'rage_quit', 'none'
    cart_value: float
    intent_shift_detected: bool = False  # "Vogal Shift" - zmiana intencji z 'browsing' na 'buying'


class RewardSignalCalculator:
    """
    [LEGACY] Silnik obliczający wartość nagrody dla CHATBOT RLHF.
    ZACHOWANE DLA KOMPATYBILNOŚCI WSTECZNEJ z /api/v1/event.
    Dla nowych integracji użyj LDIRewardCalculator.
    """
    
    def __init__(self):
        # Wagi dla różnych czynników
        self.weights = {
            'purchase': 100.0,
            'cart_add': 50.0,
            'message_engagement': 2.0,  # Punkty za każdą wiadomość
            'duration_sweet_spot': 10.0, # Bonus za idealny czas trwania (nie za krótko, nie za długo)
            'vogal_shift': 30.0         # Bonus za wykrytą zmianę intencji
        }
        
        # Penalties
        self.penalties = {
            'rage_quit': -50.0,
            'low_engagement': -10.0  # < 2 wiadomości
        }

    def calculate_score(self, session: UserSession) -> float:
        """
        Oblicza finalny Reward Score dla danej sesji.
        Zwraca float w zakresie zazwyczaj -100 do +200.
        """
        score = 0.0
        
        # 1. Base Action Reward
        if session.final_action == 'purchase':
            score += self.weights['purchase']
            # Bonus za wartość koszyka (np. 1 pkt za każde 10 zł)
            score += min(session.cart_value / 10.0, 50.0)
            
        elif session.final_action == 'cart_add':
            score += self.weights['cart_add']
            score += min(session.cart_value / 20.0, 20.0)
            
        elif session.final_action == 'rage_quit':
            score += self.penalties['rage_quit']
            
        # 2. Engagement Reward (Conversational Depth)
        # Nagradzamy dialog, ale do pewnego stopnia (zbyt długi = frustracja?)
        if session.total_messages < 2:
            score += self.penalties['low_engagement']
        else:
            # Logarytmiczny wzrost nagrody za wiadomości, żeby nie spamować
            # 2 msgs -> ~1.4, 10 msgs -> ~4.6, 20 msgs -> ~6.0 * waga
            engagement_score = math.log(session.total_messages) * self.weights['message_engagement'] * 5
            score += min(engagement_score, 40.0) # Cap na 40 pkt
            
        # 3. Duration Sweet Spot (Golden Zone)
        # Zakładamy, że dobra interakcja trwa między 60s a 300s (1-5 min)
        if 45 <= session.duration_seconds <= 400:
            score += self.weights['duration_sweet_spot']
        elif session.duration_seconds < 15 and session.total_messages < 2:
            # Bounce
            score -= 5.0
            
        # 4. "Vogal Shift" (Strategiczny pivot intencji)
        # Jeśli wykryliśmy, że user przeszedł z "pytam" na "kupuję" (nawet bez zakupu)
        if session.intent_shift_detected:
            score += self.weights['vogal_shift']
            
        # Normalizacja wyniku (-1.0 do 1.0 dla ML, tutaj zostawiamy raw score dla czytelności)
        # Możemy zaokrąglić do 2 miejsc po przecinku
        return round(score, 2)

    def analyze_vogal_shift(self, messages: List[dict]) -> bool:
        """
        Prosta heurystyka wykrywania zmiany intencji (Vogal Shift).
        Sprawdza czy w ostatnich wiadomościach pojawiły się słowa kluczowe 'buying intent'.
        To placeholder pod bardziej zaawansowane NLP.
        """
        buying_keywords = ['cena', 'koszt', 'kupić', 'zamówić', 'dostawa', 'płatność', 'faktura', 'dostępność']
        
        # Sprawdzamy tylko wiadomości użytkownika z drugiej połowy konwersacji
        if not messages:
            return False
            
        mid_point = len(messages) // 2
        late_messages = messages[mid_point:]
        
        for msg in late_messages:
            if msg.get('role') == 'user':
                content = msg.get('content', '').lower()
                if any(keyword in content for keyword in buying_keywords):
                    return True
                    
        return False


# ========================================
# 🚀 LDI REWARD SIGNAL (P3 - NEW!)
# Optimized for PRODUCT SEARCH, not chatbot
# ========================================

@dataclass
class LDISession:
    """
    [P3] Sesja LDI - śledzi ścieżkę od query do konwersji.
    KLUCZOWE: To nie jest chatbot, to wyszukiwarka produktów!
    """
    session_id: str
    
    # === QUERY LAYER ===
    original_query: str
    confidence_level: str  # HIGH/MEDIUM/LOW/NO_MATCH
    was_lost_demand: bool = False
    
    # === BEHAVIORAL LAYER ===
    clicked_alternative: bool = False  # Czy kliknął w zaproponowany produkt?
    query_refinement_count: int = 0    # Ile razy zmieniał query? (>3 = frustracja)
    time_to_first_click: float = 0.0   # Sekundy do kliknięcia
    session_duration: float = 0.0      # Całkowity czas sesji
    bounce: bool = False               # <5s bez akcji
    
    # === CONVERSION LAYER ===
    added_to_cart: bool = False
    purchased: bool = False
    cart_value: float = 0.0


class LDIRewardCalculator:
    """
    [P3] Reward Signal dla Lost Demand Intelligence.
    
    CEL: Nagradzaj DOPASOWANIE, nie clickbait.
    
    KLUCZOWE SYGNAŁY:
    1. clicked_despite_no_match - ZŁOTO! User szukał X, kliknął Y, nauczyliśmy się
    2. query_refinement_count - >3 zmiany = frustracja = KARA
    3. bounce - <5s bez akcji = instant penalty
    4. time_to_first_click - <10s = szybkie dopasowanie = BONUS
    """
    
    def __init__(self):
        self.weights = {
            # MATCH QUALITY
            'high_confidence_match': 10.0,
            'clicked_despite_no_match': 15.0,  # 🏆 GOLD SIGNAL
            
            # BEHAVIORAL QUALITY
            'clicked_alternative': 20.0,
            'quick_click_bonus': 10.0,  # <10s to click
            
            # CONVERSION
            'cart_add': 35.0,
            'purchase': 50.0,
            'cart_value_multiplier': 0.4,  # Per 100 PLN, cap at 20
        }
        
        self.penalties = {
            'bounce': -100.0,  # Instant normalization to -1.0
            'multiple_refinements': -15.0,  # >=3 query changes
            'long_session_no_action': -10.0,  # >3min without click
        }
        
        logger.info("[LDI] LDIRewardCalculator initialized (P3)")
    
    def calculate_reward(self, session: LDISession) -> float:
        """
        Oblicza Reward Score dla sesji LDI.
        Zwraca float znormalizowany do zakresu [-1.0, +1.0].
        """
        # ========================================
        # ANTI-BAIT: Bounce = instant penalty
        # ========================================
        if session.bounce:
            logger.debug(f"[LDI] Session {session.session_id}: BOUNCE detected -> -1.0")
            return -1.0
        
        score = 0.0
        
        # ========================================
        # 1. MATCH QUALITY REWARD
        # ========================================
        if session.confidence_level == 'HIGH':
            score += self.weights['high_confidence_match']
            logger.debug(f"[LDI] HIGH confidence: +{self.weights['high_confidence_match']}")
            
        elif session.confidence_level == 'NO_MATCH' and session.clicked_alternative:
            # 🏆 GOLD SIGNAL: User szukał X, kliknął Y = nauczyliśmy się!
            score += self.weights['clicked_despite_no_match']
            logger.debug(f"[LDI] GOLD: clicked_despite_no_match +{self.weights['clicked_despite_no_match']}")
        
        # ========================================
        # 2. BEHAVIORAL QUALITY
        # ========================================
        if session.clicked_alternative:
            score += self.weights['clicked_alternative']
            
            # Bonus za szybkie kliknięcie (dopasowanie było trafne)
            if session.time_to_first_click > 0 and session.time_to_first_click < 10:
                score += self.weights['quick_click_bonus']
                logger.debug(f"[LDI] QUICK CLICK: +{self.weights['quick_click_bonus']}")
        
        # ========================================
        # 3. ANTI-BAIT: Query refinement penalty
        # ========================================
        if session.query_refinement_count >= 3:
            score += self.penalties['multiple_refinements']
            logger.debug(f"[LDI] FRUSTRATION: {session.query_refinement_count} refinements -> penalty")
        
        # ========================================
        # 4. ANTI-BAIT: Long session without action
        # ========================================
        if session.session_duration > 180 and not session.clicked_alternative:
            score += self.penalties['long_session_no_action']
            logger.debug(f"[LDI] LONG SESSION NO ACTION: penalty applied")
        
        # ========================================
        # 5. CONVERSION
        # ========================================
        if session.added_to_cart:
            score += self.weights['cart_add']
            # Bonus za wartość koszyka (cap at 20)
            cart_bonus = min(session.cart_value * self.weights['cart_value_multiplier'] / 100, 20.0)
            score += cart_bonus
            logger.debug(f"[LDI] CART ADD: +{self.weights['cart_add']} + {cart_bonus:.2f} (value bonus)")
            
        if session.purchased:
            score += self.weights['purchase']
            logger.debug(f"[LDI] PURCHASE: +{self.weights['purchase']}")
        
        # ========================================
        # NORMALIZE to [-1.0, 1.0]
        # ========================================
        normalized = max(-1.0, min(1.0, score / 100.0))
        
        logger.info(f"[LDI] Session {session.session_id}: raw={score:.2f}, normalized={normalized:.2f}")
        return round(normalized, 4)
    
    def calculate_from_dict(self, data: dict) -> float:
        """
        Convenience method: oblicza reward z dict (np. z API request).
        """
        session = LDISession(
            session_id=data.get('session_id', 'unknown'),
            original_query=data.get('original_query', ''),
            confidence_level=data.get('confidence_level', 'LOW'),
            was_lost_demand=data.get('was_lost_demand', False),
            clicked_alternative=data.get('clicked_alternative', False),
            query_refinement_count=data.get('query_refinement_count', 0),
            time_to_first_click=data.get('time_to_first_click', 0.0),
            session_duration=data.get('session_duration', 0.0),
            bounce=data.get('bounce', False),
            added_to_cart=data.get('added_to_cart', False),
            purchased=data.get('purchased', False),
            cart_value=data.get('cart_value', 0.0),
        )
        return self.calculate_reward(session)

    @staticmethod
    def score_for_export(confidence_level: str, clicked_alternative: bool, stored_score: float = 0.0) -> float:
        """
        Score used in JSONL training data export.

        NO_MATCH + clicked  → 0.8  (Gold Signal: user searched X, clicked Y)
        NO_MATCH no click   → 0.0
        HIGH/MEDIUM + click → 0.1  (match was good, user confirmed)
        Everything else     → stored_score (from DB, calculated at query time)
        """
        if confidence_level == 'NO_MATCH':
            return 0.8 if clicked_alternative else 0.0
        if confidence_level in ('HIGH', 'MEDIUM') and clicked_alternative:
            return 0.1
        return stored_score if stored_score is not None else 0.0
