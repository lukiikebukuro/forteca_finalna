"""
Tests for P3 Reward Engine (LDIRewardCalculator).
Tests reward signal calculation for product search interactions.
"""
import pytest


class TestLDIRewardCalculator:
    """Test suite for LDIRewardCalculator."""

    def test_high_confidence_positive_reward(self, ldi_reward_calc):
        """HIGH confidence match should give positive reward."""
        data = {
            'session_id': 'test_001',
            'original_query': 'iPhone 15 Pro',
            'confidence_level': 'HIGH',
            'clicked_alternative': False,
            'bounce': False,
        }
        reward = ldi_reward_calc.calculate_from_dict(data)
        assert reward > 0, "HIGH confidence should have positive reward"
        assert reward == 0.1, f"Expected 0.1 for HIGH only, got {reward}"

    def test_clicked_alternative_bonus(self, ldi_reward_calc):
        """Clicking an alternative product should add bonus."""
        data = {
            'session_id': 'test_002',
            'original_query': 'Samsung Galaxy',
            'confidence_level': 'MEDIUM',
            'clicked_alternative': True,
            'time_to_first_click': 15.0,
            'bounce': False,
        }
        reward = ldi_reward_calc.calculate_from_dict(data)
        assert reward > 0.1, "Clicked alternative should add significant bonus"

    def test_quick_click_bonus(self, ldi_reward_calc):
        """Quick click (<10s) should give extra bonus."""
        data_quick = {
            'session_id': 'test_003a',
            'confidence_level': 'HIGH',
            'clicked_alternative': True,
            'time_to_first_click': 5.0,
            'bounce': False,
        }
        data_slow = {
            'session_id': 'test_003b',
            'confidence_level': 'HIGH',
            'clicked_alternative': True,
            'time_to_first_click': 20.0,
            'bounce': False,
        }
        reward_quick = ldi_reward_calc.calculate_from_dict(data_quick)
        reward_slow = ldi_reward_calc.calculate_from_dict(data_slow)
        assert reward_quick > reward_slow, "Quick click should give higher reward"

    def test_bounce_penalty(self, ldi_reward_calc):
        """Bounce should give -1.0 reward (worst case)."""
        data = {
            'session_id': 'test_004',
            'original_query': 'random gibberish',
            'confidence_level': 'LOW',
            'bounce': True,
        }
        reward = ldi_reward_calc.calculate_from_dict(data)
        assert reward == -1.0, "Bounce should give -1.0"

    def test_gold_signal_clicked_despite_no_match(self, ldi_reward_calc):
        """GOLD SIGNAL: clicking despite NO_MATCH should be highly rewarded."""
        data = {
            'session_id': 'test_005',
            'original_query': 'OnePlus 12',
            'confidence_level': 'NO_MATCH',
            'clicked_alternative': True,
            'time_to_first_click': 8.0,
            'bounce': False,
        }
        reward = ldi_reward_calc.calculate_from_dict(data)
        assert reward > 0.3, f"Gold signal should have high reward, got {reward}"

    def test_multiple_refinements_penalty(self, ldi_reward_calc):
        """>=3 query refinements indicates frustration, should penalize."""
        data = {
            'session_id': 'test_006',
            'confidence_level': 'MEDIUM',
            'query_refinement_count': 5,
            'bounce': False,
        }
        reward = ldi_reward_calc.calculate_from_dict(data)
        # Should have penalty applied
        assert reward < 0, "Multiple refinements should result in negative reward"

    def test_cart_add_bonus(self, ldi_reward_calc):
        """Adding to cart should give significant bonus."""
        data = {
            'session_id': 'test_007',
            'confidence_level': 'HIGH',
            'clicked_alternative': True,
            'added_to_cart': True,
            'cart_value': 500.0,
            'bounce': False,
        }
        reward = ldi_reward_calc.calculate_from_dict(data)
        assert reward > 0.5, f"Cart add should give high reward, got {reward}"

    def test_purchase_highest_reward(self, ldi_reward_calc):
        """Purchase should give highest reward."""
        data = {
            'session_id': 'test_008',
            'confidence_level': 'HIGH',
            'clicked_alternative': True,
            'added_to_cart': True,
            'purchased': True,
            'cart_value': 1000.0,
            'bounce': False,
        }
        reward = ldi_reward_calc.calculate_from_dict(data)
        assert reward > 0.8, f"Purchase should give very high reward, got {reward}"

    def test_reward_normalized_range(self, ldi_reward_calc):
        """All rewards should be in range [-1.0, 1.0]."""
        test_cases = [
            {'bounce': True},
            {'confidence_level': 'HIGH', 'clicked_alternative': True, 'purchased': True, 'cart_value': 10000},
            {'confidence_level': 'NO_MATCH', 'query_refinement_count': 10},
            {'confidence_level': 'LOW'},
        ]
        for data in test_cases:
            data.setdefault('session_id', 'test_range')
            data.setdefault('bounce', False)
            reward = ldi_reward_calc.calculate_from_dict(data)
            assert -1.0 <= reward <= 1.0, f"Reward {reward} out of range for {data}"

    def test_long_session_no_action_penalty(self, ldi_reward_calc):
        """Long session (>3min) without clicking should be penalized."""
        data = {
            'session_id': 'test_009',
            'confidence_level': 'MEDIUM',
            'clicked_alternative': False,
            'session_duration': 300.0,  # 5 minutes
            'bounce': False,
        }
        reward = ldi_reward_calc.calculate_from_dict(data)
        assert reward < 0, "Long session without action should be penalized"


class TestSemanticValidator:
    """Test suite for SemanticValidator (AI_READY data quality)."""

    @pytest.fixture
    def validator(self):
        from reward_engine import semantic_validator
        return semantic_validator

    def test_rejects_keyboard_patterns(self, validator):
        """Should reject keyboard patterns (asdfgh, qwerty)."""
        is_valid, reason = validator.validate("asdfgh", "NO_MATCH")
        assert not is_valid
        assert reason == "KEYBOARD_PATTERN"

        is_valid, reason = validator.validate("qwerty", "NO_MATCH")
        assert not is_valid

    def test_rejects_too_short(self, validator):
        """Should reject queries shorter than 3 characters."""
        is_valid, reason = validator.validate("ko", "HIGH")
        assert not is_valid
        assert reason == "TOO_SHORT"

    def test_rejects_unrealistic_models(self, validator):
        """Should reject unrealistic product models (iPhone 30, Galaxy S99)."""
        is_valid, reason = validator.validate("iphone 30", "HIGH")
        assert not is_valid
        assert "UNREALISTIC_MODEL" in reason

        is_valid, reason = validator.validate("galaxy s99", "HIGH")
        assert not is_valid
        assert "UNREALISTIC_MODEL" in reason

    def test_rejects_food_domain(self, validator):
        """Should reject food-related queries (wrong domain)."""
        is_valid, reason = validator.validate("pizza", "NO_MATCH")
        assert not is_valid
        assert "FOOD_DOMAIN" in reason

    def test_rejects_nonsense_words(self, validator):
        """Should reject known nonsense/test words."""
        is_valid, reason = validator.validate("test", "NO_MATCH")
        assert not is_valid
        assert reason == "NONSENSE_WORD"

    def test_accepts_valid_automotive(self, validator):
        """Should accept valid automotive queries."""
        is_valid, reason = validator.validate("klocki hamulcowe bmw", "HIGH")
        assert is_valid
        assert reason == "OK"

    def test_accepts_valid_electronics(self, validator):
        """Should accept valid electronics queries."""
        is_valid, reason = validator.validate("iphone 15 pro", "HIGH")
        assert is_valid
        assert reason == "OK"

    def test_accepts_valid_lost_demand(self, validator):
        """Should accept Lost Demand with domain context."""
        is_valid, reason = validator.validate("OnePlus 12", "NO_MATCH")
        assert is_valid
        assert reason == "VALID_LOST_DEMAND"

    def test_rejects_no_match_no_context(self, validator):
        """Should reject NO_MATCH without domain context."""
        is_valid, reason = validator.validate("xyzabc123", "NO_MATCH")
        assert not is_valid
        assert reason == "NO_MATCH_NO_CONTEXT"

    def test_ai_ready_flag_method(self, validator):
        """get_ai_ready_flag should return boolean."""
        assert validator.get_ai_ready_flag("iphone 15", "HIGH") is True
        assert validator.get_ai_ready_flag("asdfgh", "NO_MATCH") is False
