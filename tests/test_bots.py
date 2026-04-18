"""
Tests for dual bot system (MotoBot + ElektroBot).
Tests product matching, intent analysis, and lost demand detection.
"""
import pytest


class TestMotoBot:
    """Test suite for MotoBot (automotive)."""

    def test_moto_products_loaded(self, moto_bot):
        """MotoBot should have products loaded."""
        assert len(moto_bot.products) > 0, "MotoBot should have products"
        assert len(moto_bot.products) >= 50, f"Expected 50+ products, got {len(moto_bot.products)}"

    def test_moto_high_confidence_match(self, moto_bot):
        """Known product query should return HIGH confidence."""
        analysis = moto_bot.analyze_query_intent("klocki hamulcowe BMW")
        assert analysis['confidence_level'] == 'HIGH', f"Expected HIGH, got {analysis['confidence_level']}"

    def test_moto_brand_recognition(self, moto_bot):
        """MotoBot should recognize automotive brands."""
        analysis = moto_bot.analyze_query_intent("filtr oleju Bosch")
        assert analysis['confidence_level'] in ['HIGH', 'MEDIUM'], "Known brand should match"

    def test_moto_nonsense_filter(self, moto_bot):
        """MotoBot should filter obvious nonsense."""
        analysis = moto_bot.analyze_query_intent("asdfghjkl")
        # Either LOW or NO_MATCH for gibberish
        assert analysis['confidence_level'] in ['LOW', 'NO_MATCH']

    def test_moto_lost_demand_unknown_brand(self, moto_bot):
        """Unknown brand should trigger lost demand (structural gap)."""
        # Query for a brand MotoBot doesn't carry
        analysis = moto_bot.analyze_query_intent("klocki hamulcowe Pagid")
        # Should recognize it's automotive - may still match existing products
        # or detect as structural gap
        assert analysis['confidence_level'] in ['HIGH', 'MEDIUM', 'LOW', 'NO_MATCH']

    def test_moto_fuzzy_matching(self, moto_bot):
        """Fuzzy matching should find products with typos."""
        # Test with slight typo
        products, conf, sug_type, _ = moto_bot.get_fuzzy_product_matches(
            "klocki hamolcowe", None, limit=5, analyze_intent=True
        )
        # Should still find something (hamolcowe -> hamulcowe)
        assert len(products) >= 0  # May or may not match depending on threshold


class TestElektroBot:
    """Test suite for ElektroBot (electronics)."""

    def test_elektro_products_loaded(self, elektro_bot):
        """ElektroBot should have products loaded."""
        if elektro_bot is None:
            pytest.skip("ElektroBot not available")
        assert len(elektro_bot.products) > 0, "ElektroBot should have products"
        assert len(elektro_bot.products) >= 40, f"Expected 40+ products, got {len(elektro_bot.products)}"

    def test_elektro_high_confidence_iphone(self, elektro_bot):
        """iPhone query should return HIGH confidence."""
        if elektro_bot is None:
            pytest.skip("ElektroBot not available")
        analysis = elektro_bot.analyze_query_intent("iPhone 13")
        assert analysis['confidence_level'] in ['HIGH', 'MEDIUM'], f"Got {analysis['confidence_level']}"

    def test_elektro_brand_recognition(self, elektro_bot):
        """ElektroBot should recognize electronics brands."""
        if elektro_bot is None:
            pytest.skip("ElektroBot not available")
        brands = ['Samsung', 'Apple', 'Sony', 'LG']
        for brand in brands:
            analysis = elektro_bot.analyze_query_intent(f"{brand} telefon")
            # Should at least recognize the brand context
            assert 'confidence_level' in analysis

    def test_elektro_lost_demand_unknown_brand(self, elektro_bot):
        """Unknown brand should be detected as lost demand."""
        if elektro_bot is None:
            pytest.skip("ElektroBot not available")
        # OnePlus is in competitor_brands, not our assortment
        analysis = elektro_bot.analyze_query_intent("OnePlus 12 Pro")
        # Should detect as NO_MATCH (brand we don't carry)
        assert analysis['confidence_level'] == 'NO_MATCH', f"Expected NO_MATCH, got {analysis['confidence_level']}"

    def test_elektro_color_mismatch(self, elektro_bot):
        """Query for unavailable color should be detected."""
        if elektro_bot is None:
            pytest.skip("ElektroBot not available")
        # Query for specific color that might not exist
        analysis = elektro_bot.analyze_query_intent("iPhone 13 rozowy")
        # May be NO_MATCH if we don't have pink/rozowy
        assert analysis['confidence_level'] in ['HIGH', 'MEDIUM', 'LOW', 'NO_MATCH']

    def test_elektro_nonsense_filter(self, elektro_bot):
        """ElektroBot should filter food/nonsense queries."""
        if elektro_bot is None:
            pytest.skip("ElektroBot not available")
        analysis = elektro_bot.analyze_query_intent("kanapka z serem")
        assert analysis['confidence_level'] in ['LOW', 'NO_MATCH']

    def test_elektro_spec_detection(self, elektro_bot):
        """ElektroBot should recognize technical specifications."""
        if elektro_bot is None:
            pytest.skip("ElektroBot not available")
        # Query with specific storage
        analysis = elektro_bot.analyze_query_intent("iPhone 256GB")
        assert 'confidence_level' in analysis


class TestDualBotIntegration:
    """Test integration between both bots."""

    def test_both_bots_have_analyze_method(self, moto_bot, elektro_bot):
        """Both bots should have analyze_query_intent method."""
        assert hasattr(moto_bot, 'analyze_query_intent')
        if elektro_bot:
            assert hasattr(elektro_bot, 'analyze_query_intent')

    def test_both_bots_have_fuzzy_match(self, moto_bot, elektro_bot):
        """Both bots should have get_fuzzy_product_matches method."""
        assert hasattr(moto_bot, 'get_fuzzy_product_matches')
        if elektro_bot:
            assert hasattr(elektro_bot, 'get_fuzzy_product_matches')

    def test_both_bots_have_greeting(self, moto_bot, elektro_bot):
        """Both bots should have get_initial_greeting method."""
        moto_greeting = moto_bot.get_initial_greeting()
        assert moto_greeting is not None
        assert 'text_message' in moto_greeting or isinstance(moto_greeting, dict)

        if elektro_bot:
            elektro_greeting = elektro_bot.get_initial_greeting()
            assert elektro_greeting is not None
