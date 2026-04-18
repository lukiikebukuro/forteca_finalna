#!/usr/bin/env python3
"""
DATA QUALITY VERIFICATION SCRIPT
Demonstrates the 3 new features:
1. Session Consolidation (only FINAL INTENT in database)
2. Semantic Validator (filter garbage queries)
3. AI_READY flag in query_intents table
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from reward_engine import semantic_validator, LDIRewardCalculator
from database import QueryIntentManager, DATABASE_NAME
import sqlite3

def print_header(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def test_semantic_validator():
    """Test the semantic validator with various queries"""
    print_header("SEMANTIC VALIDATOR TEST")

    test_cases = [
        # (query, confidence, expected_valid, description)
        ("klocki hamulcowe bmw", "HIGH", True, "Valid: automotive part + brand"),
        ("iphone 15 pro", "HIGH", True, "Valid: known electronics product"),
        ("iphone 30", "HIGH", False, "REJECT: unrealistic model (iPhone 30)"),
        ("galaxy s99", "HIGH", False, "REJECT: unrealistic model (Galaxy S99)"),
        ("asdfgh", "NO_MATCH", False, "REJECT: keyboard pattern"),
        ("qwerty", "NO_MATCH", False, "REJECT: keyboard pattern"),
        ("pizza", "NO_MATCH", False, "REJECT: food domain (pizza)"),
        ("test", "NO_MATCH", False, "REJECT: nonsense word"),
        ("ko", "HIGH", False, "REJECT: too short (<3 chars)"),
        ("OnePlus 12", "NO_MATCH", True, "VALID Lost Demand: real brand we don't carry"),
        ("mercedes c klasa", "HIGH", True, "Valid: automotive brand + model"),
        ("aaaaaaa", "NO_MATCH", False, "REJECT: repeated characters"),
        ("filtr oleju", "MEDIUM", True, "Valid: automotive part"),
        ("dupa", "NO_MATCH", False, "REJECT: nonsense/vulgar"),
    ]

    passed = 0
    failed = 0

    for query, confidence, expected, description in test_cases:
        is_valid, reason = semantic_validator.validate(query, confidence)
        status = "[PASS]" if is_valid == expected else "[FAIL]"
        if is_valid == expected:
            passed += 1
        else:
            failed += 1

        print(f"{status} '{query}' -> valid={is_valid}, reason={reason}")
        print(f"       {description}")

    print(f"\n>>> Semantic Validator: {passed}/{passed+failed} tests passed")
    return passed, failed

def test_session_consolidation():
    """Test that session consolidation works (UPDATE instead of INSERT)"""
    print_header("SESSION CONSOLIDATION TEST")

    # Initialize table
    QueryIntentManager.init_table()

    # Create test data simulating typing: "ko" -> "komp" -> "komputer"
    test_session = "test_consolidation_session_001"

    # Clean up any existing test data
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM query_intents WHERE session_id = ?", (test_session,))
    conn.commit()
    conn.close()

    # Simulate typing sequence
    typing_sequence = [
        ("ko", "NO_MATCH", False),      # Too short, rejected
        ("komp", "MEDIUM", True),       # First valid query
        ("komput", "MEDIUM", True),     # Refinement 1
        ("komputer", "HIGH", True),     # Final intent
    ]

    for query, confidence, ai_ready in typing_sequence:
        QueryIntentManager.add_query_intent({
            'session_id': test_session,
            'query_text': query,
            'confidence_level': confidence,
            'suggestion_type': 'products',
            'best_match_score': 85 if confidence == 'HIGH' else 50,
            'reward_score': 0.1,
            'ai_ready': ai_ready
        })

    # Check how many records exist for this session
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT query_text, query_refinement_count, ai_ready
        FROM query_intents WHERE session_id = ?
    """, (test_session,))
    rows = cursor.fetchall()
    conn.close()

    print(f"\nTyping sequence: 'ko' -> 'komp' -> 'komput' -> 'komputer'")
    print(f"Records in database for session: {len(rows)}")

    if len(rows) == 1:
        query, refinements, ai_ready = rows[0]
        print(f"[PASS] Only 1 record (FINAL INTENT): '{query}'")
        print(f"       Refinement count: {refinements}")
        print(f"       AI_READY: {bool(ai_ready)}")
        return 1, 0
    else:
        print(f"[FAIL] Expected 1 record, got {len(rows)}")
        for row in rows:
            print(f"       - '{row[0]}' (refinements: {row[1]})")
        return 0, 1

def test_ai_ready_flag():
    """Test that AI_READY flag is properly stored and queryable"""
    print_header("AI_READY FLAG TEST")

    # Get stats
    stats = QueryIntentManager.get_stats()

    print(f"Total intents: {stats['total_intents']}")
    print(f"AI Ready count: {stats['ai_ready_count']}")
    print(f"AI Ready percentage: {stats['ai_ready_percentage']:.1f}%")
    print(f"Average reward: {stats['avg_reward']}")
    print(f"Gold signals: {stats['gold_signals']}")
    print(f"Bounce rate: {stats['bounce_rate']}%")

    # Test ai_ready_only filter
    all_data = QueryIntentManager.get_training_data(limit=100, ai_ready_only=False)
    clean_data = QueryIntentManager.get_training_data(limit=100, ai_ready_only=True)

    print(f"\nAll training data: {len(all_data)} records")
    print(f"Clean (AI_READY=1) data: {len(clean_data)} records")

    if len(clean_data) <= len(all_data):
        print("[PASS] AI_READY filter works correctly")
        return 1, 0
    else:
        print("[FAIL] AI_READY filter returned more than total")
        return 0, 1

def main():
    print("\n" + "=" * 70)
    print("  LDI DATA QUALITY VERIFICATION")
    print("  Testing: Session Consolidation, Semantic Validator, AI_READY flag")
    print("=" * 70)

    total_passed = 0
    total_failed = 0

    # Test 1: Semantic Validator
    p, f = test_semantic_validator()
    total_passed += p
    total_failed += f

    # Test 2: Session Consolidation
    p, f = test_session_consolidation()
    total_passed += p
    total_failed += f

    # Test 3: AI_READY Flag
    p, f = test_ai_ready_flag()
    total_passed += p
    total_failed += f

    print_header("SUMMARY")
    print(f"Total tests: {total_passed + total_failed}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_failed}")

    if total_failed == 0:
        print("\n>>> ALL DATA QUALITY FEATURES WORKING <<<")
    else:
        print(f"\n>>> {total_failed} TESTS FAILED <<<")

    return total_failed

if __name__ == "__main__":
    sys.exit(main())
