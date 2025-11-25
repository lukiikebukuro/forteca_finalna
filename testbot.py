# Test czy bot ma wszystkie metody i czy produkty się załadowały

import sys
sys.path.insert(0, 'C:/Users/lpisk/Projects/forteca_finalna1')

from ecommerce_bot import EcommerceBot

print("🔍 Testowanie bota...")
bot = EcommerceBot()

print(f"\n📊 WYNIKI:")
print(f"bot.products: {type(bot.products)}, len={len(bot.products)}")
print(f"bot.product_database: {type(bot.product_database)}")
if bot.product_database:
    print(f"bot.product_database['products']: len={len(bot.product_database.get('products', []))}")

if len(bot.products) > 0:
    print(f"\n✅ Pierwszy produkt: {bot.products[0]}")
else:
    print(f"\n❌ BRAK PRODUKTÓW!")
    print(f"❌ bot.products jest pusty!")
    
print(f"\n📋 Metody bota:")
print(f"  - initialize_data: {hasattr(bot, 'initialize_data')}")
print(f"  - get_fuzzy_product_matches: {hasattr(bot, 'get_fuzzy_product_matches')}")