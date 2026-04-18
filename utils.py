"""
Helper functions: lost value calculation, category extraction, CSV logging,
PDF report generation, firehose logging.
"""
import os
import csv
import json
import random
import time
from datetime import datetime

from config import app, LOST_DEMAND_LOG


def extract_category_from_query(query):
    """Extract category keyword from query"""
    query_lower = query.lower()
    categories = ['klocki', 'filtry', 'amortyzatory', 'swiece', 'akumulatory', 'oleje', 'tarcze']
    for category in categories:
        if category in query_lower:
            return category
    return 'inne'


def calculate_lost_value_internal(query, source='unknown'):
    """
    Estimate realistic lost demand value based on Polish market prices 2024.
    MOTO: Ferrari/Porsche (2500-9000), Turbo (1500-4000), Oil/Filter (50-200)
    ELEKTRO: RTX 4090/Macbook (8000-22000), iPhone (3500-7500), Cables (50-300)
    """
    query_lower = query.lower()

    # MOTO price ladder
    moto_premium = [
        'ferrari', 'lamborghini', 'porsche', 'bentley', 'maserati', 'aston martin',
        'mclaren', 'bugatti', 'rolls-royce', 'maybach', 'koenigsegg',
        'turbo', 'turbosprezarka', 'skrzynia biegow', 'automatyczna', 'dsg', 'tiptronic',
        'silnik', 'glowica', 'blok silnika', 'wal korbowy', 'tlok'
    ]
    moto_high = [
        'amortyzator', 'amortyzatory', 'zawieszenie', 'sprezyna', 'sprezyny',
        'sprzeglo', 'komplet sprzegla', 'kolo dwumasowe', 'docisk',
        'rozrzad', 'zestaw rozrzadu', 'lancuch rozrzadu', 'pasek rozrzadu',
        'alternator', 'rozrusznik', 'pompa wtryskowa', 'wtryskiwacz',
        'chlodnica', 'intercooler', 'katalizator', 'dpf', 'fap'
    ]
    moto_medium = [
        'klocki', 'tarcze', 'hamulcowe', 'tarcza hamulcowa', 'beben',
        'wahacz', 'drazek', 'stabilizator', 'lozysko', 'piasta', 'przegub',
        'akumulator', 'akumulatory', 'swiece', 'cewka zaplonowa', 'modul zaplonu',
        'pompa wody', 'termostat', 'czujnik', 'sonda lambda'
    ]
    moto_low = [
        'filtr', 'filtry', 'oleju', 'powietrza', 'paliwa', 'kabinowy',
        'olej', 'oleje', 'plyn', 'plyny', 'antyfriz', 'hamulcowy',
        'uszczelka', 'oring', 'simering', 'zarowka', 'bezpiecznik', 'przekaznik'
    ]

    # ELEKTRO price ladder
    elektro_premium = [
        'rtx 4090', 'rtx 4080', 'rtx 5090', 'rtx 5080', 'rtx 4090 ti',
        'macbook pro', 'macbook 16', 'm3 max', 'm3 pro', 'm4 pro', 'm4 max',
        'iphone 15 pro max', 'iphone 16 pro max', 'iphone 16 ultra',
        'oled 77', 'oled 83', 'oled 88', 'neo qled 85', '8k samsung', '8k lg',
        'sony a1', 'sony a7r', 'sony a9', 'leica q3', 'hasselblad'
    ]
    elektro_high = [
        'iphone 14', 'iphone 15', 'iphone 16', 'iphone pro',
        'galaxy s24', 'galaxy s23', 'samsung ultra', 'galaxy z fold', 'galaxy z flip',
        'pixel 8', 'pixel 9', 'pixel pro',
        'macbook air', 'macbook m2', 'macbook m3', 'dell xps', 'thinkpad x1',
        'rtx 4070', 'rtx 4060', 'rtx 3080', 'rtx 3090',
        'ps5', 'playstation 5', 'xbox series x', 'ps5 pro',
        'sony wh-1000', 'airpods max', 'bose 700', 'bose qc ultra'
    ]
    elektro_medium = [
        'laptop', 'notebook', 'komputer', 'desktop', 'all-in-one',
        'telewizor', 'tv', 'smart tv', '55 cali', '65 cali', '50 cali',
        'monitor', 'monitor gaming', '27 cali', '32 cali', '34 cali',
        'tablet', 'ipad', 'ipad air', 'galaxy tab', 'tab s9',
        'sluchawki', 'headphones', 'airpods', 'airpods pro', 'earbuds', 'buds',
        'glosnik', 'soundbar', 'jbl', 'marshall', 'bose soundlink',
        'konsola', 'nintendo switch', 'switch oled', 'xbox series s', 'ps4',
        'aparat', 'canon', 'nikon', 'sony alpha', 'fujifilm'
    ]
    elektro_low = [
        'kabel', 'ladowarka', 'charger', 'powerbank', 'adapter', 'zasilacz',
        'etui', 'case', 'pokrowiec', 'folia', 'szklo', 'hartowane',
        'myszka', 'mysz', 'klawiatura', 'keyboard', 'mata', 'podkladka',
        'pendrive', 'karta pamieci', 'sd card', 'microsd',
        'hub', 'przejsciowka', 'usb', 'usb-c', 'hdmi', 'splitter'
    ]

    # Industry detection
    elektro_indicators = [
        'iphone', 'samsung', 'galaxy', 'macbook', 'laptop', 'rtx', 'nvidia', 'geforce',
        'sluchawki', 'telewizor', 'tv', 'monitor', 'tablet', 'ipad', 'konsola',
        'ps5', 'ps4', 'xbox', 'nintendo', 'switch', 'pixel', 'xiaomi', 'redmi',
        'airpods', 'bluetooth', 'smartwatch', 'apple watch', 'garmin',
        'klawiatura', 'myszka', 'glosnik', 'soundbar', 'projektor'
    ]
    moto_indicators = [
        'klocki', 'filtr', 'olej', 'amortyzator', 'swiece', 'rozrzad', 'sprzeglo',
        'hamulce', 'tarcze', 'zawieszenie', 'wahacz', 'bmw', 'audi', 'mercedes',
        'volkswagen', 'vw', 'toyota', 'ford', 'opel', 'skoda', 'seat', 'renault',
        'ferrari', 'porsche', 'turbo', 'silnik', 'skrzynia', 'akumulator',
        'czujnik', 'lambda', 'katalizator', 'dpf', 'egr'
    ]

    is_elektro = any(kw in query_lower for kw in elektro_indicators)
    is_moto = any(kw in query_lower for kw in moto_indicators)

    # ELEKTRO
    if is_elektro or source == 'elektro':
        if any(kw in query_lower for kw in elektro_premium):
            return random.randint(8000, 22000)
        if any(kw in query_lower for kw in elektro_high):
            return random.randint(3500, 7500)
        if any(kw in query_lower for kw in elektro_medium):
            return random.randint(500, 2000)
        if any(kw in query_lower for kw in elektro_low):
            return random.randint(50, 300)
        return random.randint(800, 2500)

    # MOTO (or unknown - fallback)
    if any(kw in query_lower for kw in moto_premium):
        return random.randint(2500, 9000)
    if any(kw in query_lower for kw in moto_high):
        return random.randint(1500, 4000)
    if any(kw in query_lower for kw in moto_medium):
        return random.randint(300, 1000)
    if any(kw in query_lower for kw in moto_low):
        return random.randint(50, 200)
    return random.randint(300, 800)


def log_lost_demand(query, analysis):
    """Log lost demand to CSV file"""
    from flask import session
    try:
        if not os.path.exists(LOST_DEMAND_LOG) or os.path.getsize(LOST_DEMAND_LOG) == 0:
            with open(LOST_DEMAND_LOG, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['timestamp', 'query', 'email', 'notify', 'machine_filter'])
        with open(LOST_DEMAND_LOG, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([datetime.now().isoformat(), query, '', False, session.get('machine_filter', 'all')])
        print(f"[LOST DEMAND AUTO] Logged: '{query}'")
    except Exception as e:
        print(f"[ERROR] Failed to log lost demand: {e}")


def log_firehose(session_id, event, score, session_data):
    """Log raw training data to JSONL (the 'Oil Well')"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'session_id': session_id,
        'store_id': session_data['store_id'],
        'event': event,
        'reward_score': score,
        'messages_count': len(session_data['messages']),
        'duration': time.time() - session_data['start_time']
    }
    with open('ldi_firehose.jsonl', 'a') as f:
        f.write(json.dumps(log_entry) + '\n')


def generate_pdf_html(data):
    """Generate HTML for weekly PDF report"""
    html = f"""
    <!DOCTYPE html>
    <html lang="pl">
    <head>
        <meta charset="UTF-8">
        <title>Raport Utraconych Okazji - {data['client']['company_name']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
            .header {{ text-align: center; border-bottom: 2px solid #4fc3f7; padding-bottom: 20px; margin-bottom: 30px; }}
            .summary {{ background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 8px; }}
            .products-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            .products-table th, .products-table td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            .products-table th {{ background: #4fc3f7; color: white; }}
            .value {{ color: #ff6b6b; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Centrum Analityczne Utraconych Okazji</h1>
            <h2>Cotygodniowy Raport Zweryfikowany</h2>
            <p><strong>{data['client']['company_name']}</strong> | {data['report_date']}</p>
        </div>
        <div class="summary">
            <h3>Podsumowanie wykonawcze</h3>
            <p><strong>Szacowana utracona marza (tygodniowo):</strong> <span class="value">{data['total_lost_value']:,} zl</span></p>
            <p><strong>Calkowity wolumen popytu brutto:</strong> {data.get('total_volume_gross', 0):,} zl</p>
            <p><strong>Liczba zidentyfikowanych produktow:</strong> {data['total_products']}</p>
            <p><strong>Status:</strong> Zweryfikowany przez Lost Demand Intelligence</p>
        </div>
        <h3>Szczegolowa lista utraconych produktow</h3>
        <table class="products-table">
            <thead><tr><th>Lp.</th><th>Produkt</th><th>Kategoria</th><th>Szacowana wartosc</th><th>Czestotliwosc zapytan</th></tr></thead>
            <tbody>
    """
    for i, product in enumerate(data['lost_products'], 1):
        html += f"<tr><td>{i}</td><td>{product['name']}</td><td>{product['category']}</td><td class='value'>{product['value']} zl</td><td>{product['frequency']}x</td></tr>"

    html += "</tbody></table><div style='margin-top: 40px;'><h3>Rekomendacje implementacji</h3><ol>"
    for rec in data['recommendations']:
        html += f"<li>{rec}</li>"
    html += f"""</ol></div>
        <div style="margin-top: 40px; text-align: center; color: #666; font-size: 12px;">
            <p>Raport wygenerowany przez Centrum Analityczne Utraconych Okazji</p>
            <p>Studio Adept AI | {data['report_date']}</p>
        </div>
    </body></html>"""
    return html
