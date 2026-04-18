# POSTGRESQL MIGRATION PLAN
## SQLite → PostgreSQL: Why, When, How
**Date:** 2026-02-05

---

## 1. WHY MIGRATE (Concrete Reasons)

### Showstoppers with Current SQLite
| Problem | Impact | Severity |
|---------|--------|----------|
| Data loss on Render redeploy | All training data, users, companies lost | CRITICAL |
| Single-writer limitation | Only one process can write at a time | HIGH |
| No concurrent connections | WebSocket + HTTP requests block each other | HIGH |
| File-based = no cloud sync | Cannot scale to multiple instances | HIGH |
| No proper backups | No point-in-time recovery | HIGH |
| No user-level access control | Anyone with file access sees everything | MEDIUM |
| Limited query optimization | No query planner, no parallel queries | MEDIUM |

### What PostgreSQL Gives You
- **Persistence:** Data survives deploys, managed by Render/Supabase/Neon
- **Concurrency:** Hundreds of concurrent connections
- **Backups:** Automated daily backups with point-in-time recovery
- **Scalability:** Connection pooling, read replicas, horizontal scaling
- **Enterprise credibility:** Every acqui-hire pitch expects PostgreSQL
- **Advanced queries:** Full-text search, JSON columns, window functions
- **Free tier options:** Neon (free), Supabase (free), Render PostgreSQL (free 90 days)

### For Acqui-hire Pitch
"SQLite in production" is a red flag for any engineering team evaluating your system. PostgreSQL is table stakes for enterprise credibility.

---

## 2. WHEN TO MIGRATE

### Recommended Timeline
```
Week 1: Setup PostgreSQL instance + Schema migration script
Week 2: Update all Python code (connection strings, queries)
Week 3: Data migration + Testing
Week 4: Deploy to Render with PostgreSQL + Verification
```

**Migrate BEFORE any acqui-hire pitch.** This is a P0 prerequisite.

---

## 3. HOW TO MIGRATE (Step-by-Step)

### Step 1: Choose PostgreSQL Provider

**Recommended: Neon (Free Tier)**
- Free: 0.5 GB storage, 1 project
- Connection pooling built-in
- Serverless (scales to zero)
- Branching for dev/prod
- URL: neon.tech

**Alternative: Render PostgreSQL**
- Free 90 days, then $7/month
- Same platform as app hosting
- Internal networking (faster)

**Alternative: Supabase**
- Free: 500 MB, 2 projects
- Built-in REST API
- Good dashboard

### Step 2: Schema Migration Script

```python
# migrate_to_postgres.py

import psycopg2
import sqlite3
import os

POSTGRES_URL = os.getenv('DATABASE_URL')
SQLITE_PATH = 'dashboard.db'

def create_postgres_schema(pg_conn):
    """Create all tables in PostgreSQL"""
    cursor = pg_conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) NOT NULL UNIQUE,
            email VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            salt VARCHAR(64) DEFAULT '',
            role VARCHAR(20) NOT NULL DEFAULT 'client'
                CHECK (role IN ('client', 'admin', 'debug')),
            client_id INTEGER,
            last_login TIMESTAMP,
            login_count INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER
        )
    ''')

    # Clients table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            id SERIAL PRIMARY KEY,
            company_name VARCHAR(255) NOT NULL UNIQUE,
            api_key VARCHAR(64) UNIQUE,
            domain VARCHAR(255),
            subscription_tier VARCHAR(50) DEFAULT 'basic',
            contact_email VARCHAR(255),
            monthly_query_limit INTEGER DEFAULT 10000,
            current_month_queries INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE
        )
    ''')

    # Events table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            query_text TEXT NOT NULL,
            decision VARCHAR(50) NOT NULL,
            details TEXT,
            category VARCHAR(100),
            brand_type VARCHAR(50),
            potential_value INTEGER,
            explanation TEXT
        )
    ''')

    # Visitor sessions (GDPR compliant)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS visitor_sessions (
            id SERIAL PRIMARY KEY,
            session_id VARCHAR(64) UNIQUE NOT NULL,
            ip_hash VARCHAR(64),
            ip_masked VARCHAR(50),
            user_agent TEXT,
            referrer TEXT,
            page_url TEXT,
            entry_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            exit_time TIMESTAMP,
            last_activity TIMESTAMP,
            session_duration REAL,
            country VARCHAR(100),
            country_code VARCHAR(10),
            city VARCHAR(100),
            region VARCHAR(100),
            timezone VARCHAR(100),
            organization VARCHAR(255),
            isp VARCHAR(255),
            asn VARCHAR(50),
            total_messages INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT TRUE,
            radar_status VARCHAR(50) DEFAULT 'Przegląda',
            radar_company VARCHAR(255),
            anonymous_mode BOOLEAN DEFAULT FALSE
        )
    ''')

    # Query intents (P3 training data)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS query_intents (
            id SERIAL PRIMARY KEY,
            session_id VARCHAR(64) NOT NULL,
            query_text TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            confidence_level VARCHAR(20),
            suggestion_type VARCHAR(50),
            best_match_score INTEGER,
            clicked_alternative BOOLEAN DEFAULT FALSE,
            query_refinement_count INTEGER DEFAULT 0,
            time_to_first_click REAL,
            session_duration REAL,
            bounce BOOLEAN DEFAULT FALSE,
            added_to_cart BOOLEAN DEFAULT FALSE,
            purchased BOOLEAN DEFAULT FALSE,
            cart_value REAL DEFAULT 0.0,
            reward_score REAL,
            missing_attributes JSONB,
            matched_product_id VARCHAR(20)
        )
    ''')

    # Admin dashboard state
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_dashboard_state (
            id SERIAL PRIMARY KEY,
            state_key VARCHAR(100) UNIQUE NOT NULL,
            state_data JSONB NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Companies (persistent)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS companies (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            city VARCHAR(100),
            country VARCHAR(100),
            first_visit TIMESTAMP,
            last_visit TIMESTAMP,
            total_queries INTEGER DEFAULT 0,
            high_intent_queries INTEGER DEFAULT 0,
            lost_opportunities INTEGER DEFAULT 0,
            engagement_score INTEGER DEFAULT 0,
            queries_json JSONB DEFAULT '[]'
        )
    ''')

    # Hot leads
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hot_leads (
            id SERIAL PRIMARY KEY,
            company VARCHAR(255),
            query TEXT,
            score INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Log history
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_history (
            id SERIAL PRIMARY KEY,
            log_type VARCHAR(100),
            company VARCHAR(255),
            query TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_vs_session ON visitor_sessions(session_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_vs_entry ON visitor_sessions(entry_time)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_qi_session ON query_intents(session_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_qi_timestamp ON query_intents(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_qi_reward ON query_intents(reward_score)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_companies_name ON companies(name)')

    pg_conn.commit()
    print("[MIGRATE] PostgreSQL schema created")


def migrate_data(sqlite_path, pg_conn):
    """Copy all data from SQLite to PostgreSQL"""
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row

    tables = ['users', 'clients', 'events', 'visitor_sessions',
              'admin_dashboard_state', 'companies', 'hot_leads',
              'log_history', 'query_intents']

    for table in tables:
        try:
            sqlite_cursor = sqlite_conn.cursor()
            sqlite_cursor.execute(f'SELECT * FROM {table}')
            rows = sqlite_cursor.fetchall()

            if not rows:
                print(f"[MIGRATE] {table}: 0 rows (empty)")
                continue

            columns = [desc[0] for desc in sqlite_cursor.description]
            # Skip 'id' column (auto-generated in PostgreSQL)
            cols_no_id = [c for c in columns if c != 'id']
            placeholders = ', '.join(['%s'] * len(cols_no_id))
            col_names = ', '.join(cols_no_id)

            pg_cursor = pg_conn.cursor()
            for row in rows:
                row_dict = dict(row)
                values = [row_dict[c] for c in cols_no_id]
                pg_cursor.execute(
                    f'INSERT INTO {table} ({col_names}) VALUES ({placeholders}) ON CONFLICT DO NOTHING',
                    values
                )

            pg_conn.commit()
            print(f"[MIGRATE] {table}: {len(rows)} rows migrated")

        except Exception as e:
            print(f"[MIGRATE] {table}: ERROR - {e}")
            pg_conn.rollback()

    sqlite_conn.close()
    print("[MIGRATE] Data migration complete")


if __name__ == '__main__':
    pg_conn = psycopg2.connect(POSTGRES_URL)
    create_postgres_schema(pg_conn)
    migrate_data(SQLITE_PATH, pg_conn)
    pg_conn.close()
    print("[MIGRATE] Done!")
```

### Step 3: Update Python Code

**Key changes needed:**

1. **Replace all `sqlite3.connect('dashboard.db')` with connection pool:**
```python
# app/models/database.py
import psycopg2
from psycopg2 import pool
import os

DATABASE_URL = os.getenv('DATABASE_URL')

# Connection pool (min 2, max 20 connections)
connection_pool = psycopg2.pool.ThreadedConnectionPool(
    2, 20, DATABASE_URL
)

def get_db():
    """Get connection from pool"""
    return connection_pool.getconn()

def release_db(conn):
    """Return connection to pool"""
    connection_pool.putconn(conn)
```

2. **Replace `?` placeholders with `%s`:**
```python
# SQLite:  cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
# PostgreSQL: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
```

3. **Replace SQLite-specific functions:**
```python
# SQLite:  datetime('now', '-5 seconds')
# PostgreSQL: NOW() - INTERVAL '5 seconds'

# SQLite:  strftime('%s', timestamp)
# PostgreSQL: EXTRACT(EPOCH FROM timestamp)

# SQLite:  date(timestamp)
# PostgreSQL: DATE(timestamp)

# SQLite:  julianday('now') - julianday(entry_time)
# PostgreSQL: EXTRACT(EPOCH FROM (NOW() - entry_time))
```

4. **Replace INSERT OR IGNORE with ON CONFLICT:**
```python
# SQLite:  INSERT OR IGNORE INTO ...
# PostgreSQL: INSERT INTO ... ON CONFLICT DO NOTHING
```

5. **Update boolean handling:**
```python
# SQLite uses 0/1 for booleans
# PostgreSQL uses TRUE/FALSE (already compatible via psycopg2)
```

### Step 4: Update requirements.txt
```
# Add:
psycopg2-binary
# Remove (after migration):
# (keep sqlite3 as fallback for local dev)
```

### Step 5: Update Render Environment
```
# Add environment variable in Render dashboard:
DATABASE_URL=postgresql://user:pass@host:5432/dbname
```

### Step 6: Deploy and Verify
1. Push code with PostgreSQL support
2. Run migration script once: `python migrate_to_postgres.py`
3. Verify all endpoints work
4. Monitor for SQL syntax issues
5. Remove SQLite fallback after 1 week of stable operation

---

## 4. RISK MITIGATION

| Risk | Mitigation |
|------|------------|
| Data loss during migration | Export SQLite backup before starting |
| SQL syntax differences | Run test suite against PostgreSQL |
| Connection pool exhaustion | Monitor pool metrics, start with max=20 |
| Performance regression | Add query timing logs, compare |
| Rollback needed | Keep SQLite code on a branch |

---

## 5. ROLLBACK PLAN

1. Keep `dashboard.db` file as backup
2. Maintain SQLite connection code on git branch `sqlite-fallback`
3. If PostgreSQL fails: revert to SQLite branch, restore backup
4. Timeline: Keep SQLite fallback available for 2 weeks post-migration

---

## 6. ESTIMATED EFFORT

| Task | Hours | Difficulty |
|------|-------|------------|
| Setup PostgreSQL instance | 1h | Easy |
| Write migration script | 3h | Medium |
| Update 71 sqlite3.connect calls | 4h | Tedious |
| Fix SQL syntax differences | 3h | Medium |
| Testing all endpoints | 4h | Medium |
| Deploy and verify | 2h | Easy |
| **Total** | **~17h** | **Medium** |
