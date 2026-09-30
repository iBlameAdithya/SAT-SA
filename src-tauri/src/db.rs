use rusqlite::{Connection, Result};

pub fn init_db(db_path: &str) -> Result<Connection> {
    let conn = Connection::open(db_path)?;

    // Configure connection pragmas for performance and concurrency
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS entities (
            entity_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            sector TEXT NOT NULL,
            total_assets INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            entity_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            subnet TEXT,
            rule_name TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            raw_payload TEXT
        );

        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            alert_id TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            investigator_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            closed_at TEXT,
            duration_seconds REAL,
            status TEXT NOT NULL,
            escalated INTEGER DEFAULT 0,
            escalated_at TEXT,
            resolution_notes TEXT,
            disposition TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            entity_id TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            rule_code TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL DEFAULT 1.0,
            description TEXT NOT NULL,
            explainability_notes TEXT,
            supporting_evidence TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS risk_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_id TEXT NOT NULL,
            execution_gap_score REAL DEFAULT 0.0,
            negative_space_score REAL DEFAULT 0.0,
            composite_risk_score REAL DEFAULT 0.0,
            risk_level TEXT NOT NULL,
            z_score_overall REAL DEFAULT 0.0,
            breakdown_json TEXT,
            assessed_at TEXT NOT NULL
        );
        ",
    )?;

    // Safe schema migrations for existing local databases
    let _ = conn.execute("ALTER TABLE alerts ADD COLUMN mitre_tactic TEXT", []);
    let _ = conn.execute("ALTER TABLE alerts ADD COLUMN mitre_technique TEXT", []);
    let _ = conn.execute("ALTER TABLE cases ADD COLUMN escalated_at TEXT", []);

    Ok(conn)
}
