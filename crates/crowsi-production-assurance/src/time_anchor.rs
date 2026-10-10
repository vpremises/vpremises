use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::{AssuranceError, secure_path};

const DDL: &str = "CREATE TABLE IF NOT EXISTS trusted_clock_watermark(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  epoch_s INTEGER NOT NULL CHECK(epoch_s>=0)
) STRICT;";

pub(crate) struct DurableTimeAnchor {
    connection: Connection,
}

impl DurableTimeAnchor {
    pub(crate) fn open(path: &Path) -> Result<Self, AssuranceError> {
        let existed = secure_path::prepare_file(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_EXRESCODE;
        let connection = Connection::open_with_flags(path, flags)
            .map_err(|_| AssuranceError::StateUnavailable)?;
        if existed && !version_matches(&connection) {
            return Err(AssuranceError::StateUnavailable);
        }
        connection
            .execute_batch(&format!(
                "PRAGMA trusted_schema=OFF;
                 PRAGMA application_id=1129466705;
                 PRAGMA user_version=1;
                 {DDL}"
            ))
            .map_err(|_| AssuranceError::StateUnavailable)?;
        if !schema_matches(&connection) {
            return Err(AssuranceError::StateUnavailable);
        }
        Ok(Self { connection })
    }

    pub(crate) fn observe(&mut self, now: u64) -> Result<(), AssuranceError> {
        let now = i64::try_from(now).map_err(|_| AssuranceError::StateUnavailable)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AssuranceError::StateUnavailable)?;
        let previous = transaction
            .query_row(
                "SELECT epoch_s FROM trusted_clock_watermark WHERE singleton=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| AssuranceError::StateUnavailable)?;
        if previous.is_some_and(|value| now < value) {
            return Err(AssuranceError::StateUnavailable);
        }
        transaction
            .execute(
                "INSERT INTO trusted_clock_watermark(singleton, epoch_s) VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET epoch_s=excluded.epoch_s",
                [now],
            )
            .map_err(|_| AssuranceError::StateUnavailable)?;
        transaction
            .commit()
            .map_err(|_| AssuranceError::StateUnavailable)
    }
}

fn version_matches(connection: &Connection) -> bool {
    let application: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .unwrap_or_default();
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap_or_default();
    application == 1_129_466_705 && version == 1
}

fn schema_matches(connection: &Connection) -> bool {
    let unexpected: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name NOT IN ('trusted_clock_watermark')",
            [],
            |row| row.get(0),
        )
        .unwrap_or(1);
    let sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type='table' AND name='trusted_clock_watermark'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_default();
    unexpected == 0 && normalized(&sql) == normalized(&DDL.replace(" IF NOT EXISTS", ""))
}

fn normalized(value: &str) -> String {
    value
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests;
