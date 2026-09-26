use super::Store;
use crate::Result;
use rusqlite::{Connection, Savepoint, Transaction, TransactionBehavior};
use std::ops::Deref;
pub(super) enum WriteTransaction<'a> {
    Transaction(Transaction<'a>),
    Savepoint(Savepoint<'a>),
}
impl<'a> WriteTransaction<'a> {
    pub fn begin(connection: &'a mut Connection) -> Result<Self> {
        if connection.is_autocommit() {
            Ok(Self::Transaction(connection.transaction_with_behavior(
                TransactionBehavior::Immediate,
            )?))
        } else {
            Ok(Self::Savepoint(connection.savepoint()?))
        }
    }
    pub fn commit(self) -> Result<()> {
        match self {
            Self::Transaction(tx) => tx.commit()?,
            Self::Savepoint(tx) => tx.commit()?,
        }
        Ok(())
    }
}
impl Deref for WriteTransaction<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        match self {
            Self::Transaction(tx) => tx,
            Self::Savepoint(tx) => tx,
        }
    }
}
struct Rollback<'a>(&'a mut Store, bool, bool);
impl Drop for Rollback<'_> {
    fn drop(&mut self) {
        if self.2 && !self.0.connection.is_autocommit() {
            let _ = self.0.connection.execute_batch(if self.1 {
                "ROLLBACK TO command; RELEASE command"
            } else {
                "ROLLBACK"
            });
        }
    }
}
impl Store {
    pub(crate) fn atomic<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let nested = !self.connection.is_autocommit();
        self.connection.execute_batch(if nested {
            "SAVEPOINT command"
        } else {
            "BEGIN IMMEDIATE"
        })?;
        let mut guard = Rollback(self, nested, true);
        let value = operation(guard.0)?;
        guard
            .0
            .connection
            .execute_batch(if nested { "RELEASE command" } else { "COMMIT" })?;
        // A released nested savepoint must not roll back its parent.
        guard.2 = false;
        Ok(value)
    }
}
