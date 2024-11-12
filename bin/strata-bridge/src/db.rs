use std::{
    env, fs,
    path::{Path, PathBuf},
};

use sqlx::{migrate::Migrator, SqlitePool};
use strata_bridge_db::persistent::sqlite::SqliteDb;

pub async fn create_db(datadir: impl AsRef<Path>, db_name: &str) -> SqliteDb {
    let db_path = create_db_file(datadir, db_name);
    let url = format!("sqlite://{}", db_path.to_string_lossy());

    let pool = SqlitePool::connect(url.as_ref())
        .await
        .expect("should be able to connect to db");

    let current_dir = env::current_dir().expect("should be able to get current working directory");
    let migrations_path = current_dir.join("migrations");

    let migrator = Migrator::new(migrations_path)
        .await
        .expect("should be able to initialize migrator");

    migrator
        .run(&pool)
        .await
        .expect("should be able to run migrations");

    SqliteDb::new(pool)
}

fn create_db_file(datadir: impl AsRef<Path>, db_name: &str) -> PathBuf {
    if !datadir.as_ref().exists() {
        fs::create_dir_all(datadir.as_ref())
            .map_err(|e| {
                panic!(
                    "could not create datadir at {:?} due to {}",
                    datadir.as_ref().canonicalize(),
                    e
                );
            })
            .unwrap();
    }

    let db_path = datadir.as_ref().join(db_name);

    if !db_path.exists() {
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false) // don't overwrite the file
            .open(db_path.as_path())
            .map_err(|e| {
                panic!(
                    "could not create public db at {:?} due to {}",
                    db_path.to_string_lossy(),
                    e
                );
            })
            .unwrap();
    }

    db_path
}
