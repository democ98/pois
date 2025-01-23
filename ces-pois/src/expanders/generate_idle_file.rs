use std::path;

use super::Expanders;
use crate::tree::{self, LightMHT};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256, Sha512};
use tokio::fs;

pub const DEFAULT_IDLE_FILES_PATH: &str = "./proofs";
pub const FILE_NAME: &str = "sub-file";
pub const COMMIT_FILE: &str = "file-roots";
pub const CLUSTER_DIR_NAME: &str = "file-cluster";
pub const SET_DIR_NAME: &str = "idle-files";
pub const AUX_FILE: &str = "aux-file";
pub const DEFAULT_AUX_SIZE: i64 = 64;
pub const DEFAULT_NODES_CACHE: i64 = 1024;

pub const HASH_SIZE: i32 = 64;

pub enum Hasher {
    SHA256(Sha256),
    SHA512(Sha512),
}

pub async fn make_proof_dir(dir: &str) -> Result<()> {
    if fs::metadata(dir).await.is_err() {
        fs::DirBuilder::new().recursive(true).create(dir).await?;
    } else {
        fs::remove_dir_all(dir).await?;
        fs::DirBuilder::new().recursive(true).create(dir).await?;
    }
    Ok(())
}

pub fn new_hash() -> Hasher {
    match HASH_SIZE {
        32 => Hasher::SHA256(Sha256::new()),
        64 => Hasher::SHA512(Sha512::new()),
        _ => Hasher::SHA512(Sha512::new()),
    }
}

pub fn get_hash(data: &[u8]) -> Vec<u8> {
    let hash = new_hash();
    let mut data = data;
    if data.is_empty() {
        data = b"none";
    }

    match hash {
        Hasher::SHA256(hash) => {
            let mut hash = hash;
            hash.update(data);
            let result = hash.finalize();
            result.to_vec()
        },
        Hasher::SHA512(hash) => {
            let mut hash = hash;
            hash.update(data);
            let result = hash.finalize();
            result.to_vec()
        },
    }
}

impl Expanders {
    pub async fn generate_idle_file_set(
        &mut self,
        miner_id: Vec<u8>,
        start: i64,
        size: i64,
        root_dir: &str,
    ) -> Result<()> {
        let mut clusters = vec![0_i64; size as usize];
        let set_dir = format!("{}/{}-{}", root_dir, SET_DIR_NAME, (start + size) / size);

        for i in start..start + size {
            let dir = format!("{}/{}-{}", set_dir, CLUSTER_DIR_NAME, i);
            make_proof_dir(&dir).await.context("generate idle file error")?;
            clusters[(i - start) as usize] = i;
        }

        // Number of idle files in each file cluster
        let file_num = self.k;
        let mut roots = vec![vec![0, 0]; (self.k + file_num) as usize * size as usize + 1];
        let elders = self.file_pool.clone();
        let parents = self.file_pool.clone();
        let labels = self.file_pool.clone();
        let mht = tree::get_light_mht(self.n);

        Ok(())
    }
}
