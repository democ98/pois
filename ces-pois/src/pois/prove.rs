use crate::{
    acc::{
        multi_level_acc::{new_muti_level_acc, recovery, AccHandle, MutiLevelAcc, WitnessNode, DEFAULT_PATH},
        RsaKey,
    },
    expanders::{
        self,
        generate_expanders::construct_stacked_expanders,
        generate_idle_file::{COMMIT_FILE, HASH_SIZE},
    },
    tree::DEFAULT_HASH_SIZE,
    util,
};
use anyhow::{anyhow, bail, Result};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Mutex;
use tokio::{fs, sync::RwLock};

const FILE_SIZE: i64 = HASH_SIZE as i64;

lazy_static! {
    static ref AccPath: Mutex<String> =
        Mutex::new(String::from_str(DEFAULT_PATH).expect("init global acc path failed"));
    static ref ChallAccPath: Mutex<String> =
        Mutex::new(String::from_str("./chall_acc/").expect("init global chall acc failed"));
    static ref IdleFilePath: Mutex<String> = Mutex::new(
        String::from_str(expanders::generate_idle_file::DEFAULT_IDLE_FILES_PATH)
            .expect("init global idle file path failed")
    );
    static ref MaxProofThread: Mutex<i64> = Mutex::new(4);
    static ref MiniFileSize: Mutex<i64> = Mutex::new(1024 * 1024);
}

pub struct Prover<T: AccHandle> {
    pub rw: RwLock<ProverStruct<T>>,
}

pub struct ProverStruct<T: AccHandle> {
    pub expanders: expanders::Expanders,
    pub rear: i64,
    pub front: i64,
    pub space: i64,
    pub set_len: i64,
    pub cluster_size: i64,
    context: Context,
    pub delete: bool,
    pub update: bool,
    pub sync: bool,
    pub generate: bool,
    pub id: Vec<u8>,
    pub chain_state: ChainState<T>,
    pub acc_manager: Option<T>,
}

pub struct Config {
    pub acc_path: String,
    pub chall_acc_path: String,
    pub idle_file_path: String,
    pub max_proof_thread: i64,
}

struct Context {
    pub commited: i64,
    pub added: i64,
    pub generated: i64,
    pub proofed: i64,
}

pub struct ChainState<T: AccHandle> {
    pub acc: Option<T>,
    pub challenging: bool,
    // pub del_ch      :chan struct{},
    pub rear: i64,
    pub front: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MhtProof {
    pub index: expanders::NodeType,
    pub label: Vec<u8>,
    pub paths: Vec<Vec<u8>>,
    pub locs: Vec<u8>,
}

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct Commits {
    pub file_indexs: Vec<i64>,
    pub roots: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommitProof {
    pub node: MhtProof,
    pub parents: Vec<MhtProof>,
    pub elders: Vec<MhtProof>,
}

#[derive(Debug, Default)]
pub struct AccProof {
    pub indexs: Vec<i64>,
    pub labels: Vec<Vec<u8>>,
    pub wit_chains: Option<Box<WitnessNode>>,
    pub acc_path: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SpaceProof {
    pub left: i64,
    pub right: i64,
    pub proofs: Vec<Vec<MhtProof>>,
    pub roots: Vec<Vec<u8>>,
    pub wit_chains: Vec<WitnessNode>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DeletionProof {
    pub roots: Vec<Vec<u8>>,
    pub wit_chain: WitnessNode,
    pub acc_path: Vec<Vec<u8>>,
}

pub async fn new_prover<T: AccHandle>(
    k: i64,
    n: i64,
    d: i64,
    id: Vec<u8>,
    space: i64,
    set_len: i64,
) -> Result<Prover<T>> {
    if k <= 0 || n <= 0 || d <= 0 || space <= 0 || id.len() == 0 {
        return Err(anyhow!("bad params"));
    }

    let prover = ProverStruct {
        expanders: construct_stacked_expanders(k, n, d),
        rear: 0,
        front: 0,
        space,
        set_len,
        cluster_size: k,
        delete: false,
        update: false,
        sync: false,
        generate: false,
        id,
        context: Context { commited: 0, added: 0, generated: 0, proofed: 0 },
        chain_state: ChainState { acc: None, challenging: false, rear: 0, front: 0 },
        acc_manager: None,
    };

    Ok(Prover { rw: RwLock::new(prover) })
}

impl Prover<MutiLevelAcc> {
    pub async fn init(&mut self, key: RsaKey, config: Config) -> Result<()> {
        if key.g.to_bytes_be().len() == 0 || key.n.to_bytes_be().len() == 0 {
            return Err(anyhow!("bad init params"));
        }
        check_config(config);

        let mut prover_guard = self.rw.write().await;

        prover_guard.acc_manager = Some(new_muti_level_acc(AccPath.lock().unwrap().as_str(), key.clone())?);
        let _ = new_muti_level_acc(ChallAccPath.lock().unwrap().as_str(), key)?;
        Ok(())
    }
    pub async fn recovery(&mut self, key: RsaKey, front: i64, rear: i64, config: Config) -> Result<()> {
        {
            let mut prover_guard = self.rw.write().await;
            if key.g.to_bytes_be().len() == 0
                || key.n.to_bytes_be().len() == 0
                || front < 0
                || rear < 0
                || front > rear
                || rear % (prover_guard.set_len * prover_guard.cluster_size) != 0
            {
                bail!("bad recovery params");
            }
            check_config(config);

            //recovery front and rear
            prover_guard.front = front;
            prover_guard.rear = rear;

            //recovery acc
            prover_guard.acc_manager = Some(recovery(AccPath.lock().unwrap().as_str(), key.clone(), front, rear)?);
        }
        {
            //recovery context
            let mut generated = self.calc_generated_file(IdleFilePath.lock().unwrap().as_str()).await?;
            let mut prover_guard = self.rw.write().await;
            if generated % (prover_guard.set_len * prover_guard.cluster_size) != 0 {
                //restores must be performed in units of the number of files in a set
                generated -= generated % (prover_guard.set_len * prover_guard.cluster_size)
            };
            prover_guard.context.generated = rear + generated; //generated files do not need to be generated again
            prover_guard.context.added = rear + generated; //the file index to be generated should be consistent with the generated file index firstly
            prover_guard.context.commited = rear;
            prover_guard.space -= (prover_guard.rear - prover_guard.front) * FILE_SIZE; //calc proved space
            prover_guard.space -= generated / prover_guard.cluster_size
                * (prover_guard.cluster_size + prover_guard.expanders.k)
                * FILE_SIZE; //calc generated space
        }
        //backup acc file for challenge
        util::copy_files(AccPath.lock().unwrap().as_str(), ChallAccPath.lock().unwrap().as_str())?;

        Ok(())
    }

    pub async fn generate_idle_file_set(&mut self) -> Result<()> {
        let mut prover_guard = self.rw.write().await;

        let file_num = prover_guard.set_len * prover_guard.cluster_size;
        let free_space = util::get_dir_free_space(IdleFilePath.lock().unwrap().as_str())? / 1024 * 1024;
        let mut reserved = 256_i64;

        if prover_guard.space == file_num * FILE_SIZE
            && free_space > (prover_guard.expanders.k * FILE_SIZE + reserved) as u64
        {
            prover_guard.space += prover_guard.expanders.k * FILE_SIZE;
        }

        if prover_guard.space < (file_num + prover_guard.set_len * prover_guard.expanders.k) * FILE_SIZE {
            bail!("generate idle file set error: not enough space")
        }

        prover_guard.context.added += file_num;
        prover_guard.space -= (file_num + prover_guard.set_len * prover_guard.expanders.k) * FILE_SIZE;
        let start = (prover_guard.context.added - file_num) / prover_guard.cluster_size + 1;

        let id = prover_guard.id.clone();
        let set_len = prover_guard.set_len;
        prover_guard
            .expanders
            .generate_idle_file_set(id, start, set_len, IdleFilePath.lock().unwrap().as_str())
            .await?;

        Ok(())
    }

    pub async fn calc_generated_file(&mut self, dir: &str) -> Result<i64> {
        let mut count = 0_i64;
        let prover_guard = self.rw.read().await;
        let file_total_size = FILE_SIZE * (prover_guard.expanders.k + prover_guard.cluster_size) * 1024 * 1024;
        let root_size = (prover_guard.set_len * (prover_guard.expanders.k + prover_guard.cluster_size) + 1)
            * (DEFAULT_HASH_SIZE as i64);
        let mut next = 1_i64;

        let mut files = fs::read_dir(dir).await?;
        while let Some(file) = files.next_entry().await? {
            let file_name = file
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("failed to convert file name to string"))?;
            let sidxs = file_name.split("-").collect::<Vec<&str>>();
            if sidxs.len() < 3 {
                continue;
            }
            let number: i64 = sidxs[2].parse()?;
            if number != prover_guard.rear / (prover_guard.set_len * prover_guard.cluster_size) + next {
                continue;
            }
            if !file.file_type().await?.is_dir() {
                continue;
            }
            let roots_file = file.path().join(COMMIT_FILE);
            match fs::metadata(roots_file).await {
                Ok(metadata) => {
                    if metadata.len() != root_size as u64 {
                        continue;
                    }
                },
                Err(_) => continue,
            }

            let mut clusters = fs::read_dir(file.path()).await?;
            let mut i = 0;
            while let Some(cluster) = clusters.next_entry().await? {
                if !cluster.metadata().await?.is_dir() {
                    continue;
                }

                let mut size = 0;
                let mut files = fs::read_dir(cluster.path()).await?;

                while let Some(file) = files.next_entry().await? {
                    if !file.metadata().await?.is_dir()
                        && file.metadata().await?.len() >= *MiniFileSize.lock().unwrap() as u64
                    {
                        size += file.metadata().await?.len() as i64;
                    }
                }
                if size == file_total_size {
                    count += prover_guard.cluster_size;
                    i += 1;
                }
            }
            if i == prover_guard.set_len as usize {
                next += 1;
            }
        }
        Ok(count)
    }
}

pub fn check_config(config: Config) {
    if !config.acc_path.eq("") {
        let mut acc_path = AccPath.lock().unwrap();
        *acc_path = config.acc_path.to_string();
    }
    if !config.idle_file_path.eq("") {
        let mut idle_file_path = IdleFilePath.lock().unwrap();
        *idle_file_path = config.idle_file_path.to_string();
    }
    if config.max_proof_thread > 0 && *MaxProofThread.lock().unwrap() != config.max_proof_thread {
        let mut max_proof_thread = MaxProofThread.lock().unwrap();
        *max_proof_thread = config.max_proof_thread;
    }
    if !config.chall_acc_path.eq("") && !config.chall_acc_path.eq(AccPath.lock().unwrap().as_str()) {
        let mut chall_acc_path = ChallAccPath.lock().unwrap();
        *chall_acc_path = config.chall_acc_path.to_string();
    }
}
