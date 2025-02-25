use crate::{
    acc::{
        file_manager::backup_acc_data_for_chall,
        multi_level_acc::{
            new_muti_level_acc, recovery, AccHandle, MutiLevelAcc, WitnessNode, DEFAULT_ELEMS_NUM, DEFAULT_PATH,
        },
        RsaKey,
    },
    expanders::{
        self,
        generate_expanders::{self, construct_stacked_expanders},
        generate_idle_file::{AUX_FILE, COMMIT_FILE, DEFAULT_AUX_SIZE, FILE_NAME, HASH_SIZE, SET_DIR_NAME},
        Node, NodeType,
    },
    tree::{self, get_path_proof, PathProof, DEFAULT_HASH_SIZE},
    util,
};
use anyhow::{anyhow, bail, Context as AnyhowContext, Result};
use serde::{Deserialize, Serialize};
use std::{os::fd, path::Path, sync::Mutex};
use tokio::{fs, sync::RwLock};

const FILE_SIZE: i64 = HASH_SIZE as i64;
const ACC_PATH: &str = DEFAULT_PATH;
const CHALL_ACC_PATH: &str = "./chall_acc/";
const IDLE_FILE_PATH: &str = "./proofs";
const MAXPROOFTHREAD: i64 = 4;
const MINIFILESIZE: i64 = 1024 * 1024;

pub struct Prover<T: AccHandle> {
    pub rw: RwLock<ProverBody<T>>,
}

pub struct ProverBody<T: AccHandle> {
    pub expanders: expanders::Expanders,
    pub rear: i64,
    pub front: i64,
    pub space: i64,
    pub set_len: i64,
    pub cluster_size: i64,
    context: Context,
    pub id: Vec<u8>,
    pub chain_state: ChainState<T>,
    pub acc_manager: Option<T>,
    pub config: Config,
}

#[derive(Clone)]
pub struct Config {
    pub file_size: i64,
    pub acc_path: String,
    pub chall_acc_path: String,
    pub idle_file_path: String,
    pub max_proof_thread: i64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            file_size: FILE_SIZE,
            acc_path: ACC_PATH.to_string(),
            chall_acc_path: CHALL_ACC_PATH.to_string(),
            idle_file_path: IDLE_FILE_PATH.to_string(),
            max_proof_thread: MAXPROOFTHREAD,
        }
    }
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

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
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

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
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

    let prover = ProverBody {
        expanders: construct_stacked_expanders(k, n, d),
        rear: 0,
        front: 0,
        space,
        set_len,
        cluster_size: k,
        id,
        context: Context { commited: 0, added: 0, generated: 0, proofed: 0 },
        chain_state: ChainState { acc: None, challenging: false, rear: 0, front: 0 },
        acc_manager: None,
        config: Config::default(),
    };

    Ok(Prover { rw: RwLock::new(prover) })
}

impl Prover<MutiLevelAcc> {
    pub async fn init(&mut self, key: RsaKey, config: Config) -> Result<()> {
        if key.g.to_bytes_be().len() == 0 || key.n.to_bytes_be().len() == 0 {
            return Err(anyhow!("bad init params"));
        }
        let mut prover_guard = self.rw.write().await;

        prover_guard.config = config;

        prover_guard.acc_manager = Some(new_muti_level_acc(&prover_guard.config.acc_path, key.clone()).await?);
        let _ = new_muti_level_acc(&prover_guard.config.chall_acc_path, key).await?;
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
            prover_guard.config = config.clone();

            //recovery front and rear
            prover_guard.front = front;
            prover_guard.rear = rear;

            //recovery acc
            prover_guard.acc_manager = Some(recovery(&prover_guard.config.acc_path, key.clone(), front, rear).await?);
        }
        {
            //recovery context
            let mut generated = self.calc_generated_file(&config.idle_file_path).await?;
            let mut prover_guard = self.rw.write().await;
            if generated % (prover_guard.set_len * prover_guard.cluster_size) != 0 {
                //restores must be performed in units of the number of files in a set
                generated -= generated % (prover_guard.set_len * prover_guard.cluster_size)
            };
            prover_guard.context.generated = rear + generated; //generated files do not need to be generated again
            prover_guard.context.added = rear + generated; //the file index to be generated should be consistent with the generated file index firstly
            prover_guard.context.commited = rear;
            prover_guard.space -= (prover_guard.rear - prover_guard.front) * prover_guard.config.file_size; //calc proved space
            prover_guard.space -= generated / prover_guard.cluster_size
                * (prover_guard.cluster_size + prover_guard.expanders.k)
                * prover_guard.config.file_size; //calc generated space
        }
        //backup acc file for challenge
        util::copy_files(&config.acc_path, &config.chall_acc_path)?;

        Ok(())
    }

    // GenerateIdleFileSet generate num=(p.setLen*p.clusterSize(==k)) idle files, num must be consistent with the data given by CESS, otherwise it cannot pass the verification
    // This method is not thread-safe, please do not use it concurrently!
    pub async fn generate_idle_file_set(&mut self) -> Result<()> {
        let mut prover_guard = self.rw.write().await;

        let file_num = prover_guard.set_len * prover_guard.cluster_size;
        let idle_file_path = prover_guard.config.idle_file_path.clone();
        let free_space = util::get_dir_free_space(&idle_file_path)? / 1024 * 1024;
        let reserved = 256_i64;

        if prover_guard.space == file_num * prover_guard.config.file_size
            && free_space > (prover_guard.expanders.k * prover_guard.config.file_size + reserved) as u64
        {
            prover_guard.space += prover_guard.expanders.k * prover_guard.config.file_size;
        }

        if prover_guard.space
            < (file_num + prover_guard.set_len * prover_guard.expanders.k) * prover_guard.config.file_size
        {
            bail!("generate idle file set error: not enough space")
        }

        prover_guard.context.added += file_num;
        prover_guard.space -=
            (file_num + prover_guard.set_len * prover_guard.expanders.k) * prover_guard.config.file_size;
        let start = (prover_guard.context.added - file_num) / prover_guard.cluster_size + 1;

        let id = prover_guard.id.clone();
        let set_len = prover_guard.set_len;
        prover_guard
            .expanders
            .generate_idle_file_set(id, start, set_len, &idle_file_path)
            .await
            .map_err(|e| {
                prover_guard.context.added -= file_num;
                prover_guard.space +=
                    (file_num + prover_guard.set_len * prover_guard.expanders.k) * prover_guard.config.file_size;
                e
            })?;
        prover_guard.context.generated += file_num;

        Ok(())
    }

    pub async fn calc_generated_file(&mut self, dir: &str) -> Result<i64> {
        let mut count = 0_i64;
        let prover_guard = self.rw.read().await;
        let file_total_size =
            prover_guard.config.file_size * (prover_guard.expanders.k + prover_guard.cluster_size) * 1024 * 1024;
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
                    if !file.metadata().await?.is_dir() && file.metadata().await?.len() >= MINIFILESIZE as u64 {
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

    pub async fn get_idle_file_set_commits(&mut self) -> Result<Commits> {
        let mut commits = Commits::default();
        let mut prover_guard = self.rw.write().await;

        let file_num = prover_guard.context.generated;
        let commited = prover_guard.context.commited;
        let commit_num = prover_guard.set_len * prover_guard.cluster_size;

        if file_num - commited < commit_num {
            bail!("get commits error:bad commit data");
        }
        //read commit file of idle file set
        let name = Path::new(IDLE_FILE_PATH)
            .join(format!(
                "{}-{}",
                expanders::generate_idle_file::SET_DIR_NAME,
                (commited) / (prover_guard.set_len * prover_guard.cluster_size) + 1
            ))
            .join(expanders::generate_idle_file::COMMIT_FILE);
        let root_num = commit_num + prover_guard.expanders.k * prover_guard.set_len + 1;
        commits.roots =
            util::read_proof_file(&name, root_num as usize, tree::DEFAULT_HASH_SIZE as usize).map_err(|e| e)?;
        commits.file_indexs = vec![0_i64; commit_num as usize];
        for i in 0..commit_num {
            commits.file_indexs[i as usize] = commited + i + 1;
        }
        prover_guard.context.commited += commit_num;

        Ok(commits)
    }

    pub async fn prove_commit_and_acc(
        &mut self,
        challenges: Vec<Vec<i64>>,
    ) -> Result<(Option<Vec<Vec<CommitProof>>>, Option<AccProof>)> {
        {
            let prover_guard = self.rw.read().await;
            //copy new acc data to challenging acc path
            let index = prover_guard.rear / DEFAULT_ELEMS_NUM as i64;
            backup_acc_data_for_chall(ACC_PATH, CHALL_ACC_PATH, index)?;
        }

        let commit_proofs = self.prove_commits(challenges.clone()).await?;
        let acc_proof = self.prove_acc(challenges).await?;

        Ok((commit_proofs, acc_proof))
    }

    pub async fn prove_acc(&mut self, challenges: Vec<Vec<i64>>) -> Result<Option<AccProof>> {
        let mut prover_guard = self.rw.write().await;
        if challenges.len() != prover_guard.set_len as usize {
            bail!("update acc error:bad challenges data")
        }
        let file_num = prover_guard.set_len * prover_guard.cluster_size;
        let mut labels: Vec<Vec<u8>> = vec![Vec::new(); file_num as usize];
        let mut proof = AccProof::default();
        proof.indexs = vec![0_i64; file_num as usize];
        //read commit roots file
        let fname = Path::new(IDLE_FILE_PATH)
            .join(format!("{}-{}", SET_DIR_NAME, (challenges[0][0] - 1) / prover_guard.set_len + 1))
            .join(COMMIT_FILE);

        let roots = util::read_proof_file(
            &fname,
            ((prover_guard.expanders.k + prover_guard.cluster_size) * prover_guard.set_len + 1) as usize,
            DEFAULT_HASH_SIZE as usize,
        )
        .context("update acc error")?;

        for i in 0..prover_guard.set_len as usize {
            for j in 0..prover_guard.cluster_size as usize {
                let index = (challenges[i][0] - 1) * prover_guard.cluster_size + j as i64 + 1;
                proof.indexs[i * prover_guard.cluster_size as usize + j] = index;
                let root = roots[(prover_guard.expanders.k as usize + j) * prover_guard.set_len as usize + i].clone();
                let mut label = prover_guard.id.clone();
                label.extend_from_slice(&expanders::get_bytes(index));
                label.extend_from_slice(&root);
                labels[i * prover_guard.cluster_size as usize + j] = expanders::generate_idle_file::get_hash(&label);
            }
        }
        let (wit_chains, acc_path) = prover_guard
            .acc_manager
            .as_mut()
            .ok_or_else(|| anyhow!("acc manager is none"))?
            .add_elements_and_proof(labels.clone())
            .await?;
        proof.wit_chains = Some(Box::new(wit_chains));
        proof.acc_path = acc_path;

        proof.labels = labels;

        Ok(Some(proof))
    }

    pub async fn read_file_labels(&self, cluster: i64, fidx: i64, buf: Vec<u8>) -> Result<()> {
        todo!()
    }

    pub async fn read_aux_data(&self, cluster: i64, fidx: i64, buf: Vec<u8>) -> Result<()> {
        todo!()
    }

    // ProveCommit prove commits no more than MaxCommitProofThread
    pub async fn prove_commits(&self, challenges: Vec<Vec<i64>>) -> Result<Option<Vec<Vec<CommitProof>>>> {
        let neighbor = Path::new(IDLE_FILE_PATH);

        let lens = challenges.len();
        let mut proof_set: Vec<Vec<CommitProof>> = vec![Vec::new(); lens];
        let prover_guard = self.rw.read().await;
        for i in 0..lens {
            let mut proofs: Vec<CommitProof> = vec![CommitProof::default(); challenges[i].len() - 1];
            let fdir = Path::new(IDLE_FILE_PATH)
                .join(format!(
                    "{}-{}",
                    expanders::generate_idle_file::SET_DIR_NAME,
                    (challenges[i][0] - 1) / prover_guard.set_len + 1
                ))
                .join(format!("{}-{}", expanders::generate_idle_file::CLUSTER_DIR_NAME, challenges[i][0]));
            for j in 1..(proofs.len() + 1) as i64 {
                let mut index = challenges[i][j as usize];
                if j > prover_guard.cluster_size + 1 {
                    index = proofs[j as usize - 2].parents[challenges[i][j as usize] as usize].index as i64;
                }
                let mut layer = index / prover_guard.expanders.n;
                if j < prover_guard.cluster_size + 1 {
                    layer = prover_guard.expanders.k + j - 1;
                }
                if layer != 0 || i != 0 {
                    let mut cid = challenges[i][0] - 1;
                    if cid % prover_guard.set_len == 0 {
                        cid += prover_guard.set_len;
                    }
                    neighbor
                        .join(format!(
                            "{}-{}",
                            expanders::generate_idle_file::SET_DIR_NAME,
                            (challenges[i][0] - 1) / prover_guard.set_len + 1,
                        ))
                        .join(format!("{}-{}", expanders::generate_idle_file::CLUSTER_DIR_NAME, cid))
                        .join(format!(
                            "{}-{}",
                            expanders::generate_idle_file::FILE_NAME,
                            layer - (prover_guard.set_len - i as i64) / prover_guard.set_len
                        ));
                }
                proofs[j as usize - 1] = self
                    .generate_commit_proof(&fdir, neighbor, challenges[i][0], index, layer)
                    .await?;
            }
            proof_set[i] = proofs;
        }
        Ok(Some(proof_set))
    }

    pub async fn generate_path_proof(
        &self,
        mht: &mut tree::LightMHT,
        data: &mut [u8],
        index: i64,
        node_idx: i64,
    ) -> Result<MhtProof> {
        tree::calc_light_mht_with_bytes(mht, data, HASH_SIZE as i64);
        let path_proof =
            tree::get_path_proof(&mht, data, index, HASH_SIZE as i64, false).context("generate path proof error")?;

        let mut label: Vec<u8> = vec![0u8; HASH_SIZE as usize];
        label.copy_from_slice(&data[index as usize * HASH_SIZE as usize..(index + 1) as usize * HASH_SIZE as usize]);

        Ok(MhtProof { index: node_idx as NodeType, label, paths: path_proof.path, locs: path_proof.locs })
    }

    pub async fn get_path_proof_with_aux(
        &self,
        aux: &mut Vec<u8>,
        data: &mut Vec<u8>,
        index: i64,
        node_idx: i64,
    ) -> Result<MhtProof> {
        let path_proof = tree::get_path_proof_with_aux(data, aux, index as usize, HASH_SIZE as usize)?;

        let mut label = vec![0u8; HASH_SIZE as usize];
        label.copy_from_slice(&data[index as usize * HASH_SIZE as usize..(index + 1) as usize * HASH_SIZE as usize]);

        Ok(MhtProof { index: node_idx as NodeType, label, paths: path_proof.path, locs: path_proof.locs })
    }

    pub async fn generate_commit_proof(
        &self,
        fdir: &Path,
        neighbor: &Path,
        count: i64,
        c: i64,
        mut subfile: i64,
    ) -> Result<CommitProof> {
        let prover_guard = self.rw.read().await;
        if subfile < 0 || subfile > prover_guard.cluster_size + prover_guard.expanders.k - 1 {
            bail!("generate commit proof error: bad node index")
        }
        let mut data = prover_guard.expanders.file_pool.clone();
        let fpath = fdir.join(format!("{}-{}", expanders::generate_idle_file::FILE_NAME, subfile));

        util::read_file_to_buf(&fpath, &mut data).context("generate commit proof error")?;

        let mut node_tree = tree::get_light_mht(prover_guard.expanders.n);
        let mut parent_tree = tree::get_light_mht(prover_guard.expanders.n);
        let index = c % prover_guard.expanders.n;

        let path_proof = self
            .generate_path_proof(&mut node_tree, &mut data, index, index)
            .await
            .context("generate commit proof error")?;

        let mut proof = CommitProof::default();
        proof.node = path_proof;

        let mut pdata = prover_guard.expanders.file_pool.clone();

        let mut aux: Vec<u8> = vec![0u8; DEFAULT_AUX_SIZE as usize * DEFAULT_HASH_SIZE as usize];

        //add neighbor node dependency
        proof.elders = vec![
            MhtProof::default();
            (subfile / prover_guard.expanders.k) as usize * (prover_guard.expanders.k / 2 + 1) as usize
        ];

        if !neighbor.eq(Path::new("")) {
            util::read_file_to_buf(&neighbor, &mut pdata).context("generate commit proof error")?;

            util::read_file_to_buf(
                Path::new(&neighbor.to_str().unwrap_or("").replacen(FILE_NAME, AUX_FILE, 1)),
                &mut aux,
            )
            .context("generate commit proof error")?;
            proof.elders[0] = self.get_path_proof_with_aux(&mut aux, &mut pdata, index, index).await?;
        }

        if subfile == 0 {
            return Ok(proof);
        }

        //file remapping
        let layer = subfile;
        if subfile > prover_guard.expanders.k {
            let base_layer = (subfile - prover_guard.expanders.k / 2) / prover_guard.expanders.k;
            subfile = prover_guard.expanders.k;

            //add elder node dependency
            for i in 0..prover_guard.expanders.k / 2 {
                let f_path = fdir.join(format!("{}-{}", FILE_NAME, base_layer + i * 2));
                let a_path = fdir.join(format!("{}-{}", AUX_FILE, base_layer + i * 2));

                util::read_file_to_buf(&f_path, &mut pdata).context("generate commit proof error")?;
                util::read_file_to_buf(&a_path, &mut aux).context("generate commit proof error")?;
                proof.elders[i as usize + 1] = self
                    .get_path_proof_with_aux(
                        &mut aux,
                        &mut pdata,
                        index,
                        index + (base_layer + i * 2) * prover_guard.expanders.n,
                    )
                    .await
                    .context("generate commit proof error")?;
            }
        }

        let mut node = Node::new(c as NodeType);
        node.parents = Vec::with_capacity(prover_guard.expanders.d as usize + 1);
        generate_expanders::calc_parents(&prover_guard.expanders, &mut node, &prover_guard.id, count, layer);

        let fpath = fdir.join(format!("{}-{}", FILE_NAME, subfile - 1));

        util::read_file_to_buf(&fpath, &mut pdata).context("generate commit proof error")?;

        tree::calc_light_mht_with_bytes(&mut parent_tree, &mut pdata, HASH_SIZE as i64);
        let lens = node.parents.len();
        let mut parent_proofs = vec![MhtProof::default(); lens];

        for i in 0..lens {
            let index = node.parents[i] as usize % prover_guard.expanders.n as usize;
            let mut path_proof = PathProof::default();
            let mut label = vec![0u8; HASH_SIZE as usize];

            if node.parents[i] as i64 >= subfile * prover_guard.expanders.n {
                label.copy_from_slice(&data[index * HASH_SIZE as usize..(index + 1) * HASH_SIZE as usize]);
                path_proof = get_path_proof(&node_tree, &mut data, index as i64, HASH_SIZE as i64, false)?;
            } else {
                label.copy_from_slice(&pdata[index * HASH_SIZE as usize..(index + 1) * HASH_SIZE as usize]);
                path_proof = get_path_proof(&parent_tree, &mut pdata, index as i64, HASH_SIZE as i64, false)?;
            }
            if node.parents[i] % 6 != 0 {
                path_proof.path = Vec::new();
                path_proof.locs = Vec::new();
            }
            parent_proofs[i] = MhtProof { index: node.parents[i], label, paths: path_proof.path, locs: path_proof.locs }
        }

        proof.parents = parent_proofs;
        Ok(proof)
    }
}
