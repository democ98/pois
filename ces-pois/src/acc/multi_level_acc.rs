use std::{fs, sync::RwLock};

use super::{generate_acc, hash_2_prime::h_prime, RsaKey};
use anyhow::{anyhow, Ok, Result};
use num_bigint_dig::BigUint;
use rand::Rng;
use serde::{Deserialize, Serialize};

pub const DEFAULT_PATH: &str = "./acc/";
const DEFAULT_ELEMS_NUM: i32 = 256;
const DEFAULT_LEVEL: i32 = 3;

pub trait AccHandle {
    fn get_snapshot(&self) -> &MutiLevelAcc;

    fn add_elements_and_proof(&mut self, elements: Vec<Vec<u8>>) -> Result<(Option<Box<WitnessNode>>, Vec<Vec<u8>>)>;

    fn delete_elements_and_proof(&mut self, index: usize) -> Result<(Option<Box<WitnessNode>>, Vec<Vec<u8>>)>;

    fn get_witness_chains(&self, indexes: Vec<i64>) -> Result<Vec<Option<Box<WitnessNode>>>>;

    fn update_snapshot(&mut self) -> bool;

    fn rollback(&mut self) -> bool;

    fn restore_sub_acc_file(&mut self, index: usize, elems: Vec<Vec<u8>>) -> Result<()>;

    fn get_file_path(&self) -> &str;
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AccNode {
    pub value: Vec<u8>,
    pub children: Vec<Option<Box<AccNode>>>,
    pub len: i64,
    pub wit: Vec<u8>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct WitnessNode {
    pub elem: Vec<u8>,
    pub wit: Vec<u8>,
    pub acc: Option<Box<WitnessNode>>,
}

pub struct MutiLevelAcc {
    pub rw: RwLock<MutiLevelAccStruct>,
}

pub struct MutiLevelAccStruct {
    pub accs: AccNode,
    pub key: RsaKey,
    pub elem_nums: i64,
    pub deleted: i64,
    pub curr_count: i64,
    pub curr: Option<AccNode>,
    pub parent: Option<AccNode>,
    pub is_update: bool,
    pub stable: bool,
    pub is_del: bool,
    pub snapshot: Option<Box<MutiLevelAcc>>,
    pub file_path: String,
}

impl Default for MutiLevelAcc {
    fn default() -> Self {
        Self {
            rw: RwLock::new(MutiLevelAccStruct {
                accs: Default::default(),
                key: Default::default(),
                elem_nums: 0,
                deleted: 0,
                curr_count: 0,
                curr: Default::default(),
                parent: Default::default(),
                is_update: false,
                stable: false,
                is_del: false,
                snapshot: None,
                file_path: "".to_string(),
            }),
        }
    }
}

pub fn recovery(acc_path: &str, key: RsaKey, front: i64, rear: i64) -> Result<MutiLevelAcc> {
    todo!()
}

pub fn new_muti_level_acc(path: &str, key: RsaKey) -> Result<MutiLevelAcc> {
    let path = if path == "" { DEFAULT_PATH.to_string() } else { path.to_string() };

    if !std::path::Path::new(&path).exists() {
        fs::create_dir_all(&path)?;
    }
    let mut acc = AccNode::default();
    acc.value = key.g.to_bytes_be();

    let acc_manager = MutiLevelAcc::default();

    {
        let mut acc_manager_guard = acc_manager
            .rw
            .write()
            .map_err(|e| anyhow!("new_muti_level_acc RwLock error: {}", e))?;
        acc_manager_guard.accs = acc;
        acc_manager_guard.key = key;
        acc_manager_guard.file_path = path;
        acc_manager_guard.stable = true;
    }

    Ok(acc_manager)
}

impl AccHandle for MutiLevelAcc {
    fn get_snapshot(&self) -> &MutiLevelAcc {
        // let acc = self.rw.read().map_err(|e| e.into_inner()).unwrap();
        // if acc.snapshot.is_none() {}
        todo!()
    }

    fn add_elements_and_proof(&mut self, elements: Vec<Vec<u8>>) -> Result<(Option<Box<WitnessNode>>, Vec<Vec<u8>>)> {
        todo!()
    }

    fn delete_elements_and_proof(&mut self, index: usize) -> Result<(Option<Box<WitnessNode>>, Vec<Vec<u8>>)> {
        todo!()
    }

    fn get_witness_chains(&self, indexes: Vec<i64>) -> Result<Vec<Option<Box<WitnessNode>>>> {
        todo!()
    }

    fn update_snapshot(&mut self) -> bool {
        todo!()
    }

    fn rollback(&mut self) -> bool {
        todo!()
    }

    fn restore_sub_acc_file(&mut self, index: usize, elems: Vec<Vec<u8>>) -> Result<()> {
        todo!()
    }

    fn get_file_path(&self) -> &str {
        todo!()
    }
}

impl MutiLevelAcc {
    pub fn copy(&mut self, other: Option<MutiLevelAcc>) {
        if other.is_none() {
            return;
        }
        let other = other.unwrap();
        let other_guard = other.rw.write().unwrap();
        let mut accs = AccNode::default();
        copy_acc_node(&other_guard.accs.clone(), &mut accs);
        let mut self_guard = self.rw.write().unwrap();
        self_guard.accs = accs;
        self_guard.key = other_guard.key.clone();
        self_guard.elem_nums = other_guard.elem_nums;
        self_guard.curr_count = other_guard.curr_count;
        if self_guard.accs.len > 0 {
            self_guard.parent = self_guard.accs.children[self_guard.accs.len as usize - 1]
                .as_ref()
                .and_then(|node| Some(node.as_ref().clone()));
        }

        if let Some(ref parent) = self_guard.parent {
            if parent.len > 0 {
                self_guard.curr = parent.children[parent.len as usize - 1]
                    .as_ref()
                    .and_then(|node| Some(node.as_ref().clone()));
            }
        };
    }
    pub fn create_snap_shot(&mut self) {}
}

fn copy_acc_node(src: &AccNode, target: &mut AccNode) {
    target.value = src.value.clone();
    target.children = vec![Some(Box::new(AccNode::default())); src.children.len()];
    target.len = src.len;
    target.wit = src.wit.clone();
    for i in 0..src.children.len() {
        if let Some(child) = &src.children[i] {
            copy_acc_node(child, target.children[i].as_mut().unwrap());
        }
    }
}

pub fn verify_insert_update(
    key: RsaKey,
    exist: Option<Box<WitnessNode>>,
    elems: Vec<Vec<u8>>,
    accs: Vec<Vec<u8>>,
    acc: Vec<u8>,
) -> bool {
    if exist.is_none() || elems.is_empty() || accs.len() < DEFAULT_LEVEL as usize {
        println!("acc wit chain is empty");
        return false;
    }

    let mut p = exist.clone().unwrap().as_ref().clone();
    while p.acc.is_some() && p.acc.as_ref().unwrap().elem == p.wit {
        p = p.acc.unwrap().as_ref().clone();
    }

    // Proof of the witness of accumulator elements,
    // when the element's accumulator does not exist, recursively verify its parent accumulator
    if !verify_mutilevel_acc(&key, Some(&mut p.clone()), &acc) {
        println!("verify muti-level acc error");
        return false;
    }

    // Verify that the newly generated accumulators after inserting elements
    // is calculated based on the original accumulators
    let sub_acc = generate_acc(&key, &exist.as_ref().unwrap().elem, elems);
    if !sub_acc.eq(&Some(accs[0].clone())) {
        println!("Verify that the newly generated accumulators after inserting elements is calculated based on the original accumulators error");
        return false;
    }

    let mut count = 1;
    let mut p = *exist.unwrap();
    let mut sub_acc;

    while p.acc.is_some() {
        sub_acc = generate_acc(&key, &p.wit, vec![accs[count - 1].clone()]);

        if !sub_acc.eq(&Some(accs[count].to_vec())) {
            println!("verify sub acc error");
            return false;
        }
        p = *p.acc.unwrap();
        count += 1;
    }

    true
}

fn verify_acc(key: &RsaKey, acc: &[u8], u: &[u8], wit: &[u8]) -> bool {
    let e = h_prime(&BigUint::from_bytes_be(u));
    let dash = BigUint::from_bytes_be(wit).modpow(&e, &key.n);
    dash == BigUint::from_bytes_be(acc)
}

pub fn verify_mutilevel_acc(key: &RsaKey, wits: Option<&mut WitnessNode>, acc: &[u8]) -> bool {
    let mut current_wit = wits.unwrap();
    while let Some(acc_node) = &mut current_wit.acc {
        if !verify_acc(key, &acc_node.elem, &current_wit.elem, &current_wit.wit) {
            return false;
        }
        current_wit = acc_node;
    }
    current_wit.elem.eq(acc)
}

pub fn verify_mutilevel_acc_for_batch(key: &RsaKey, base_idx: i64, wits: Vec<WitnessNode>, acc: &[u8]) -> bool {
    let mut sub_acc: Option<Vec<u8>> = None;
    let default_elems_num = DEFAULT_ELEMS_NUM as i64;
    for (i, witness) in wits.iter().enumerate() {
        if let Some(sa) = &sub_acc {
            if witness.acc.clone().unwrap().elem != *sa {
                return false;
            }
        }

        if (i as i64 + base_idx) % default_elems_num == 0 || i == wits.len() - 1 {
            if !verify_mutilevel_acc(key, Some(&mut witness.clone()), acc) {
                return false;
            }
            sub_acc = None;
            continue;
        }

        let mut rng = rand::thread_rng();
        if rng.gen_range(0..100) < 25
            && !verify_acc(key, &witness.acc.clone().unwrap().elem, &witness.elem, &witness.wit)
        {
            return false;
        }

        sub_acc = Some(witness.acc.clone().unwrap().elem.clone());
    }
    true
}

pub fn verify_delete_update(
    key: RsaKey,
    exist: &mut WitnessNode,
    elems: Vec<Vec<u8>>,
    accs: Vec<Vec<u8>>,
    acc: &[u8],
) -> bool {
    if elems.is_empty() || accs.len() < DEFAULT_LEVEL as usize {
        return false;
    }
    if !verify_mutilevel_acc(&key, Some(exist), acc) {
        return false;
    }

    let mut sub_acc = generate_acc(&key, &accs[0], elems);
    if sub_acc.eq(&Some(exist.elem.clone())) {
        return false;
    }
    let mut p = exist;
    let mut count = 1;
    while p.acc.is_some() {
        if accs[count - 1].eq(&key.g.to_bytes_be()) {
            sub_acc = generate_acc(&key, &p.wit, vec![accs[count - 1].clone()]);
        } else {
            sub_acc = Some(p.wit.clone());
        }
        if !sub_acc.eq(&Some(accs[count].to_vec())) {
            return false;
        }
        p = p.acc.as_mut().unwrap();
        count += 1;
    }

    true
}
