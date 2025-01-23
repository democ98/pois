use std::{fs, path::Path};

use crate::acc::{self, RsaKey};
use anyhow::{anyhow, Result};
use num_bigint_dig::BigUint;
use sysinfo::{DiskExt, System, SystemExt};

pub fn get_dir_free_space(dir: &str) -> Result<u64> {
    let system = System::new_all();
    let disk = system
        .disks()
        .iter()
        .find(|d| d.mount_point().eq(Path::new(dir)))
        .ok_or_else(|| anyhow!("Directory not found"))?
        .available_space();
    Ok(disk)
}

pub fn copy_data(target: &mut [u8], src: &[&[u8]]) {
    let mut count = 0;
    let lens = target.len();

    for d in src {
        let l = d.len();
        if l == 0 || l + count > lens {
            continue;
        }
        target[count..count + l].copy_from_slice(d);
        count += l;
    }
}

pub fn parse_key(path: &str) -> Result<RsaKey, std::io::Error> {
    let data = fs::read(path)?;
    Ok(get_key_from_bytes(&data))
}

fn get_key_from_bytes(data: &[u8]) -> RsaKey {
    if data.len() < 8 {
        return acc::rsa_keygen(2048);
    }
    let nl = u64::from_be_bytes(data[..8].try_into().unwrap());
    let gl = u64::from_be_bytes(data[8..16].try_into().unwrap());
    if nl == 0 || gl == 0 || data.len() - 16 != (nl + gl) as usize {
        return acc::rsa_keygen(2048);
    }
    let n = BigUint::from_bytes_be(&data[16..16 + nl as usize]);
    let g = BigUint::from_bytes_be(&data[16 + nl as usize..]);
    RsaKey::new(n, g)
}

pub fn add_data(target: &mut [u8], src: &[&[u8]]) {
    let target_len = target.len();
    for s in src {
        if s.len() < target_len {
            continue;
        }
        for (i, elem) in target.iter_mut().enumerate() {
            *elem ^= s[i];
        }
    }
}

pub fn clear_data(target: &mut [u8]) {
    for element in target.iter_mut() {
        *element = 0;
    }
}

pub fn copy_files(src: &str, dst: &str) -> Result<()> {
    if !fs::read_dir(dst).is_err() {
        fs::remove_dir_all(dst)?;
    }

    fs::create_dir_all(dst)?;

    let files = fs::read_dir(src)?;

    //check file in src directory is folder or not , if is folder then continue, otherwise open the file and copy on into det directory
    for file in files {
        let file_path = file?.path();
        if file_path.is_dir() {
            continue;
        } else {
            fs::copy(
                &file_path,
                Path::new(dst).join(
                    file_path
                        .file_name()
                        .ok_or_else(|| anyhow!("Invalid file name"))?
                        .to_str()
                        .unwrap(),
                ),
            )?;
        }
    }

    fs::copy(src, dst)?;

    Ok(())
}
