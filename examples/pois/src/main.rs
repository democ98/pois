use std::{fs, io::Read};

use anyhow::{bail, Context, Result};
use ces_pois::{
    acc::{
        self,
        multi_level_acc::{AccHandle, MutiLevelAcc},
    },
    pois::{
        prove::{self},
        verify::Verifier,
    },
    util,
};

#[tokio::main]
async fn main() -> Result<()> {
    //Initialize the execution environment
    let k = 8_i64;
    let n = 1024 * 16_i64;
    let d = 64_i64;

    let key = acc::rsa_keygen(2048);
    // let key = parse_key("./key")?;

    let id = b"test miner id".to_vec();
    let mut prover =
        prove::new_prover::<MutiLevelAcc>(k, n, d, id.clone(), 256 * 64 * 2 * 4, 32).await?;
    prover
        .recovery(key.clone(), 0, 0, Default::default())
        .await
        .context("recovery failed")?;
    // prover
    //     .init(key.clone(), Default::default())
    //     .await
    //     .context("init prover failed")?;

    let verifier = Verifier::new(k, n, d);

    let mut ts = tokio::time::Instant::now();
    prover
        .generate_idle_file_set()
        .await
        .context("generate idle file set failed")?;
    println!(
        "generate idle file set time :{}ms",
        ts.elapsed().as_millis()
    );

    // get commits
    ts = tokio::time::Instant::now();
    let commits = prover
        .get_idle_file_set_commits()
        .await
        .context("get idle file set commits failed")?;
    println!("get commits time :{}ms", ts.elapsed().as_millis());

    //register prover
    let value = prover
        .rw
        .write()
        .await
        .acc_manager
        .clone()
        .unwrap()
        .get_snapshot()
        .await
        .read()
        .await
        .accs
        .clone()
        .unwrap()
        .read()
        .await
        .value
        .clone();
    let id = prover.rw.read().await.id.clone();
    verifier.register_prover_node(&id, key.clone(), &value, 0, 0);

    //verifier receive commits
    ts = tokio::time::Instant::now();
    if !verifier.receive_commits(&id, &commits) {
        bail!("receive commits failed")
    };
    println!("receive commits time :{}ms", ts.elapsed().as_millis());

    //generate commits challenges
    let chals = verifier
        .commit_challenges(&id)
        .context("generate commit challenges error")?;
    // let chals = parse_challenge("./challenge")?;
    //prove commit and acc
    ts = tokio::time::Instant::now();
    let (commit_proofs, acc_proof) = prover
        .prove_commit_and_acc(chals.clone())
        .await
        .context("prove commit error")?;
    if commit_proofs.is_some() && acc_proof.is_some() {
        println!("update or delete task is already running")
    };
    println!("prove commit time :{}ms", ts.elapsed().as_millis());

    //// make commit_proofs and acc_proof to json////

    let commit_proofs_json = serde_json::to_vec(&commit_proofs.clone().unwrap())?;
    util::save_file(
        std::path::Path::new("./commit_proof.json"),
        &commit_proofs_json,
    )?;

    //verify commit proof
    ts = tokio::time::Instant::now();
    verifier
        .verify_commit_proofs(&id, chals.clone(), commit_proofs.unwrap())
        .context("verify commit proof error")?;
    println!("verify commit proof time :{}ms", ts.elapsed().as_millis());

    //verify acc proof
    ts = tokio::time::Instant::now();
    verifier
        .verify_acc(&id, chals.clone(), acc_proof.unwrap())
        .context("verify acc proof error")?;
    println!("verify acc proof time :{}ms", ts.elapsed().as_millis());

    //add file to count
    ts = tokio::time::Instant::now();
    prover
        .update_status(256, false)
        .await
        .context("update status error")?;
    println!("update prover status time :{}ms", ts.elapsed().as_millis());

    println!(
        "commit proof updated data: {},{}",
        prover.get_front().await,
        prover.get_rear().await
    );

    //deletion proof
    ts = tokio::time::Instant::now();
    let mut del_proof = prover
        .prove_deletion(8)
        .await
        .context("prove deletion proof error")?;
    println!("prove deletion proof time :{}ms", ts.elapsed().as_millis());

    ts = tokio::time::Instant::now();
    //set space challenge state
    prover
        .set_challenge_state(key, verifier.get_node(&id)?.record.unwrap().acc, 0, 256)
        .await
        .context("set challenge state error")?;
    println!("set challenge state time :{}ms", ts.elapsed().as_millis());

    ts = tokio::time::Instant::now();
    let space_chals = verifier
        .space_challenges(8)
        .context("generate space chals error")?;
    // let space_chals =
    //     parse_space_challenge("./space-challenge")?;
    println!("generate space chals time :{}ms", ts.elapsed().as_millis());

    //prove space
    ts = tokio::time::Instant::now();
    let space_proof = prover
        .prove_space(space_chals.clone(), 1, 256 + 1)
        .await
        .context("prove space error")?;
    println!("prove space time :{}ms", ts.elapsed().as_millis());

    //verify space proof
    ts = tokio::time::Instant::now();
    verifier
        .verify_space(
            &verifier.get_node(&id)?,
            space_chals,
            &mut space_proof.write().await.clone(),
        )
        .context("verify space proof error")?;
    println!("verify space proof time :{}ms", ts.elapsed().as_millis());
    prover.rest_challenge_state().await;

    //verify deletion proof
    ts = tokio::time::Instant::now();
    verifier
        .verify_deletion(&id, &mut del_proof)
        .context("verify deletion proof error")?;
    println!("verify deletion proof time :{}ms", ts.elapsed().as_millis());

    //add file to count
    ts = tokio::time::Instant::now();
    prover
        .update_status(del_proof.roots.len() as i64, true)
        .await
        .context("update count error")?;
    println!("update prover status time :{}ms", ts.elapsed().as_millis());
    ts = tokio::time::Instant::now();
    prover.delete_files().await.context("delete files error")?;
    println!("delete files time :{}ms", ts.elapsed().as_millis());

    Ok(())
}

#[allow(dead_code)]
fn parse_key(path: &str) -> Result<acc::RsaKey> {
    let mut f = fs::File::open(path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    Ok(acc::get_key_from_bytes(buffer))
}

#[allow(dead_code)]
fn parse_challenge(path: &str) -> Result<Vec<Vec<i64>>> {
    let mut f = fs::File::open(path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    let challenge: Vec<Vec<i64>> =
        serde_json::from_slice(&buffer).context("parse challenge error")?;

    Ok(challenge)
}

#[allow(dead_code)]
fn parse_space_challenge(path: &str) -> Result<Vec<i64>> {
    let mut f = fs::File::open(path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    let challenge: Vec<i64> =
        serde_json::from_slice(&buffer).context("parse space challenge error")?;

    Ok(challenge)
}
