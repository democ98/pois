use anyhow::{bail, Context, Result};
use ces_pois::{
    acc::{
        self,
        multi_level_acc::{AccHandle, MutiLevelAcc},
    },
    pois::{
        prove::{self},
        verify::{self, Verifier},
    },
};

#[tokio::main]
async fn main() -> Result<()> {
    //Initialize the execution environment
    let k = 8_i64;
    let n = 1024 * 16_i64;
    let d = 64_i64;

    let key = acc::rsa_keygen(2048);

    let id = b"test miner id".to_vec();
    let mut prover = prove::new_prover::<MutiLevelAcc>(k, n, d, id, 256 * 64 * 2 * 4, 32).await?;
    // prover
    //     .recovery(key, 0, 0, Config::default())
    //     .await
    //     .context("recovery failed")?;
    prover
        .init(key.clone(), Default::default())
        .await
        .context("init prover failed")?;

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
    Ok(())
}
