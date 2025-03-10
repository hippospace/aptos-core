// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use ::aptos_logger::*;
use anyhow::{format_err, Context, Result};
use aptos_rest_client::{Client as RestClient, PendingTransaction, Response};
use aptos_sdk::{
    move_types::account_address::AccountAddress,
    transaction_builder::TransactionFactory,
    types::{
        chain_id::ChainId,
        transaction::{authenticator::AuthenticationKey, SignedTransaction},
        LocalAccount,
    },
};
use futures::future::{try_join_all, FutureExt};
use itertools::zip;
use rand::{
    distributions::{Distribution, Standard},
    seq::{IteratorRandom, SliceRandom},
    Rng, RngCore,
};
use rand_core::SeedableRng;
use std::{
    cmp::{max, min},
    collections::HashSet,
    fmt,
    num::NonZeroU64,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{runtime::Handle, task::JoinHandle, time};

pub mod atomic_histogram;
pub mod cluster;
pub mod instance;

use aptos::common::types::EncodingType;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use aptos_sdk::{
    transaction_builder::aptos_stdlib,
    types::{transaction::authenticator::AuthenticationKeyPreimage, AccountKey},
};
use atomic_histogram::*;
use rand::rngs::StdRng;

/// Max transactions per account in mempool
const MAX_TXN_BATCH_SIZE: usize = 100;
const MAX_TXNS: u64 = 1_000_000;
const SEND_AMOUNT: u64 = 1;
const TXN_EXPIRATION_SECONDS: u64 = 180;
const TXN_MAX_WAIT: Duration = Duration::from_secs(TXN_EXPIRATION_SECONDS as u64 + 30);
const MAX_CHILD_VASP_NUM: usize = 65536;
const MAX_VASP_ACCOUNT_NUM: usize = 16;

#[derive(Clone)]
pub struct EmitThreadParams {
    pub wait_millis: u64,
    pub wait_committed: bool,
}

impl Default for EmitThreadParams {
    fn default() -> Self {
        Self {
            wait_millis: 0,
            wait_committed: true,
        }
    }
}

#[derive(Clone)]
pub struct EmitJobRequest {
    rest_clients: Vec<RestClient>,
    accounts_per_client: usize,
    workers_per_endpoint: Option<usize>,
    thread_params: EmitThreadParams,
    gas_price: u64,
    invalid_transaction_ratio: usize,
    vasp: bool,
}

impl Default for EmitJobRequest {
    fn default() -> Self {
        Self {
            rest_clients: Vec::new(),
            accounts_per_client: 15,
            workers_per_endpoint: None,
            thread_params: EmitThreadParams::default(),
            gas_price: 0,
            invalid_transaction_ratio: 0,
            vasp: false,
        }
    }
}

impl EmitJobRequest {
    pub fn new(rest_clients: Vec<RestClient>) -> Self {
        Self::default().rest_clients(rest_clients)
    }

    pub fn rest_clients(mut self, rest_clients: Vec<RestClient>) -> Self {
        self.rest_clients = rest_clients;
        self
    }

    pub fn accounts_per_client(mut self, accounts_per_client: usize) -> Self {
        self.accounts_per_client = accounts_per_client;
        self
    }

    pub fn workers_per_endpoint(mut self, workers_per_endpoint: usize) -> Self {
        self.workers_per_endpoint = Some(workers_per_endpoint);
        self
    }

    pub fn thread_params(mut self, thread_params: EmitThreadParams) -> Self {
        self.thread_params = thread_params;
        self
    }

    pub fn gas_price(mut self, gas_price: u64) -> Self {
        self.gas_price = gas_price;
        self
    }

    pub fn invalid_transaction_ratio(mut self, invalid_transaction_ratio: usize) -> Self {
        self.invalid_transaction_ratio = invalid_transaction_ratio;
        self
    }

    pub fn fixed_tps(self, target_tps: NonZeroU64) -> Self {
        let clients_count = self.rest_clients.len() as u64;
        let num_workers = target_tps.get() / clients_count + 1;
        let wait_time = clients_count * num_workers * 1000 / target_tps.get();

        self.workers_per_endpoint(num_workers as usize)
            .thread_params(EmitThreadParams {
                wait_millis: wait_time,
                wait_committed: true,
            })
            .accounts_per_client(1)
    }

    pub fn vasp(mut self) -> Self {
        self.vasp = true;
        self
    }
}

#[derive(Debug, Default)]
pub struct TxnStats {
    pub submitted: u64,
    pub committed: u64,
    pub expired: u64,
    pub latency: u64,
    pub latency_buckets: AtomicHistogramSnapshot,
}

#[derive(Debug, Default)]
pub struct TxnStatsRate {
    pub submitted: u64,
    pub committed: u64,
    pub expired: u64,
    pub latency: u64,
    pub p99_latency: u64,
}

#[derive(Default)]
struct StatsAccumulator {
    submitted: AtomicU64,
    committed: AtomicU64,
    expired: AtomicU64,
    latency: AtomicU64,
    latencies: Arc<AtomicHistogramAccumulator>,
}

struct Worker {
    join_handle: JoinHandle<Vec<LocalAccount>>,
}

pub struct EmitJob {
    workers: Vec<Worker>,
    stop: Arc<AtomicBool>,
    stats: Arc<StatsAccumulator>,
}

struct SubmissionWorker {
    accounts: Vec<LocalAccount>,
    client: RestClient,
    all_addresses: Arc<Vec<AccountAddress>>,
    stop: Arc<AtomicBool>,
    params: EmitThreadParams,
    stats: Arc<StatsAccumulator>,
    txn_factory: TransactionFactory,
    invalid_transaction_ratio: usize,
    rng: ::rand::rngs::StdRng,
}

impl SubmissionWorker {
    #[allow(clippy::collapsible_if)]
    async fn run(mut self, gas_price: u64) -> Vec<LocalAccount> {
        let wait_duration = Duration::from_millis(self.params.wait_millis);
        while !self.stop.load(Ordering::Relaxed) {
            let requests = self.gen_requests(gas_price);
            let num_requests = requests.len();
            let start_time = Instant::now();
            let wait_until = start_time + wait_duration;
            let mut txn_offset_time = 0u64;
            for request in requests {
                let cur_time = Instant::now();
                txn_offset_time += (cur_time - start_time).as_millis() as u64;
                self.stats.submitted.fetch_add(1, Ordering::Relaxed);
                let resp = self.client.submit(&request).await;
                if let Err(e) = resp {
                    warn!("[{:?}] Failed to submit request: {:?}", self.client, e);
                }
            }
            if self.params.wait_committed {
                if let Err(uncommitted) =
                    wait_for_accounts_sequence(&self.client, &mut self.accounts).await
                {
                    let num_committed = (num_requests - uncommitted.len()) as u64;
                    // To avoid negative result caused by uncommitted tx occur
                    // Simplified from:
                    // end_time * num_committed - (txn_offset_time/num_requests) * num_committed
                    // to
                    // (end_time - txn_offset_time / num_requests) * num_committed
                    let latency = (Instant::now() - start_time).as_millis() as u64
                        - txn_offset_time / num_requests as u64;
                    let committed_latency = latency * num_committed as u64;
                    self.stats
                        .committed
                        .fetch_add(num_committed, Ordering::Relaxed);
                    self.stats
                        .expired
                        .fetch_add(uncommitted.len() as u64, Ordering::Relaxed);
                    self.stats
                        .latency
                        .fetch_add(committed_latency, Ordering::Relaxed);
                    self.stats
                        .latencies
                        .record_data_point(latency, num_committed);
                    info!(
                        "[{:?}] Transactions were not committed before expiration: {:?}",
                        self.client, uncommitted
                    );
                } else {
                    let latency = (Instant::now() - start_time).as_millis() as u64
                        - txn_offset_time / num_requests as u64;
                    self.stats
                        .committed
                        .fetch_add(num_requests as u64, Ordering::Relaxed);
                    self.stats
                        .latency
                        .fetch_add(latency * num_requests as u64, Ordering::Relaxed);
                    self.stats
                        .latencies
                        .record_data_point(latency, num_requests as u64);
                }
            }
            let now = Instant::now();
            if wait_until > now {
                time::sleep(wait_until - now).await;
            }
        }
        self.accounts
    }

    fn gen_requests(&mut self, gas_price: u64) -> Vec<SignedTransaction> {
        let batch_size = max(MAX_TXN_BATCH_SIZE, self.accounts.len());
        let accounts = self
            .accounts
            .iter_mut()
            .choose_multiple(&mut self.rng, batch_size);
        let mut requests = Vec::with_capacity(accounts.len());
        let invalid_size = if self.invalid_transaction_ratio != 0 {
            // if enable mix invalid tx, at least 1 invalid tx per batch
            max(1, accounts.len() * self.invalid_transaction_ratio / 100)
        } else {
            0
        };
        let mut num_valid_tx = accounts.len() - invalid_size;
        for sender in accounts {
            let receiver = self
                .all_addresses
                .choose(&mut self.rng)
                .expect("all_addresses can't be empty");
            let request = if num_valid_tx > 0 {
                num_valid_tx -= 1;
                gen_transfer_txn_request(
                    sender,
                    receiver,
                    SEND_AMOUNT,
                    &self.txn_factory,
                    gas_price,
                )
            } else {
                generate_invalid_transaction(
                    sender,
                    receiver,
                    SEND_AMOUNT,
                    &self.txn_factory,
                    gas_price,
                    &requests,
                    &mut self.rng,
                )
            };
            requests.push(request);
        }
        requests
    }
}

#[derive(Debug)]
pub struct TxnEmitter<'t> {
    accounts: Vec<LocalAccount>,
    txn_factory: TransactionFactory,
    client: RestClient,
    rng: ::rand::rngs::StdRng,
    root_account: &'t mut LocalAccount,
}

impl<'t> TxnEmitter<'t> {
    pub fn new(
        root_account: &'t mut LocalAccount,
        client: RestClient,
        transaction_factory: TransactionFactory,
        rng: ::rand::rngs::StdRng,
    ) -> Self {
        Self {
            accounts: vec![],
            txn_factory: transaction_factory,
            root_account,
            client,
            rng,
        }
    }

    pub fn take_account(&mut self) -> LocalAccount {
        self.accounts.remove(0)
    }

    pub fn clear(&mut self) {
        self.accounts.clear();
    }

    pub fn rng(&mut self) -> &mut ::rand::rngs::StdRng {
        &mut self.rng
    }

    pub fn from_rng(&mut self) -> ::rand::rngs::StdRng {
        ::rand::rngs::StdRng::from_rng(self.rng()).unwrap()
    }

    pub async fn get_money_source(&mut self, coins_total: u64) -> Result<&mut LocalAccount> {
        let client = self.client.clone();
        println!("Creating and minting faucet account");
        let faucet_account = &mut self.root_account;
        let balance = client
            .get_account_balance(faucet_account.address())
            .await?
            .into_inner();
        println!(
            "Root account current balances are {}, requested {} coins",
            balance.get(),
            coins_total
        );
        Ok(faucet_account)
    }

    pub async fn load_vasp_account(
        &self,
        client: &RestClient,
        index: usize,
    ) -> Result<LocalAccount> {
        let file = "vasp".to_owned() + index.to_string().as_str() + ".key";
        let mint_key: Ed25519PrivateKey = EncodingType::BCS
            .load_key("vasp private key", Path::new(&file))
            .unwrap();
        let account_key = AccountKey::from_private_key(mint_key);
        let address = account_key.authentication_key().derived_address();
        let sequence_number = query_sequence_numbers(client, &[address])
            .await
            .map_err(|e| {
                format_err!(
                    "query_sequence_numbers on {:?} for dd account failed: {}",
                    client,
                    e
                )
            })?[0];
        Ok(LocalAccount::new(address, account_key, sequence_number))
    }

    pub async fn get_seed_accounts(
        &mut self,
        rest_clients: &[RestClient],
        seed_account_num: usize,
        vasp: bool,
    ) -> Result<Vec<LocalAccount>> {
        info!("Creating and minting seeds accounts");
        let mut i = 0;
        let mut seed_accounts = vec![];
        if vasp {
            let client = self.pick_mint_client(rest_clients).clone();
            info!("Loading VASP account as seed accounts");
            let load_account_num = min(seed_account_num, MAX_VASP_ACCOUNT_NUM);
            for i in 0..load_account_num {
                let account = self.load_vasp_account(&client, i).await?;
                seed_accounts.push(account);
            }
            info!("Loaded {} VASP accounts", seed_accounts.len());
            return Ok(seed_accounts);
        }
        while i < seed_account_num {
            let client = self.pick_mint_client(rest_clients).clone();
            let batch_size = min(MAX_TXN_BATCH_SIZE, seed_account_num - i);
            let mut rng = self.from_rng();
            let mut batch = gen_random_accounts(batch_size, &mut rng);
            let creation_account = &mut self.root_account;
            let txn_factory = &self.txn_factory;
            let create_requests = batch
                .iter()
                .map(|account| {
                    create_account_request(creation_account, account.public_key(), txn_factory)
                })
                .collect();
            execute_and_wait_transactions(&client, creation_account, create_requests).await?;
            i += batch_size;
            seed_accounts.append(&mut batch);
        }
        info!("Completed creating seed accounts");

        Ok(seed_accounts)
    }

    /// workflow of mint accounts:
    /// 1. mint faucet account as the money source
    /// 2. load tc account to create seed accounts, one seed account for each endpoint
    /// 3. mint coins from faucet to new created seed accounts
    /// 4. split number of requested accounts into equally size of groups
    /// 5. each seed account take responsibility to create one size of group requested accounts and mint coins to them
    /// example:
    /// requested totally 100 new accounts with 10 endpoints
    /// will create 10 seed accounts, each seed account create 10 new accounts
    pub async fn mint_accounts(
        &mut self,
        req: &EmitJobRequest,
        total_requested_accounts: usize,
    ) -> Result<()> {
        if self.accounts.len() >= total_requested_accounts {
            info!("Already have enough accounts exist, do not need to mint more");
            return Ok(());
        }
        let expected_num_seed_accounts =
            if total_requested_accounts / req.rest_clients.len() > MAX_CHILD_VASP_NUM {
                total_requested_accounts / MAX_CHILD_VASP_NUM + 1
            } else {
                (total_requested_accounts / 50).max(1)
            };
        let num_accounts = total_requested_accounts - self.accounts.len(); // Only minting extra accounts
        let coins_per_account = SEND_AMOUNT * MAX_TXNS * 10; // extra coins for secure to pay none zero gas price
        let coins_total = coins_per_account * num_accounts as u64;
        let txn_factory = self.txn_factory.clone();
        let client = self.pick_mint_client(&req.rest_clients);

        // Create seed accounts with which we can create actual accounts concurrently
        let seed_accounts = self
            .get_seed_accounts(&req.rest_clients, expected_num_seed_accounts, req.vasp)
            .await?;
        let mut rng = self.from_rng();
        let faucet_account = self.get_money_source(coins_total).await?;
        let actual_num_seed_accounts = seed_accounts.len();
        let num_new_child_accounts =
            (num_accounts + actual_num_seed_accounts - 1) / actual_num_seed_accounts;
        let coins_per_seed_account = coins_per_account * num_new_child_accounts as u64;
        fund_new_accounts(
            faucet_account,
            &seed_accounts,
            // * 2 for gas fee
            coins_per_seed_account * 2,
            100,
            client.clone(),
            &txn_factory,
            &mut rng,
        )
        .await
        .map_err(|e| format_err!("Failed to mint seed_accounts: {}", e))?;
        println!(
            "Completed minting {} seed accounts, each with {} coins",
            seed_accounts.len(),
            coins_per_seed_account
        );
        println!(
            "Minting additional {} accounts with {} coins each",
            num_accounts, coins_per_account
        );
        // tokio::time::sleep(Duration::from_secs(10)).await;

        let seed_rngs = gen_rng_for_reusable_account(actual_num_seed_accounts);
        // For each seed account, create a future and transfer coins from that seed account to new accounts
        let account_futures = seed_accounts
            .into_iter()
            .enumerate()
            .map(|(i, seed_account)| {
                // Spawn new threads
                let index = i % req.rest_clients.len();
                let cur_client = req.rest_clients[index].clone();
                create_new_accounts(
                    seed_account,
                    num_new_child_accounts,
                    coins_per_account,
                    20,
                    cur_client,
                    &txn_factory,
                    req.vasp,
                    if req.vasp {
                        seed_rngs[i].clone()
                    } else {
                        self.from_rng()
                    },
                )
            });
        let mut minted_accounts = try_join_all(account_futures)
            .await
            .context("Failed to mint accounts")?
            .into_iter()
            .flatten()
            .collect();

        self.accounts.append(&mut minted_accounts);
        assert!(
            self.accounts.len() >= num_accounts,
            "Something wrong in mint_account, wanted to mint {}, only have {}",
            total_requested_accounts,
            self.accounts.len()
        );
        println!("Mint is done");
        Ok(())
    }

    pub async fn start_job(&mut self, req: EmitJobRequest) -> Result<EmitJob> {
        let workers_per_endpoint = match req.workers_per_endpoint {
            Some(x) => x,
            None => {
                let target_threads = 300;
                // Trying to create somewhere between target_threads/2..target_threads threads
                // We want to have equal numbers of threads for each endpoint, so that they are equally loaded
                // Otherwise things like flamegrap/perf going to show different numbers depending on which endpoint is chosen
                // Also limiting number of threads as max 10 per endpoint for use cases with very small number of nodes or use --peers
                min(10, max(1, target_threads / req.rest_clients.len()))
            }
        };
        let num_clients = req.rest_clients.len() * workers_per_endpoint;
        println!(
            "Will use {} workers per endpoint with total {} endpoint clients",
            workers_per_endpoint, num_clients
        );
        let num_accounts = req.accounts_per_client * num_clients;
        println!(
            "Will create {} accounts_per_client with total {} accounts",
            req.accounts_per_client, num_accounts
        );
        self.mint_accounts(&req, num_accounts).await?;
        let all_accounts = self.accounts.split_off(self.accounts.len() - num_accounts);
        let mut workers = vec![];
        let all_addresses: Vec<_> = all_accounts.iter().map(|d| d.address()).collect();
        let all_addresses = Arc::new(all_addresses);
        let mut all_accounts = all_accounts.into_iter();
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(StatsAccumulator::default());
        let tokio_handle = Handle::current();
        for client in req.rest_clients {
            for _ in 0..workers_per_endpoint {
                let accounts = (&mut all_accounts).take(req.accounts_per_client).collect();
                let all_addresses = all_addresses.clone();
                let stop = stop.clone();
                let params = req.thread_params.clone();
                let stats = Arc::clone(&stats);
                let worker = SubmissionWorker {
                    accounts,
                    client: client.clone(),
                    all_addresses,
                    stop,
                    params,
                    stats,
                    txn_factory: self.txn_factory.clone(),
                    invalid_transaction_ratio: req.invalid_transaction_ratio,
                    rng: self.from_rng(),
                };
                let join_handle = tokio_handle.spawn(worker.run(req.gas_price).boxed());
                workers.push(Worker { join_handle });
            }
        }
        println!("Tx emitter workers started");
        Ok(EmitJob {
            workers,
            stop,
            stats,
        })
    }

    pub async fn stop_job(&mut self, job: EmitJob) -> TxnStats {
        job.stop.store(true, Ordering::Relaxed);
        for worker in job.workers {
            let mut accounts = worker
                .join_handle
                .await
                .expect("TxnEmitter worker thread failed");
            self.accounts.append(&mut accounts);
        }
        job.stats.accumulate()
    }

    pub fn peek_job_stats(&self, job: &EmitJob) -> TxnStats {
        job.stats.accumulate()
    }

    pub async fn periodic_stat(&mut self, job: &EmitJob, duration: Duration, interval_secs: u64) {
        let deadline = Instant::now() + duration;
        let mut prev_stats: Option<TxnStats> = None;
        while Instant::now() < deadline {
            let window = Duration::from_secs(interval_secs);
            tokio::time::sleep(window).await;
            let stats = self.peek_job_stats(job);
            let delta = &stats - &prev_stats.unwrap_or_default();
            prev_stats = Some(stats);
            println!("{}", delta.rate(window));
        }
    }

    pub async fn emit_txn_for(
        &mut self,
        duration: Duration,
        emit_job_request: EmitJobRequest,
    ) -> Result<TxnStats> {
        let job = self.start_job(emit_job_request).await?;
        println!("starting emitting txns for {} secs", duration.as_secs());
        tokio::time::sleep(duration).await;
        let stats = self.stop_job(job).await;
        Ok(stats)
    }

    pub async fn emit_txn_for_with_stats(
        &mut self,
        duration: Duration,
        emit_job_request: EmitJobRequest,
        interval_secs: u64,
    ) -> Result<TxnStats> {
        let job = self.start_job(emit_job_request).await?;
        self.periodic_stat(&job, duration, interval_secs).await;
        let stats = self.stop_job(job).await;
        Ok(stats)
    }

    fn pick_mint_client<'a>(&mut self, clients: &'a [RestClient]) -> &'a RestClient {
        clients
            .choose(self.rng())
            .expect("json-rpc clients can not be empty")
    }

    pub async fn submit_single_transaction(
        &self,
        client: &RestClient,
        sender: &mut LocalAccount,
        receiver: &AccountAddress,
        num_coins: u64,
    ) -> Result<Instant> {
        client
            .submit(&gen_transfer_txn_request(
                sender,
                receiver,
                num_coins,
                &self.txn_factory,
                1,
            ))
            .await?;
        let deadline = Instant::now() + TXN_MAX_WAIT;
        Ok(deadline)
    }
}

pub async fn execute_and_wait_transactions(
    client: &RestClient,
    account: &mut LocalAccount,
    txns: Vec<SignedTransaction>,
) -> Result<()> {
    debug!(
        "[{:?}] Submitting transactions {} - {} for {}",
        client,
        account.sequence_number() - txns.len() as u64,
        account.sequence_number(),
        account.address()
    );

    let pending_txns: Vec<Response<PendingTransaction>> =
        try_join_all(txns.iter().map(|t| client.submit(t))).await?;

    for pt in pending_txns {
        client
            .wait_for_transaction(&pt.into_inner())
            .await
            .context("wait for transactions failed")?;
    }

    debug!(
        "[{:?}] Account {} is at sequence number {} now",
        client,
        account.address(),
        account.sequence_number()
    );
    Ok(())
}

async fn wait_for_accounts_sequence(
    client: &RestClient,
    accounts: &mut [LocalAccount],
) -> Result<(), Vec<AccountAddress>> {
    let deadline = Instant::now() + Duration::from_secs(TXN_EXPIRATION_SECONDS); //TXN_MAX_WAIT;
    let addresses: Vec<_> = accounts.iter().map(|d| d.address()).collect();
    let mut uncommitted = addresses.clone().into_iter().collect::<HashSet<_>>();

    while Instant::now() < deadline {
        match query_sequence_numbers(client, &addresses).await {
            Ok(sequence_numbers) => {
                for (account, sequence_number) in zip(accounts.iter(), &sequence_numbers) {
                    if account.sequence_number() == *sequence_number {
                        uncommitted.remove(&account.address());
                    }
                }

                if uncommitted.is_empty() {
                    return Ok(());
                }
            }
            Err(e) => {
                println!(
                    "Failed to query ledger info on accounts {:?} for instance {:?} : {:?}",
                    addresses, client, e
                );
            }
        }

        time::sleep(Duration::from_millis(500)).await;
    }

    Err(uncommitted.into_iter().collect())
}

pub async fn query_sequence_numbers(
    client: &RestClient,
    addresses: &[AccountAddress],
) -> Result<Vec<u64>> {
    Ok(
        try_join_all(addresses.iter().map(|address| client.get_account(*address)))
            .await
            .context("get accounts failed")?
            .into_iter()
            .map(|resp| resp.into_inner().sequence_number)
            .collect(),
    )
}

/// Create `num_new_accounts` by transferring coins from `source_account`. Return Vec of created
/// accounts
async fn create_new_accounts<R>(
    mut source_account: LocalAccount,
    num_new_accounts: usize,
    coins_per_new_account: u64,
    max_num_accounts_per_batch: u64,
    client: RestClient,
    txn_factory: &TransactionFactory,
    reuse_account: bool,
    mut rng: R,
) -> Result<Vec<LocalAccount>>
where
    R: ::rand_core::RngCore + ::rand_core::CryptoRng,
{
    let mut i = 0;
    let mut accounts = vec![];
    while i < num_new_accounts {
        let batch_size = min(
            max_num_accounts_per_batch as usize,
            min(MAX_TXN_BATCH_SIZE, num_new_accounts - i),
        );
        let mut batch = if reuse_account {
            println!("loading {} accounts if they exist", batch_size);
            gen_reusable_accounts(&client, batch_size, &mut rng).await?
        } else {
            let batch = gen_random_accounts(batch_size, &mut rng);
            let creation_requests = batch
                .as_slice()
                .iter()
                .map(|account| {
                    create_account_request(&mut source_account, account.public_key(), txn_factory)
                })
                .collect();
            execute_and_wait_transactions(&client, &mut source_account, creation_requests).await?;
            fund_new_accounts(
                &mut source_account,
                batch.as_slice(),
                coins_per_new_account,
                100,
                client.clone(),
                txn_factory,
                &mut rng,
            )
            .await?;
            batch
        };

        i += batch.len();
        accounts.append(&mut batch);
    }
    Ok(accounts)
}

/// Transfer `coins_per_new_account` from `minting_account` to each account in `accounts`.
async fn fund_new_accounts<R>(
    minting_account: &mut LocalAccount,
    accounts: &[LocalAccount],
    coins_per_new_account: u64,
    max_num_accounts_per_batch: u64,
    client: RestClient,
    txn_factory: &TransactionFactory,
    rng: &mut R,
) -> Result<()>
where
    R: ::rand_core::RngCore + ::rand_core::CryptoRng,
{
    let mut left = accounts;
    let mut i = 0;
    let num_accounts = accounts.len();
    while !left.is_empty() {
        let batch_size = rng.gen::<usize>()
            % min(
                max_num_accounts_per_batch as usize,
                min(MAX_TXN_BATCH_SIZE, num_accounts - i),
            );
        let (to_batch, rest) = left.split_at(batch_size + 1);
        let mint_requests = to_batch
            .iter()
            .map(|account| {
                gen_transfer_txn_request(
                    minting_account,
                    &account.address(),
                    coins_per_new_account,
                    txn_factory,
                    1,
                )
            })
            .collect();
        execute_and_wait_transactions(&client, minting_account, mint_requests).await?;
        i += to_batch.len();
        left = rest;
    }
    Ok(())
}

pub fn create_account_request(
    creation_account: &mut LocalAccount,
    pubkey: &Ed25519PublicKey,
    txn_factory: &TransactionFactory,
) -> SignedTransaction {
    let preimage = AuthenticationKeyPreimage::ed25519(pubkey);
    let auth_key = AuthenticationKey::from_preimage(&preimage);
    creation_account.sign_with_transaction_builder(txn_factory.payload(
        aptos_stdlib::encode_account_create_account(auth_key.derived_address()),
    ))
}

fn gen_random_accounts<R>(num_accounts: usize, rng: &mut R) -> Vec<LocalAccount>
where
    R: ::rand_core::RngCore + ::rand_core::CryptoRng,
{
    (0..num_accounts)
        .map(|_| LocalAccount::generate(rng))
        .collect()
}

pub fn gen_transfer_txn_request(
    sender: &mut LocalAccount,
    receiver: &AccountAddress,
    num_coins: u64,
    txn_factory: &TransactionFactory,
    gas_price: u64,
) -> SignedTransaction {
    sender.sign_with_transaction_builder(
        txn_factory
            .payload(aptos_stdlib::encode_test_coin_transfer(
                *receiver, num_coins,
            ))
            .gas_unit_price(gas_price),
    )
}

fn generate_invalid_transaction<R>(
    sender: &mut LocalAccount,
    receiver: &AccountAddress,
    num_coins: u64,
    transaction_factory: &TransactionFactory,
    gas_price: u64,
    reqs: &[SignedTransaction],
    rng: &mut R,
) -> SignedTransaction
where
    R: ::rand_core::RngCore + ::rand_core::CryptoRng,
{
    let mut invalid_account = LocalAccount::generate(rng);
    let invalid_address = invalid_account.address();
    match Standard.sample(rng) {
        InvalidTransactionType::ChainId => {
            let txn_factory = transaction_factory.clone().with_chain_id(ChainId::new(255));
            gen_transfer_txn_request(sender, receiver, num_coins, &txn_factory, gas_price)
        }
        InvalidTransactionType::Sender => gen_transfer_txn_request(
            &mut invalid_account,
            receiver,
            num_coins,
            transaction_factory,
            gas_price,
        ),
        InvalidTransactionType::Receiver => gen_transfer_txn_request(
            sender,
            &invalid_address,
            num_coins,
            transaction_factory,
            gas_price,
        ),
        InvalidTransactionType::Duplication => {
            // if this is the first tx, default to generate invalid tx with wrong chain id
            // otherwise, make a duplication of an exist valid tx
            if reqs.is_empty() {
                let txn_factory = transaction_factory.clone().with_chain_id(ChainId::new(255));
                gen_transfer_txn_request(sender, receiver, num_coins, &txn_factory, gas_price)
            } else {
                let random_index = rng.gen_range(0, reqs.len());
                reqs[random_index].clone()
            }
        }
    }
}

impl StatsAccumulator {
    pub fn accumulate(&self) -> TxnStats {
        TxnStats {
            submitted: self.submitted.load(Ordering::Relaxed),
            committed: self.committed.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
            latency: self.latency.load(Ordering::Relaxed),
            latency_buckets: self.latencies.snapshot(),
        }
    }
}

impl TxnStats {
    pub fn rate(&self, window: Duration) -> TxnStatsRate {
        TxnStatsRate {
            submitted: self.submitted / window.as_secs(),
            committed: self.committed / window.as_secs(),
            expired: self.expired / window.as_secs(),
            latency: if self.committed == 0 {
                0u64
            } else {
                self.latency / self.committed
            },
            p99_latency: self.latency_buckets.percentile(99, 100),
        }
    }
}

impl std::ops::Sub for &TxnStats {
    type Output = TxnStats;

    fn sub(self, other: &TxnStats) -> TxnStats {
        TxnStats {
            submitted: self.submitted - other.submitted,
            committed: self.committed - other.committed,
            expired: self.expired - other.expired,
            latency: self.latency - other.latency,
            latency_buckets: &self.latency_buckets - &other.latency_buckets,
        }
    }
}

impl fmt::Display for TxnStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "submitted: {}, committed: {}, expired: {}",
            self.submitted, self.committed, self.expired,
        )
    }
}

impl fmt::Display for TxnStatsRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "submitted: {} txn/s, committed: {} txn/s, expired: {} txn/s, latency: {} ms, p99 latency: {} ms",
            self.submitted, self.committed, self.expired, self.latency, self.p99_latency,
        )
    }
}

#[derive(Debug)]
enum InvalidTransactionType {
    /// invalid tx with wrong chain id
    ChainId,
    /// invalid tx with sender not on chain
    Sender,
    /// invalid tx with receiver not on chain
    Receiver,
    /// duplicate an exist tx
    Duplication,
}

impl Distribution<InvalidTransactionType> for Standard {
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> InvalidTransactionType {
        match rng.gen_range(0, 4) {
            0 => InvalidTransactionType::ChainId,
            1 => InvalidTransactionType::Sender,
            2 => InvalidTransactionType::Receiver,
            _ => InvalidTransactionType::Duplication,
        }
    }
}

fn gen_rng_for_reusable_account(count: usize) -> Vec<StdRng> {
    // use same seed for reuse account creation and reuse
    let mut seed = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0,
        0, 0,
    ];
    let mut rngs = vec![];
    for i in 0..count {
        seed[31] = i as u8;
        rngs.push(StdRng::from_seed(seed));
    }
    rngs
}

async fn gen_reusable_account<R>(client: &RestClient, rng: &mut R) -> Result<LocalAccount>
where
    R: ::rand_core::RngCore + ::rand_core::CryptoRng,
{
    let account_key = AccountKey::generate(rng);
    let address = account_key.authentication_key().derived_address();
    let sequence_number = match query_sequence_numbers(client, &[address]).await {
        Ok(v) => v[0],
        Err(_) => 0,
    };
    Ok(LocalAccount::new(address, account_key, sequence_number))
}

async fn gen_reusable_accounts<R>(
    client: &RestClient,
    num_accounts: usize,
    rng: &mut R,
) -> Result<Vec<LocalAccount>>
where
    R: ::rand_core::RngCore + ::rand_core::CryptoRng,
{
    let mut vasp_accounts = vec![];
    let mut i = 0;
    while i < num_accounts {
        vasp_accounts.push(gen_reusable_account(client, rng).await?);
        i += 1;
    }
    Ok(vasp_accounts)
}
