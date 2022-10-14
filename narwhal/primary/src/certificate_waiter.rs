// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::metrics::PrimaryMetrics;
use config::Committee;
use crypto::{NetworkPublicKey, PublicKey};
use futures::{stream::FuturesUnordered, Future, FutureExt, StreamExt};
use network::PrimaryToPrimaryRpc;
use rand::{rngs::ThreadRng, seq::SliceRandom};
use std::{collections::BTreeMap, future::pending, pin::Pin, sync::Arc, time::Duration};
use storage::CertificateStore;
use tokio::{
    sync::{oneshot, watch},
    task::{JoinError, JoinHandle},
    time::{self, Instant},
};
use tracing::{debug, error, instrument, trace, warn};
use types::{
    error::{DagError, DagResult},
    metered_channel::{Receiver, Sender},
    Certificate, FetchCertificatesRequest, FetchCertificatesResponse, ReconfigureNotification,
    Round,
};

#[cfg(test)]
#[path = "tests/certificate_waiter_tests.rs"]
pub mod certificate_waiter_tests;

// Maximum number of certficates to fetch with one request.
const MAX_CERTIFICATES_TO_FETCH: usize = 1000;

/// Message format from CertificateWaiter to core on the loopback channel.
pub struct CertificateLoopbackMessage {
    /// Certificates to be processed by the core.
    /// In normal case processing the certificates in order should not encounter any missing parent.
    pub certificates: Vec<Certificate>,
    /// Used by core to signal back that it is done with the certificates.
    pub done: oneshot::Sender<()>,
}

/// When there are certificates missing from local store, e.g. discovered when a received
/// certificate has missing parents, CertificateWaiter is responsible for fetching missing
/// certificates from other primaries.
pub(crate) struct CertificateWaiter {
    /// Internal state of CertificateWaiter.
    state: Arc<CertificateWaiterState>,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    certificate_store: CertificateStore,
    /// Watch channel notifying of epoch changes, it is only used for cleanup.
    rx_reconfigure: watch::Receiver<ReconfigureNotification>,
    /// Receives certificates with missing parents from the `Synchronizer`.
    rx_certificate_waiter: Receiver<Certificate>,
    /// Map of validator to target rounds that local store must catch up to.
    targets: BTreeMap<PublicKey, Round>,
    /// Keeps the handle to the inflight fetch certificates task.
    /// Contains a pending future that never returns, and at most 1 other task.
    fetch_certificates_task:
        FuturesUnordered<Pin<Box<dyn Future<Output = Result<(), JoinError>> + Send>>>,
}

/// Thread-safe internal state of CertificateWaiter shared with its fetch task.
struct CertificateWaiterState {
    /// Identity of the current authority.
    name: PublicKey,
    /// Network client to fetch certificates from other primaries.
    network: Arc<dyn PrimaryToPrimaryRpc>,
    /// Loops fetched certificates back to the core. Certificates are ensured to have all parents.
    tx_certificates_loopback: Sender<CertificateLoopbackMessage>,
    /// The metrics handler
    metrics: Arc<PrimaryMetrics>,
}

impl CertificateWaiter {
    #[must_use]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        network: Arc<dyn PrimaryToPrimaryRpc>,
        certificate_store: CertificateStore,
        rx_reconfigure: watch::Receiver<ReconfigureNotification>,
        rx_certificate_waiter: Receiver<Certificate>,
        tx_certificates_loopback: Sender<CertificateLoopbackMessage>,
        metrics: Arc<PrimaryMetrics>,
    ) -> JoinHandle<()> {
        let state = Arc::new(CertificateWaiterState {
            name,
            network,
            tx_certificates_loopback,
            metrics,
        });
        // Add a future that never returns to fetch_certificates_task, so it is blocked when empty.
        let fetch_certificates_task = FuturesUnordered::new();
        fetch_certificates_task.push(pending().boxed());
        tokio::spawn(async move {
            Self {
                state,
                committee,
                certificate_store,
                rx_reconfigure,
                rx_certificate_waiter,
                targets: BTreeMap::new(),
                fetch_certificates_task,
            }
            .run()
            .await;
        })
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(certificate) = self.rx_certificate_waiter.recv() => {
                    let header = &certificate.header;
                    if header.epoch != self.committee.epoch() {
                        continue;
                    }
                    // Unnecessary to validate the header and certificate further, since it has
                    // already been validated.

                    if let Some(r) = self.targets.get(&header.author) {
                        if header.round <= *r {
                            // Ignore fetch request when we already need to sync to a later
                            // certificate.
                            continue;
                        }
                    }

                    // The header should have been verified as part of the certificate.
                    match self.certificate_store.last_round_number(&header.author) {
                        Ok(Some(r)) => {
                            if r >= header.round {
                                // Ignore fetch request. Possibly the certificate was processed
                                // while the message is in the queue.
                                continue;
                            }
                            // Otherwise, continue to update fetch targets.
                        }
                        Ok(None) => {
                            // No certificate has been processed for the authority since genesis.
                            // Continue to update fetch target for the authority.
                        }
                        Err(e) => {
                            // If this happens, it is most likely due to bincode serialization error.
                            error!("Failed to read latest round for {}: {}", header.author, e);
                            continue;
                        }
                    };

                    // Update the target rounds for the authority.
                    self.targets.insert(header.author.clone(), header.round);

                    // Kick start a fetch task if there is no task other than the pending task running.
                    if self.fetch_certificates_task.len() == 1 {
                        self.kick();
                    }
                },
                _ = self.fetch_certificates_task.next() => {
                    // Kick start another fetch task after the previous one terminates.
                    // If all targets have been fetched, the new task will clean up the targets and exit.
                    if self.fetch_certificates_task.len() == 1 {
                        self.kick();
                    }
                },
                result = self.rx_reconfigure.changed() => {
                    result.expect("Committee channel dropped");
                    let message = self.rx_reconfigure.borrow_and_update().clone();
                    match message {
                        ReconfigureNotification::NewEpoch(committee) => {
                            self.committee = committee;
                            self.targets.clear();
                        },
                        ReconfigureNotification::UpdateCommittee(committee) => {
                            self.committee = committee;
                            // There should be no committee membership change so self.targets does
                            // not need to be updated.
                        },
                        ReconfigureNotification::Shutdown => return
                    }
                    debug!("Committee updated to {}", self.committee);
                }
            }
        }
    }

    // Starts a task to fetch missing certificates from other primaries.
    // A call to kick() can be triggered by a certificate with missing parents or the end of a
    // fetch task. Each iteration of kick() updates the target rounds, and iterations will continue
    // until there are no more target rounds to catch up to.
    #[allow(clippy::mutable_key_type)]
    fn kick(&mut self) {
        let highest_rounds = match self.read_highest_rounds() {
            Ok(highest_rounds) => highest_rounds,
            Err(e) => {
                warn!("Failed to read rounds per authority from the certificate store: {e}");
                return;
            }
        };
        self.targets.retain(|origin, target_round| {
            let highest_round = highest_rounds.get(origin).unwrap();
            // Drop sync target when cert store already has an equal or higher round for the origin.
            highest_round < target_round
        });
        if self.targets.is_empty() {
            trace!("Certificates have caught up. Skip fetching.");
            return;
        }

        let state = self.state.clone();
        let committee = self.committee.clone();

        self.fetch_certificates_task.push(
            tokio::task::spawn(async move {
                state
                    .metrics
                    .certificate_waiter_inflight_fetch
                    .with_label_values(&[&committee.epoch.to_string()])
                    .inc();
                state
                    .metrics
                    .certificate_waiter_fetch_attempts
                    .with_label_values(&[&committee.epoch.to_string()])
                    .inc();

                let now = Instant::now();
                match run_fetch_task(state.clone(), committee.clone(), highest_rounds).await {
                    Ok(_) => {
                        debug!("Finished task to fetch certificates successfully");
                    }
                    Err(e) => {
                        debug!("Finished task to fetch certificates with error: {e}");
                    }
                };

                state
                    .metrics
                    .certificate_waiter_op_latency
                    .with_label_values(&[&committee.epoch.to_string()])
                    .observe(now.elapsed().as_secs_f64());
                state
                    .metrics
                    .certificate_waiter_inflight_fetch
                    .with_label_values(&[&committee.epoch.to_string()])
                    .dec();
            })
            .boxed(),
        );

        debug!("Started task to fetch certificates");
    }

    #[allow(clippy::mutable_key_type)]
    fn read_highest_rounds(&self) -> DagResult<BTreeMap<PublicKey, Round>> {
        let mut highest_rounds = BTreeMap::new();
        for (name, _) in self.committee.authorities() {
            // Last round is 0 (genesis) when authority is not found in store.
            let last_round = self.certificate_store.last_round_number(name)?.unwrap_or(0);
            highest_rounds.insert(name.clone(), last_round);
        }
        Ok(highest_rounds)
    }
}

#[allow(clippy::mutable_key_type)]
async fn run_fetch_task(
    state: Arc<CertificateWaiterState>,
    committee: Committee,
    highest_rounds: BTreeMap<PublicKey, Round>,
) -> DagResult<()> {
    // Send request to fetch certificates.
    let request = FetchCertificatesRequest {
        exclusive_lower_bounds: highest_rounds.into_iter().collect(),
        max_items: MAX_CERTIFICATES_TO_FETCH,
    };
    let response =
        fetch_certificates_helper(&state.name, &state.network, &committee, request).await;

    // Process and store fetched certificates.
    let num_certs_fetched = response.certificates.len();
    process_certificates_helper(response, &state.tx_certificates_loopback).await?;
    state
        .metrics
        .certificate_waiter_num_certificates_processed
        .with_label_values(&[&committee.epoch().to_string()])
        .add(num_certs_fetched as i64);

    Ok(())
}

/// Fetches certificates from other primaries concurrently, with ~5 sec interval between each request.
/// Terminates after the 1st successful response is received.
#[instrument(level = "debug", skip_all)]
async fn fetch_certificates_helper(
    name: &PublicKey,
    network: &Arc<dyn PrimaryToPrimaryRpc>,
    committee: &Committee,
    request: FetchCertificatesRequest,
) -> FetchCertificatesResponse {
    trace!("Start sending fetch certificates requests");
    let request_interval = Duration::from_secs(5);
    let mut peers: Vec<NetworkPublicKey> = committee
        .others_primaries(name)
        .into_iter()
        .map(|(_, _, network_key)| network_key)
        .collect();
    loop {
        peers.shuffle(&mut ThreadRng::default());
        let mut fut = FuturesUnordered::new();
        for peer in peers.iter() {
            fut.push(network.fetch_certificates(peer, request.clone()));
            let mut interval = Box::pin(time::sleep(request_interval));
            tokio::select! {
                res = fut.next() => match res {
                    Some(Ok(resp)) => {
                        return resp;
                    }
                    Some(Err(e)) => {
                        debug!("Failed to fetch certificates: {e}");
                        // Issue request to another primary immediately.
                    }
                    None => {}
                },
                _ = &mut interval => {
                    debug!("fetch_certificates_helper: no response within timeout. Sending out a new fetch request.");
                }
            };
        }
    }
}

#[instrument(level = "debug", skip_all)]
async fn process_certificates_helper(
    response: FetchCertificatesResponse,
    tx_certificates_loopback: &Sender<CertificateLoopbackMessage>,
) -> DagResult<()> {
    trace!("Start sending fetched certificates to processing");
    if response.certificates.len() > MAX_CERTIFICATES_TO_FETCH {
        return Err(DagError::TooManyFetchedCertificatesReturned(
            response.certificates.len(),
            MAX_CERTIFICATES_TO_FETCH,
        ));
    }
    let (tx_done, rx_done) = oneshot::channel();
    if let Err(e) = tx_certificates_loopback
        .send(CertificateLoopbackMessage {
            certificates: response.certificates,
            done: tx_done,
        })
        .await
    {
        return Err(DagError::ClosedChannel(format!(
            "Failed to send fetched certificate to processing. tx_certificates_loopback error: {}",
            e
        )));
    }
    if let Err(e) = rx_done.await {
        return Err(DagError::ClosedChannel(format!(
            "Failed to wait for core to process loopback certificates: {}",
            e
        )));
    }
    trace!("Fetched certificates have finished processing");

    Ok(())
}
