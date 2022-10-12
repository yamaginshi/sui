// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::metrics::PrimaryMetrics;
use config::Committee;
use crypto::{NetworkPublicKey, PublicKey};
use fastcrypto::Hash;
use futures::{future::try_join_all, stream::FuturesUnordered, StreamExt};
use network::PrimaryToPrimaryRpc;
use rand::{rngs::ThreadRng, seq::SliceRandom, Rng};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use storage::CertificateStore;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
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

/// When there are certificates missing from local store, e.g. discovered when a received certificate has missing parents,
/// CertificateWaiter is responsible for fetching missing certificates from other primaries.
pub struct CertificateWaiter {
    /// Identity of the current authority.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// Network client to fetch certificates from other primaries.
    network: Arc<dyn PrimaryToPrimaryRpc>,
    /// The persistent storage.
    certificate_store: CertificateStore,
    /// Watch channel notifying of epoch changes, it is only used for cleanup.
    rx_reconfigure: watch::Receiver<ReconfigureNotification>,
    /// Receives certificates with missing parents from the `Synchronizer`.
    rx_certificate_waiter: Receiver<Certificate>,
    /// Kicks start a certificate fetching task, after receiving a certificate with missing parents.
    /// Sending to this channel should use `try_send()`, because only one pending message is needed.
    tx_kick_from_cert: mpsc::Sender<()>,
    rx_kick_from_cert: mpsc::Receiver<()>,
    /// Kicks start a certificate fetching task, after finishing the current fetch task.
    /// Sending to this channel should use `send()`. When a fetch task is finishing, the channel should be empty.
    /// The purpose is to ensure a new fetch task is started after the previous fetch task ends.
    tx_kick_from_fetch: mpsc::Sender<()>,
    rx_kick_from_fetch: mpsc::Receiver<()>,
    /// Loops fetched certificates back to the core. Certificates are ensured to have all parents.
    tx_certificates_loopback: Sender<Certificate>,
    /// Map of validator to target rounds that local store must catch up to.
    target: BTreeMap<PublicKey, Round>,
    /// Keeps the handle to the inflight fetch certificates task.
    fetch_certificates_task: Option<JoinHandle<()>>,
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
        tx_certificates_loopback: Sender<Certificate>,
        metrics: Arc<PrimaryMetrics>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let (tx_kick_from_cert, rx_kick_from_cert) = mpsc::channel(1);
            let (tx_kick_from_fetch, rx_kick_from_fetch) = mpsc::channel(1);
            Self {
                name,
                committee,
                network,
                certificate_store,
                rx_reconfigure,
                rx_certificate_waiter,
                tx_kick_from_cert,
                rx_kick_from_cert,
                tx_kick_from_fetch,
                rx_kick_from_fetch,
                tx_certificates_loopback,
                target: BTreeMap::new(),
                fetch_certificates_task: None,
                metrics,
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
                    // Unnecessary to validate the header and certificate further, since it has already been validated.

                    if let Some(r) = self.target.get(&header.author) {
                        if header.round <= *r {
                            // Ignore fetch request when we already need to sync to a later certificate.
                            continue;
                        }
                    }

                    // The header should have been verified as part of the certificate.
                    match self.certificate_store.last_round_number(&header.author) {
                        Ok(Some(r)) => {
                            if r >= header.round {
                                // Ignore fetch request. Possibly the certificate was processed while the message is in the queue.
                                continue;
                            }
                            // Otherwise, continue to update fetch target.
                        },
                        Ok(None) => {
                            // The authority has no update since genesis. Continue to update fetch target.
                        },
                        Err(e) => {
                            warn!("Failed to read latest round for {}: {}", header.author, e);
                            // Storage error.
                            continue;
                        },
                    };

                    // Update the target round for the authority.
                    *self.target.entry(header.author.clone()).or_default() = header.round;

                    // Ok to ignore kick when tx_kick_from_cert channel already has a message.
                    let _ = self.tx_kick_from_cert.try_send(());
                },
                Some(_) = self.rx_kick_from_cert.recv() => {
                    // Only proceeds to fetch certificates if there is no running fetch task.
                    if let Some(handle) = &self.fetch_certificates_task {
                        if !handle.is_finished() {
                            continue;
                        }
                    }
                    self.kick();
                },
                Some(_) = self.rx_kick_from_fetch.recv() => {
                    // The fetch task can still be running here, after sending the kick message but before finishing.
                    // But a new kick is always started regardless.
                    self.kick();
                }
                result = self.rx_reconfigure.changed() => {
                    result.expect("Committee channel dropped");
                    let message = self.rx_reconfigure.borrow_and_update().clone();
                    match message {
                        ReconfigureNotification::NewEpoch(committee) => {
                            self.committee = committee;
                            self.target.clear();
                        },
                        ReconfigureNotification::UpdateCommittee(committee) => {
                            self.committee = committee;
                            // There should be no committee membership change so self.target does not need to be updated.
                        },
                        ReconfigureNotification::Shutdown => return
                    }
                    debug!("Committee updated to {}", self.committee);
                }
            }
        }
    }

    // Starts a task to fetch missing certificates from other primaries.
    // A call to kick() can be triggered by a certificate with missing parents or the end of a fetch task.
    // Each iterations of kick() updates the target rounds, and iterations will continue until there is no more target rounds to catch up to.
    #[allow(clippy::mutable_key_type)]
    fn kick(&mut self) {
        let progression = match self.read_round_progression() {
            Ok(progression) => progression,
            Err(e) => {
                warn!("Failed to read rounds per authority from the certificate store: {e}");
                return;
            }
        };
        self.target.retain(|origin, target_round| {
            let current_round = progression.get(origin).unwrap();
            // Drop sync target when cert store already has an equal or higher round for the origin.
            current_round < target_round
        });
        if self.target.is_empty() {
            trace!("Certificates have caught up. Skip fetching.");
            return;
        }

        let handle = self.create_fetch_task(progression);
        let epoch = self.committee.epoch();
        let metrics = self.metrics.clone();
        let tx_kick_from_fetch = self.tx_kick_from_fetch.clone();

        self.fetch_certificates_task = Some(tokio::task::spawn(async move {
            metrics
                .certificate_waiter_inflight_fetch
                .with_label_values(&[&epoch.to_string()])
                .set(1);
            metrics
                .certificate_waiter_fetch_attempts
                .with_label_values(&[&epoch.to_string()])
                .inc();

            let now = Instant::now();
            match handle.await {
                Ok(_) => {
                    debug!("Finished task to fetch certificates successfully");
                }
                Err(e) => {
                    debug!("Finished task to fetch certificates with error: {e}");
                }
            };

            metrics
                .certificate_waiter_op_latency
                .with_label_values(&[&epoch.to_string()])
                .observe(now.elapsed().as_secs_f64());
            metrics
                .certificate_waiter_inflight_fetch
                .with_label_values(&[&epoch.to_string()])
                .set(0);

            // Schedule another fetch task to check progression and fetch again if needed.
            let _ = tx_kick_from_fetch.send(()).await;
        }));

        debug!("Started task to fetch certificates");
    }

    #[allow(clippy::mutable_key_type)]
    fn create_fetch_task(
        &mut self,
        progression: BTreeMap<PublicKey, Round>,
    ) -> JoinHandle<DagResult<()>> {
        let name = self.name.clone();
        let network = self.network.clone();
        let committee = self.committee.clone();
        let certificate_store = self.certificate_store.clone();
        let tx_certificates_loopback = self.tx_certificates_loopback.clone();
        let metrics = self.metrics.clone();

        tokio::task::spawn(async move {
            // Send request to fetch certificates.
            let request = FetchCertificatesRequest {
                progression: progression.into_iter().collect(),
                max_items: MAX_CERTIFICATES_TO_FETCH,
            };
            let response = fetch_certificates_helper(
                name.clone(),
                network.clone(),
                committee.clone(),
                request.clone(),
            )
            .await;

            // Process and store fetched certificates.
            store_certificates_helper(
                response,
                committee,
                &certificate_store,
                tx_certificates_loopback,
                metrics,
            )
            .await?;

            Ok(())
        })
    }

    #[allow(clippy::mutable_key_type)]
    fn read_round_progression(&self) -> DagResult<BTreeMap<PublicKey, Round>> {
        let mut progression = BTreeMap::new();
        for (name, _) in self.committee.authorities() {
            // Last round is 0 (genesis) when authority is not found in store.
            let last_round = self.certificate_store.last_round_number(name)?.unwrap_or(0);
            progression.insert(name.clone(), last_round);
        }
        Ok(progression)
    }
}

/// Fetches certificates from other primaries concurrently, with ~5 sec interval between each request.
/// Terminates after the 1st successful response is received.
#[instrument(level = "debug", skip_all)]
async fn fetch_certificates_helper(
    name: PublicKey,
    network: Arc<dyn PrimaryToPrimaryRpc>,
    committee: Committee,
    request: FetchCertificatesRequest,
) -> FetchCertificatesResponse {
    trace!("Start sending fetch certificates requests");
    let request_interval = Duration::from_secs(5);
    let mut peers: Vec<NetworkPublicKey> = committee
        .others_primaries(&name)
        .into_iter()
        .map(|(_, _, network_key)| network_key)
        .collect();
    loop {
        peers.shuffle(&mut ThreadRng::default());
        let mut fut = FuturesUnordered::new();
        for peer in peers.iter() {
            fut.push(network.fetch_certificates(peer, request.clone()));
            let mut interval = Box::pin(time::sleep(
                request_interval + Duration::from_millis(ThreadRng::default().gen_range(0..1000)),
            ));
            tokio::select! {
                res = fut.next() => match res {
                    Some(Ok(resp)) => {
                        return resp;
                    }
                    Some(Err(e)) => {
                        debug!("Failed to fetch certificates: {e}");
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
async fn store_certificates_helper(
    response: FetchCertificatesResponse,
    committee: Committee,
    certificate_store: &CertificateStore,
    tx_certificates_loopback: Sender<Certificate>,
    metrics: Arc<PrimaryMetrics>,
) -> DagResult<()> {
    trace!("Start sending fetched certificates to processing");
    let mut waiters = Vec::new();
    for certificate in response.certificates {
        if waiters.len() == MAX_CERTIFICATES_TO_FETCH {
            break;
        }
        waiters.push(certificate_store.notify_read(certificate.digest()));
        // NOTE: currently this relies on core to verify and sanitize the certificate,
        // and making sure all parents exist in storage. In future we may want to move the verification here.
        if tx_certificates_loopback.send(certificate).await.is_err() {
            warn!("Failed to send fetched certificate to processing");
            return Err(DagError::ClosedChannel(
                "tx_certificates_loopback".to_string(),
            ));
        }
    }

    // TODO: wait on a signal from core instead, without timeout.
    let waiters_len = waiters.len();
    let mut timeout = Box::pin(time::sleep(Duration::from_secs(30)));
    let epoch = committee.epoch();
    tokio::select! {
        result = try_join_all(waiters) => {
            if let Err(e) = result {
                warn!("Failed to wait for certificates written to store: {e}");
                return Err(DagError::from(e));
            }
            metrics.certificate_waiter_num_certificates_processed
            .with_label_values(&[&epoch.to_string()]).add(waiters_len as i64);
            trace!("Done writing {} fetched certificates", waiters_len);
        },
        _ = &mut timeout => {
            metrics.certificate_waiter_processing_timed_out
            .with_label_values(&[&epoch.to_string()]).inc();
            warn!("Processing fetched certificates timed out");
        }
    };

    Ok(())
}
