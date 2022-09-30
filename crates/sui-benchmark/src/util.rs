// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use sui_sdk::crypto::FileBasedKeystore;
use sui_types::{
    base_types::SuiAddress,
    crypto::{AccountKeyPair, EncodeDecodeBase64, SuiKeyPair},
};

use std::path::PathBuf;

pub fn get_ed25519_keypair_from_keystore(
    keystore_path: PathBuf,
    requested_address: &SuiAddress,
) -> Result<AccountKeyPair> {
    let keystore = SuiKeyStore::File(FileBasedKeystore::load_or_create(&keystore_path, ChainId::default())?);
    match keystore.get_key(requested_address)? {
        SuiKeyPair::Ed25519SuiKeyPair(kp) => Ok(kp),
        _ => Err(anyhow!("Key not found")),
    }
}
