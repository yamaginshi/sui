// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identi&fier: Apache-2.0

use anyhow::anyhow;
use clap::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::from_utf8;
use sui_sdk::crypto::{Keystore, SuiKeystore};
use sui_types::base_types::{decode_bytes_hex, encode_bytes_hex};
use sui_types::crypto::{KeypairTraits, PrivateKey, ToFromBytes};
use sui_types::sui_serde::{Base64, Encoding};
use sui_types::{
    base_types::SuiAddress,
    crypto::{get_key_pair, EncodeDecodeBase64, KeyPair},
};
use tracing::info;
use curve25519_parser::parse_openssl_25519_privkey;

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
#[clap(rename_all = "kebab-case")]
pub enum KeyToolCommand {
    /// Generate a new keypair
    Generate,
    Show {
        file: PathBuf,
    },
    /// Import armored format private key
    Import {
        file: PathBuf,
    },
    /// Extract components
    Unpack {
        keypair: KeyPair,
    },
    /// List all keys in the keystore
    List,
    /// Create signature using the sui keystore and provided data.
    Sign {
        #[clap(long, parse(try_from_str = decode_bytes_hex))]
        address: SuiAddress,
        #[clap(long)]
        data: String,
    },
}

impl KeyToolCommand {
    pub fn execute(self, mut keystore: SuiKeystore) -> Result<(), anyhow::Error> {
        match self {
            KeyToolCommand::Generate => {
                let (_address, keypair) = get_key_pair();

                let hex = encode_bytes_hex(keypair.public());
                let file_name = format!("{hex}.key");
                write_keypair_to_file(&keypair, &file_name)?;
                println!("Ed25519 key generated and saved to '{file_name}'");
            }

            KeyToolCommand::Show { file } => {
                let keypair = read_keypair_from_file(file)?;
                println!("Public Key: {}", encode_bytes_hex(keypair.public()));
            }
            KeyToolCommand::Import { file } => {
                let keypair = import_keypair_from_file(file)?;
                let address = keypair.public().into();
                keystore.add_key(address, keypair.copy())?;
                println!("Public Key: {}", encode_bytes_hex(keypair.public()));
            }
            KeyToolCommand::Unpack { keypair } => {
                store_and_print_keypair(keypair.public().into(), keypair)
            }
            KeyToolCommand::List => {
                println!(
                    " {0: ^42} | {1: ^45} ",
                    "Sui Address", "Public Key (Base64)"
                );
                println!("{}", ["-"; 91].join(""));
                for keypair in keystore.key_pairs() {
                    println!(
                        " {0: ^42} | {1: ^45} ",
                        Into::<SuiAddress>::into(keypair.public()),
                        Base64::encode(keypair.public().as_ref()),
                    );
                }
            }
            KeyToolCommand::Sign { address, data } => {
                info!("Data to sign : {}", data);
                info!("Address : {}", address);
                let message = Base64::decode(&data).map_err(|e| anyhow!(e))?;
                let signature = keystore.sign(&address, &message)?;
                // Separate pub key and signature string, signature and pub key are concatenated with an '@' symbol.
                let signature_string = format!("{:?}", signature);
                let sig_split = signature_string.split('@').collect::<Vec<_>>();
                let signature = sig_split
                    .first()
                    .ok_or_else(|| anyhow!("Error creating signature."))?;
                let pub_key = sig_split
                    .last()
                    .ok_or_else(|| anyhow!("Error creating signature."))?;
                info!("Public Key Base64: {}", pub_key);
                info!("Signature : {}", signature);
            }
        }

        Ok(())
    }
}

fn store_and_print_keypair(address: SuiAddress, keypair: KeyPair) {
    let path_str = format!("{}.key", address).to_lowercase();
    let path = Path::new(&path_str);
    let address = format!("{}", address);
    let kp = keypair.encode_base64();
    let kp = &kp[1..kp.len() - 1];
    let out_str = format!("address: {}\nkeypair: {}", address, kp);
    fs::write(path, out_str).unwrap();
    println!("Address and keypair written to {}", path.to_str().unwrap());
}

pub fn write_keypair_to_file<P: AsRef<std::path::Path>>(
    keypair: &KeyPair,
    path: P,
) -> anyhow::Result<()> {
    let contents = keypair.encode_base64();
    std::fs::write(path, contents)?;
    Ok(())
}

pub fn read_keypair_from_file<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<KeyPair> {
    let contents = std::fs::read_to_string(path)?;
    KeyPair::decode_base64(contents.as_str().trim()).map_err(|e| anyhow!(e))
}

pub fn import_keypair_from_file<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<KeyPair> {
    // let privdata = std::fs::read(path).unwrap();    
    // let privkey = osshkeys::KeyPair::from_keystr(from_utf8(privdata.as_slice()).unwrap(), None).unwrap();

    let keyfile = std::fs::read_to_string(path).unwrap();
    let keypair = osshkeys::KeyPair::from_keystr(&keyfile, None).unwrap();
    osshkeys::keys::ed25519::Ed25519KeyPair::ossl_pkey;
    let publickey = keypair.clone_public_key().unwrap();

    // use pem::parse;
    // let contents = std::fs::read_to_string(path)?;
    // let pem = parse(contents)?;

    // println!("pem: {:?}", pem.contents);
    // println!("pem s: {:?}", pem.contents.len());
    
    // // Decode content according to RFC8410 ASN.1 syntax
    // match parse_openssl_25519_privkey(&pem.contents) {
    //     Ok(secret) => {
    //         println!("static secret {:?}", secret.to_bytes());
    //         match PrivateKey::from_bytes(&secret.to_bytes()) {
    //             Ok(privkey) => Ok(KeyPair::from(privkey)),
    //             Err(e) => Err(anyhow!(e))
    //         }
    //     },
    //     Err(e) => Err(anyhow!(e))
    // }
}
