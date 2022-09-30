// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use bip32::DerivationPath;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use signature::Signer;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::fmt::{Display, Formatter};
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use sui_types::base_types::SuiAddress;
use sui_types::crypto::{
    derive_key_pair_from_path, get_key_pair_from_rng, EncodeDecodeBase64, PublicKey, Signature,
    SignatureScheme, SuiKeyPair,
};
use sui_types::intent::{ChainId, Intent};

// #[derive(Serialize, Deserialize)]
#[non_exhaustive]
// This will work on user signatures, but not suitable for authority signatures.1
pub enum SuiKeyStore {
    File(FileBasedKeystore),
    InMem(InMemKeystore),
}

pub trait AccountKeystore: Send + Sync {
    fn sign(&self, address: &SuiAddress, msg: &impl Serialize, intent: Intent) -> Result<Signature, signature::Error>;
    fn add_key(&mut self, keypair: SuiKeyPair) -> Result<(), anyhow::Error>;
    fn keys(&self) -> Vec<PublicKey>;
    fn get_key(&self, address: &SuiAddress) -> Option<SuiKeyPair>;
    fn generate_new_key(&mut self, key_scheme: SignatureScheme, derivation_path: Option<DerivationPath>) -> Result<(SuiAddress, String, SignatureScheme), anyhow::Error> {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        match derive_key_pair_from_path(
            Seed::new(&mnemonic, "").as_bytes(),
            derivation_path,
            &key_scheme,
        ) {
            Ok((address, keypair)) => {
                self.add_key(keypair)?;
                Ok((address, mnemonic.phrase().to_string(), key_scheme))
            }
            Err(e) => Err(anyhow!("error generating key {:?}", e)),
        }
    }

    fn import_from_mnemonic(
        &mut self,
        phrase: &str,
        key_scheme: SignatureScheme,
        derivation_path: Option<DerivationPath>,
    ) -> Result<SuiAddress, anyhow::Error> {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
            .map_err(|e| anyhow::anyhow!("Invalid mnemonic phrase: {:?}", e))?;
        let seed = Seed::new(&mnemonic, "");
        match derive_key_pair_from_path(seed.as_bytes(), derivation_path, &key_scheme) {
            Ok((address, kp)) => {
                self.keystore.add_key(kp)?;
                Ok(address)
            }
            Err(e) => Err(anyhow!("error getting keypair {:?}", e)),
        }
    }
}

// impl Display for SuiKeyStore {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         let mut writer = String::new();
//         match self {
//             SuiKeyStore::File(path) => {
//                 writeln!(writer, "Keystore Type : File")?;
//                 write!(writer, "Keystore Path : {:?}", path)?;
//                 write!(f, "{}", writer)
//             }
//             SuiKeyStore::InMem(_) => {
//                 writeln!(writer, "Keystore Type : InMem")?;
//                 write!(f, "{}", writer)
//             }
//         }
//     }
// }

#[derive(Default)]
pub struct FileBasedKeystore {
    keys: BTreeMap<SuiAddress, SuiKeyPair>,
    path: Option<PathBuf>,
    chain_id: ChainId
}

impl AccountKeystore for FileBasedKeystore {
    fn sign(&self, address: &SuiAddress, msg: &impl Serialize, intent: Intent) -> Result<Signature, signature::Error> {
        Signature::new_secure(&msg, intent.with_chain_id(self.chain_id), self.keys
            .get(address)
            .ok_or_else(|| {
                signature::Error::from_source(format!("Cannot find key for address: [{address}]"))
            })?)
        // self.keys
        //     .get(address)
        //     .ok_or_else(|| {
        //         signature::Error::from_source(format!("Cannot find key for address: [{address}]"))
        //     })?
        //     .try_sign(msg)
    }

    fn add_key(&mut self, keypair: SuiKeyPair) -> Result<(), anyhow::Error> {
        let address: SuiAddress = (&keypair.public()).into();
        self.keys.insert(address, keypair);
        self.save()?;
        Ok(())
    }

    fn keys(&self) -> Vec<PublicKey> {
        self.keys.values().map(|key| key.public()).collect()
    }

    fn get_key(&self, address: &SuiAddress) -> Result<SuiKeyPair, Error> {
        match self.keys.get(address) {
            Some(key) => Ok(key.clone()),
            None => Err(Error::KeyNotFound(address.to_string())),
        }
    }
}

impl FileBasedKeystore {
    pub fn load_or_create(path: &Path, chain_id: ChainId) -> Result<Self, anyhow::Error> {
        let keys = if path.exists() {
            let reader = BufReader::new(File::open(path)?);
            let kp_strings: Vec<String> = serde_json::from_reader(reader)?;
            kp_strings
                .iter()
                .map(|kpstr| {
                    let key = SuiKeyPair::decode_base64(kpstr);
                    key.map(|k| (Into::<SuiAddress>::into(&k.public()), k))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()
                .map_err(|e| anyhow::anyhow!("Invalid Keypair file {:#?} {:?}", e, path))?
        } else {
            BTreeMap::new()
        };

        Ok(Self {
            keys,
            path: Some(path.to_path_buf()),
            chain_id
        })
    }

    // pub fn set_path(&mut self, path: &Path) {
    //     self.path = Some(path.to_path_buf());
    // }

    // pub fn set_chain_id(&mut self, chain_id: &ChainId) {
    //     self.chain_id = chain_id;
    // }

    pub fn save(&self) -> Result<(), anyhow::Error> {
        if let Some(path) = &self.path {
            let store = serde_json::to_string_pretty(
                &self
                    .keys
                    .values()
                    .map(EncodeDecodeBase64::encode_base64)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            fs::write(path, store)?
        }
        Ok(())
    }

    // pub fn key_pairs(&self) -> Vec<&SuiKeyPair> {
    //     self.keys.values().collect()
    // }
}

// pub struct SuiKeystore {
//     keystore: Box<dyn AccountKeystore>,
//     chain_id: ChainId,
// }

// impl SuiKeystore {
//     fn from<S: AccountKeystore + 'static>(keystore: S, chain_id: &ChainId) -> Self {
//         Self {
//             keystore: Box::new(keystore),
//             chain_id: *chain_id,
//         }
//     }

//     pub fn add_key(&mut self, keypair: SuiKeyPair) -> Result<(), anyhow::Error> {
//         self.keystore.add_key(keypair)
//     }

//     pub fn generate_new_key(
//         &mut self,
//         key_scheme: SignatureScheme,
//         derivation_path: Option<DerivationPath>,
//     ) -> Result<(SuiAddress, String, SignatureScheme), anyhow::Error> {
//         let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
//         match derive_key_pair_from_path(
//             Seed::new(&mnemonic, "").as_bytes(),
//             derivation_path,
//             &key_scheme,
//         ) {
//             Ok((address, keypair)) => {
//                 self.add_key(keypair)?;
//                 Ok((address, mnemonic.phrase().to_string(), key_scheme))
//             }
//             Err(e) => Err(anyhow!("error generating key {:?}", e)),
//         }
//     }

//     pub fn keys(&self) -> Vec<PublicKey> {
//         self.keystore.keys()
//     }

//     pub fn addresses(&self) -> Vec<SuiAddress> {
//         self.keys().iter().map(|k| k.into()).collect()
//     }

//     pub fn import_from_mnemonic(
//         &mut self,
//         phrase: &str,
//         key_scheme: SignatureScheme,
//         derivation_path: Option<DerivationPath>,
//     ) -> Result<SuiAddress, anyhow::Error> {
//         let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
//             .map_err(|e| anyhow::anyhow!("Invalid mnemonic phrase: {:?}", e))?;
//         let seed = Seed::new(&mnemonic, "");
//         match derive_key_pair_from_path(seed.as_bytes(), derivation_path, &key_scheme) {
//             Ok((address, kp)) => {
//                 self.keystore.add_key(kp)?;
//                 Ok(address)
//             }
//             Err(e) => Err(anyhow!("error getting keypair {:?}", e)),
//         }
//     }

//     pub fn sign(&self, address: &SuiAddress, msg: &impl Serialize) -> Result<Signature, signature::Error> {
//         let intent = Intent::default().with_chain_id(self.chain_id);
//         println!("intent: {:?}", intent);
//         self.keystore.sign(address, msg, intent)
//     }
// }
#[derive(Default)]
struct InMemKeystore {
    keys: BTreeMap<SuiAddress, SuiKeyPair>,
    chain_id: ChainId,
}

impl InMemKeystore {
    pub fn new(initial_key_number: usize) -> Self {
        let mut rng = StdRng::from_seed([0; 32]);
        let keys = (0..initial_key_number)
            .map(|_| get_key_pair_from_rng(&mut rng))
            .map(|(ad, k)| (ad, SuiKeyPair::Ed25519SuiKeyPair(k)))
            .collect::<BTreeMap<SuiAddress, SuiKeyPair>>();

        Self { keys, chain_id: ChainId::default() }
    }
}

impl AccountKeystore for InMemKeystore {
    fn sign(&self, address: &SuiAddress, msg: &impl Serialize, intent: Intent) -> Result<Signature, signature::Error> {
        self.keys
            .get(address)
            .ok_or_else(|| {
                signature::Error::from_source(format!("Cannot find key for address: [{address}]"))
            })?
            .try_sign(msg)
    }

    fn add_key(&mut self, keypair: SuiKeyPair) -> Result<(), anyhow::Error> {
        let address: SuiAddress = (&keypair.public()).into();
        self.keys.insert(address, keypair);
        Ok(())
    }

    fn keys(&self) -> Vec<PublicKey> {
        self.keys.values().map(|key| key.public()).collect()
    }
}
