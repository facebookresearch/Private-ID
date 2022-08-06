//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use common::timer;
use crypto::eccipher::ECCipher;
use crypto::eccipher::ECRistrettoParallel;
use crypto::prelude::*;
use itertools::Itertools;

use super::compute_prefix_sum;
use super::elgamal_decrypt;
use super::elgamal_encrypt;
use super::gen_elgamal_keypair;
use super::load_data;
use super::unflatten_vec;
use super::writer_helper;
use super::ProtocolError;
use crate::suid_create::traits::SUIDCreateMergerProtocol;

// A very specific union find implementation that will only work when elements
// are in range [0, N) where N is a positive integer
// Key is the id of a node and value is (id of parent, size) where size is
// only valid for the root and keeps track of all nodes in the tree including
// the root
pub struct UnionFind {
    sets: HashMap<usize, (usize, usize)>,
}

impl UnionFind {
    pub fn new() -> UnionFind {
        UnionFind {
            // Value is (parent, size)
            sets: HashMap::<usize, (usize, usize)>::new(),
        }
    }

    pub fn make_group(&mut self, e: usize) {
        // Make sure it does not already exist
        assert!(!self.sets.contains_key(&e));

        self.sets.insert(e, (e, 1));
    }

    // Recursive version
    pub fn find_r(&mut self, p: usize) -> usize {
        // Make sure it already exists
        assert!(self.sets.contains_key(&p));

        let &(parent, size) = self.sets.get(&p).unwrap();

        let leader = {
            if parent != p {
                self.find(parent)
            } else {
                parent
            }
        };

        // Path compression
        self.sets.insert(p, (leader, size));
        leader
    }

    pub fn path_to_leader(&self, p: usize) -> (usize, Vec<usize>) {
        // Make sure it already exists
        assert!(self.sets.contains_key(&p));

        // Only need to store all nodes on path to root
        let mut path = Vec::<usize>::new();
        let mut cur = p;
        let mut node = *self.sets.get(&cur).unwrap();
        path.push(cur);

        // node.0 is parent
        while node.0 != cur {
            cur = node.0;
            node = *self.sets.get(&cur).unwrap();
            path.push(cur);
        }

        let leader = path.pop().unwrap();
        (leader, path)
    }

    // Non recursive version
    pub fn find(&mut self, p: usize) -> usize {
        let (leader, path) = self.path_to_leader(p);

        // Path compression
        // Note that size is unchanged since nodes are not root nodes
        for t in path.iter() {
            let x = self.sets.get_mut(t).unwrap();
            x.0 = leader;
        }

        leader
    }

    pub fn union(&mut self, p: usize, q: usize) -> usize {
        let a = self.find(p);
        let b = self.find(q);

        if a != b {
            let &(a_parent, a_size) = self.sets.get(&a).unwrap();
            let &(b_parent, b_size) = self.sets.get(&b).unwrap();

            if a_size > b_size {
                self.sets.insert(a, (a_parent, a_size + b_size));
                self.sets.insert(b, (a, b_size));
                a
            } else {
                self.sets.insert(a, (b, a_size));
                self.sets.insert(b, (b_parent, a_size + b_size));
                b
            }
        } else {
            // Either a or b will work since they are equal
            a
        }
    }
}

impl Default for UnionFind {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SUIDCreateMerger {
    keypair_m: (Scalar, TPoint),
    keypair_reuse: (Scalar, TPoint),
    sharer_pub_key_reuse: Arc<RwLock<TPoint>>,
    ec_cipher: ECRistrettoParallel,
    // TODO: consider using dyn pid::crypto::ECCipher trait?
    plaintext: Arc<RwLock<Vec<Vec<String>>>>,

    from_shuffler: Arc<RwLock<(TPayload, TPayload, Vec<usize>)>>,
    to_shuffler: Arc<RwLock<(TPayload, TPayload)>>,

    suids: Arc<RwLock<(TPayload, TPayload)>>,
}

impl SUIDCreateMerger {
    pub fn new() -> SUIDCreateMerger {
        SUIDCreateMerger {
            keypair_m: gen_elgamal_keypair(),
            keypair_reuse: gen_elgamal_keypair(),
            sharer_pub_key_reuse: Arc::new(RwLock::default()),
            ec_cipher: ECRistrettoParallel::default(),
            plaintext: Arc::new(RwLock::default()),
            from_shuffler: Arc::new(RwLock::default()),
            to_shuffler: Arc::new(RwLock::default()),
            suids: Arc::new(RwLock::default()),
        }
    }

    pub fn load_data(&self, path: &str, input_with_headers: bool) -> Result<(), ProtocolError> {
        match self.plaintext.clone().write() {
            Ok(mut p_data) => {
                p_data.clear();
                let d = load_data(path, input_with_headers);
                p_data.extend(d);
                Ok(())
            }
            _ => {
                error!("Unable to load data");
                Err(ProtocolError::ErrorIO("unable to load data".to_string()))
            }
        }
    }
}

impl Default for SUIDCreateMerger {
    fn default() -> Self {
        Self::new()
    }
}

impl SUIDCreateMergerProtocol for SUIDCreateMerger {
    fn get_public_key_m(&self) -> TPayload {
        let x = vec![self.keypair_m.1];
        self.ec_cipher.to_bytes(&x)
    }

    fn set_sharer_public_key_reuse(&self, p_key: TPayload) -> Result<(), ProtocolError> {
        match self.sharer_pub_key_reuse.clone().write() {
            Ok(mut sharer_pub_key_r) => {
                // Only one key
                assert_eq!(p_key.len(), 1);
                *sharer_pub_key_r = (self.ec_cipher.to_points(&p_key))[0];
                Ok(())
            }
            _ => {
                error!("Unable to write public key");
                Err(ProtocolError::ErrorDataWrite(
                    "unable to write public key".to_string(),
                ))
            }
        }
    }

    fn set_encrypted_keys_to_merge(
        &self,
        mut c1_buf: TPayload,
        mut c2_buf: TPayload,
        mut psum: Vec<usize>,
    ) -> Result<(), ProtocolError> {
        match self.from_shuffler.clone().write() {
            Ok(mut data) => {
                data.0.clear();
                data.0.append(&mut c1_buf);

                data.1.clear();
                data.1.append(&mut c2_buf);

                data.2.clear();
                data.2.append(&mut psum);

                Ok(())
            }
            _ => {
                error!("Cannot write data from Shuffler:");
                Err(ProtocolError::ErrorDataWrite(
                    "cannot write data from Shuffler".to_string(),
                ))
            }
        }
    }

    fn get_party_merger_keys(&self) -> Result<TPayload, ProtocolError> {
        match self.plaintext.clone().read() {
            Ok(pdata) => {
                let t = timer::Timer::new_silent("party merger keys");

                let mut offset = {
                    let lengths = pdata.iter().map(|v| v.len()).collect::<Vec<usize>>();
                    compute_prefix_sum(&lengths)
                        .iter()
                        .map(|&o| ByteBuffer {
                            buffer: (o as u64).to_le_bytes().to_vec(),
                        })
                        .collect::<Vec<_>>()
                };

                let (c1_flat, c2_flat) = {
                    let d_f = {
                        let x = pdata.clone().into_iter().flatten().collect::<Vec<_>>();
                        self.ec_cipher.hash(x.as_slice())
                    };

                    elgamal_encrypt(d_f, &self.keypair_m.1)
                };

                let offset_len = offset.len();

                let mut buf = self.ec_cipher.to_bytes(&c1_flat);
                buf.extend(self.ec_cipher.to_bytes(&c2_flat));

                let data_len = buf.len();

                buf.append(&mut offset);

                buf.push(ByteBuffer {
                    buffer: (data_len as u64).to_le_bytes().to_vec(),
                });
                buf.push(ByteBuffer {
                    buffer: (offset_len as u64).to_le_bytes().to_vec(),
                });

                t.qps("encryption", c1_flat.len());

                Ok(buf)
            }
            _ => {
                error!("Unable to encrypt data for party");
                Err(ProtocolError::ErrorEncryption(
                    "unable to encrypt data for party".to_string(),
                ))
            }
        }
    }

    fn calculate_suids(&self) -> Result<(), ProtocolError> {
        match (
            self.sharer_pub_key_reuse.clone().read(),
            self.from_shuffler.clone().read(),
            self.to_shuffler.clone().write(),
        ) {
            (Ok(sharer_pub_key_reuse), Ok(from_s), Ok(mut to_s)) => {
                // Decrypt and unflatten keys
                let keys = {
                    // El Gamal decrypt
                    let m = elgamal_decrypt(
                        self.ec_cipher.to_points(&from_s.0),
                        self.ec_cipher.to_points(&from_s.1),
                        self.keypair_m.0,
                    );

                    unflatten_vec(&m, &from_s.2)
                };

                // Generate sets to find SUID
                let mut s_map = HashMap::<Vec<u8>, Vec<usize>>::new();

                // We map every entry in keys to a hash table. Each entry is
                // a vector. We hash each entry in this vector to a hash
                // table entry. The value is the index of this entry. In
                // case of a collision we add the index. Thus we end up with
                // a hashmap of vectors of indices.
                // In subsequent steps we will use the Union Find algorithm
                // to merge intersecting sets
                for (i, e_o) in keys.iter().enumerate() {
                    for e_i in e_o.iter() {
                        let x = e_i.compress().to_bytes().to_vec();
                        let v = s_map.entry(x).or_insert_with(Vec::<usize>::new);
                        v.push(i);
                    }
                }

                // Merge sets created above with union find
                let mut part = UnionFind::new();

                // Make singleton set in union find data structure
                let max_index = keys.len();
                for i in 0..max_index {
                    part.make_group(i);
                }

                // Merge singletons to create sets that are disjoint
                // 1. Iterate over keys in hashmap and retrieve corresponding
                //    vector of indices. By construction this vector has set
                //    property ie all indices within a vector are unique
                // 2. For each index in list, find the root of the tree containing
                //    it in the Union Find data structure. These roots are
                //    collected in a vector called leaders
                // 3. Iterate over leaders to merge the trees corresponding to
                //    the leaders into one tree
                for key in s_map.keys() {
                    let list = s_map.get(key).unwrap();
                    let mut leaders = Vec::<usize>::new();

                    for &x in list.iter() {
                        leaders.push(part.find(x));
                    }

                    // All elements in this list should be in one union
                    if leaders.len() > 1 {
                        for i in (1..leaders.len()).rev() {
                            leaders[0] = part.union(leaders[i], leaders[0]);
                        }
                    }
                }

                // Find leader for indices and project to Ristretto point
                // Note path_to_leader has no path compression - this will likely
                // help parallelization later.
                // Here we convert leader to string to convert it to a RistrettoPoint
                let leaders = {
                    let x = (0..max_index)
                        .collect::<Vec<usize>>()
                        .iter()
                        .map(|&i| {
                            let (leader, _) = part.path_to_leader(i);
                            println!("SHUBHO Debug: leader {}", leader);
                            leader.to_string()
                        })
                        .collect::<Vec<_>>();
                    self.ec_cipher.hash(&x)
                };

                // 2 out of 2 threshold El Gamal - so keys need to be added
                let p_key = self.keypair_reuse.1 + (*sharer_pub_key_reuse);
                let (mut c1_buf, mut c2_buf) = {
                    let (c1, c2) = elgamal_encrypt(leaders, &p_key);
                    (self.ec_cipher.to_bytes(&c1), self.ec_cipher.to_bytes(&c2))
                };

                to_s.0.clear();
                to_s.1.clear();

                to_s.0.append(&mut c1_buf);
                to_s.1.append(&mut c2_buf);
                Ok(())
            }
            _ => {
                error!("Cannot calculate SUID ");
                Err(ProtocolError::ErrorCalculateSUID(
                    "cannot calculate SUID".to_string(),
                ))
            }
        }
    }

    fn get_suids(&self) -> Result<TPayload, ProtocolError> {
        match self.to_shuffler.clone().write() {
            Ok(mut to_s) => {
                let mut data = TPayload::new();
                assert_eq!(to_s.0.len(), to_s.1.len());
                data.append(&mut to_s.0);
                data.append(&mut to_s.1);
                Ok(data)
            }
            _ => {
                error!("Cannot load SUIDs ");
                Err(ProtocolError::ErrorDataRead(
                    "cannot read SUIDs".to_string(),
                ))
            }
        }
    }

    fn set_suids_for_party_merger(&self, mut data: TPayload) -> Result<(), ProtocolError> {
        match self.suids.clone().write() {
            Ok(mut suids) => {
                assert_eq!(data.len() % 2, 0);
                let data_len = data.len();

                suids.1.clear();
                suids.1.extend(data.drain((data_len / 2)..));

                suids.0.clear();
                suids.0.append(&mut data);
                Ok(())
            }
            _ => {
                error!("Cannot write SUID for party");
                Err(ProtocolError::ErrorDataWrite(
                    "cannot write SUID for party".to_string(),
                ))
            }
        }
    }

    fn print_suids_data(&self) {
        match (self.suids.clone().read(), self.plaintext.clone().read()) {
            (Ok(suids), Ok(data)) => {
                let s = suids
                    .0
                    .iter()
                    .zip_eq(suids.1.iter())
                    .map(|(x1, x2)| (x1.clone().to_string(), x2.clone().to_string()))
                    .collect::<Vec<_>>();
                writer_helper(&s, &data, None);
            }
            _ => panic!("Cannot print SUIDs"),
        }
    }

    fn save_suids_data(&self, path: &str) -> Result<(), ProtocolError> {
        match (self.suids.clone().read(), self.plaintext.clone().read()) {
            (Ok(suids), Ok(data)) => {
                let s = suids
                    .0
                    .iter()
                    .zip_eq(suids.1.iter())
                    .map(|(x1, x2)| (x1.clone().to_string(), x2.clone().to_string()))
                    .collect::<Vec<_>>();
                writer_helper(&s, &data, Some(path.to_string()));
                Ok(())
            }
            _ => {
                error!("Unable to write SUIDs to file");
                Err(ProtocolError::ErrorIO(
                    "Unable to write SUIDs to file".to_string(),
                ))
            }
        }
    }
}
