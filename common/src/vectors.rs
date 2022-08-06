//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::hash::Hash;

use rayon::prelude::ParallelSliceMut;

/// set subtract a - b. Returns all elements of a that are not in b
/// returned elements of a may not be unique
pub fn subtract_set<T>(a: &[T], b: &[T]) -> Vec<T>
where
    T: Hash + Clone + Eq,
{
    let mut s: HashSet<T> = HashSet::with_capacity(b.len());
    b.iter().for_each(|z| {
        s.insert(z.clone());
    });

    a.iter()
        .filter(|x| !s.contains(x))
        .cloned()
        .collect::<Vec<T>>()
}

/// Mask of 0 or 1 if item in is in b
pub fn vec_intersection_mask<T>(a: &[T], b: &[T]) -> Vec<bool>
where
    T: Hash + Clone + Eq,
{
    let mut s: HashSet<T> = HashSet::with_capacity(b.len());
    b.iter().for_each(|z| {
        s.insert(z.clone());
    });
    a.iter().map(|e| s.contains(e)).collect::<Vec<bool>>()
}

/// Returns a vector with indices for which the corresponding element
/// is set in the mask
pub fn mask_to_indices(mask: &[bool]) -> Vec<usize> {
    let mut res: Vec<usize> = Vec::with_capacity(mask.len());

    mask.iter().enumerate().for_each(|(i, e)| {
        if *e {
            res.push(i)
        }
    });
    res
}

/// Returns a vector with elements for which the corresponding element
/// in mask is set to true
pub fn apply_mask<T>(mask: &[bool], v: &[T]) -> Vec<T>
where
    T: Clone,
{
    assert_eq!(
        mask.len(),
        v.len(),
        "masked vectors should have the same shape"
    );
    v.iter()
        .zip(mask.iter())
        .filter(|(_, &b)| b)
        .map(|(e, &_)| e.clone())
        .collect::<Vec<T>>()
}

/// De-duplicates the slice in place
/// the vector becomes sorted.
///
/// The alg switches to parallel implementation for
/// sizes larger than 1M records when `allow_parallel` flag is set
///
/// ## Example
///
/// ```
/// use common::vectors;
///
/// let mut v = vec![1, 2, 3, 1, 1];
/// vectors::dedup_unstable(&mut v, true);
///
/// assert_eq!(v, vec![1, 2, 3]);
/// ```
pub fn dedup_unstable<T>(v: &mut Vec<T>, allow_parallel: bool)
where
    T: Ord + Send,
{
    const LARGE_INPUT: usize = 1000000;
    if !allow_parallel || v.len() < LARGE_INPUT {
        debug!("Using sequential implementation of the vector");
        v.sort_unstable()
    } else {
        debug!("Using paerallel implementation of the vector");
        v.par_sort_unstable();
    }
    v.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vec_intersection() {
        let a = vec![1, 2, 3];
        let b = vec![2, 3];
        let c = subtract_set(&a, &b);
        let c1 = subtract_set(&a, &a);
        let c2 = subtract_set(&a, &vec![]);

        assert_eq!(c1.len(), 0);
        assert_eq!(c2.len(), 3);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0], 1);
    }

    #[test]
    fn test_vector_mask() {
        let a = vec![1, 2, 3];
        let b = vec![2, 3];
        assert_eq!(vec_intersection_mask(&a, &b), vec![false, true, true]);
        assert_eq!(vec_intersection_mask(&b, &a), vec![true, true]);

        let ind = mask_to_indices(vec_intersection_mask(&a, &b).as_slice());
        assert_eq!(ind, vec![1, 2]);

        let ind2 = mask_to_indices(vec_intersection_mask(&b, &a).as_slice());
        assert_eq!(ind2, vec![0, 1]);

        let m = vec_intersection_mask(&a, &b);
        let a2: Vec<i32> = apply_mask(&m, &a);
        assert_eq!(a2, vec![2, 3]);
    }

    #[test]
    fn test_dedup() {
        let mut v = vec![1, 2, 3, 1, 1];
        dedup_unstable(&mut v, true);
        assert_eq!(v, vec![1, 2, 3]);

        let mut v2: Vec<i8> = vec![];
        dedup_unstable(&mut v2, true);
        assert_eq!(v2, Vec::<i8>::new());

        let mut v3: Vec<i8> = vec![1, 1, 1, 1, 1];
        dedup_unstable(&mut v3, true);
        assert_eq!(v3, vec![1]);
    }

    #[test]
    fn test_dedup_large() {
        let x: Vec<u8> = vec![1u8, 2u8, 3u8];
        let mut y = x
            .iter()
            .cycle()
            .take(x.len() * 1000001)
            .map(|x| *x)
            .collect::<Vec<u8>>();
        dedup_unstable(&mut y, true);
        assert_eq!(y, vec![1u8, 2u8, 3u8]);
    }
}
