//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate rand;

use rand::{thread_rng, Rng};
use std::collections::HashSet;

/// Returns random swap permutation
///
/// acyclic, with the property `p[p[i]] = i`
///
/// `(1 2 3 4) -> (3 4 1 2)`
pub fn gen_permute_pattern(n: usize) -> Vec<usize> {
    let mut cache_: HashSet<usize> = std::collections::HashSet::new();
    let mut rng_ = thread_rng();
    let mut res_: Vec<usize> = (0..n).map(|i| i).collect::<Vec<usize>>();
    for i in 0..n {
        let k = rng_.gen_range(0, n);
        if !cache_.contains(&k) && !cache_.contains(&i) {
            cache_.insert(k);
            cache_.insert(i);
            res_[i] = k;
            res_[k] = i;
        }
    }
    res_
}

/// Applies the permutation on a vector _in place_
///
/// # Example
///
/// ```
/// use common::permutations;
/// let mut v = vec!['a', 'b', 'c'];
/// let p = vec![2, 1, 0];
///
/// permutations::permute(&p, &mut v);
/// assert_eq!(v[0], 'c');
/// assert_eq!(v[1], 'b');
/// assert_eq!(v[2], 'a');
/// ```
pub fn permute<T>(permutation: &[usize], items: &mut Vec<T>) {
    permute_and_undo(permutation, items, true);
}

/// Un-Applies the permutation on a vector _in place_
///
/// # Example
///
/// ```
/// use common::permutations;
/// let mut v = vec!['c', 'b', 'a'];
/// let p = vec![2, 1, 0];
///
/// permutations::undo_permute(&p, &mut v);
/// assert_eq!(v[0], 'a');
/// assert_eq!(v[1], 'b');
/// assert_eq!(v[2], 'c');
/// ```
pub fn undo_permute<T>(permutation: &[usize], items: &mut Vec<T>) {
    permute_and_undo(permutation, items, false);
}

/// applies or un-applies permutation
fn permute_and_undo<T>(permutation: &[usize], items: &mut Vec<T>, is_apply: bool) {
    let mut cache_: HashSet<usize> = std::collections::HashSet::new();
    permutation
        .iter()
        .enumerate()
        .for_each(|(i, p)| match is_apply {
            true => {
                if !cache_.contains(p) {
                    items.swap(i, *p);
                    cache_.insert(i);
                    cache_.insert(*p);
                }
            }
            false => {
                if !cache_.contains(&i) {
                    items.swap(i, *p);
                    cache_.insert(i);
                    cache_.insert(*p);
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    const NUM_TEST_ITERATIONS: i32 = 100;

    /// [src](https://stackoverflow.com/questions/40767815/how-do-i-check-whether-a-vector-is-equal-to-another-vector-that-contains-nan-and)
    fn vec_compare<T: Ord>(va: &[T], vb: &[T]) -> bool {
        (va.len() == vb.len()) &&  // zip stops at the shortest
            va.iter()
                .zip(vb)
                .all(|(a, b)| a == b)
    }

    #[test]
    fn check_permutation() {
        const N: usize = 50;
        let even: Vec<usize> = (0..N).map(|i| i).collect();
        for _ in 0..NUM_TEST_ITERATIONS {
            let p = gen_permute_pattern(N);
            assert_ne!(vec_compare(&p[..], &even[..]), true);
        }
    }

    #[test]
    fn permutation_has_swap_property() {
        const N: usize = 100;
        let p = gen_permute_pattern(N);
        assert_eq!(p.len(), N);
        for i in 0..p.len() {
            assert_eq!(p[p[i]], i); // swapping property
        }
    }

    #[test]
    fn permute_and_undo_permutation() {
        let v = vec!['a', 'b', 'c', 'd'];
        let p = vec![1, 0, 3, 2];

        let mut a = v.to_vec();
        permute(&p, &mut a);
        assert_eq!(vec_compare(&a, &vec!['b', 'a', 'd', 'c']), true);

        undo_permute(&p, &mut a);
        assert_eq!(vec_compare(&a, &v), true);
    }

    #[test]
    fn permute_and_undo_random_permutation() {
        const N: usize = 100;
        let v: Vec<usize> = (0..N).map(|i| i).collect();
        for _ in 0..NUM_TEST_ITERATIONS {
            let p = gen_permute_pattern(N);

            let mut a = v.to_vec();
            permute(&p, &mut a);
            assert_eq!(vec_compare(&a, &v), false);

            let mut a_permuted = a.to_vec();

            // Due to swap property - permuting twice will restore
            // to original sequence
            permute(&p, &mut a);
            assert_eq!(vec_compare(&a, &v), true);

            undo_permute(&p, &mut a_permuted);
            assert_eq!(vec_compare(&a_permuted, &v), true);
        }
    }
}
