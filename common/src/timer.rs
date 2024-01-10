//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::fmt::Error;
use std::fmt::Formatter;
use std::ops::SubAssign;
use std::sync::Arc;
use std::sync::RwLock;
// Native
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;

use log::info;
// Web Broswer
#[cfg(target_arch = "wasm32")]
use wasm_timer::Instant;

/// A simple struct that allows to do naive timing outputs
///
/// Logger is used as an output source, make sure logger backend is configured
///
/// Log output may look like
/// `[2019-12-04T20:14:59Z INFO  experimental] [general | batch serialisation size: 10000] elapsed:
/// 0.00625 sec [qps: 1600435]`
///
/// # Example
///
/// ```
/// use common::timer;
/// let mut t = timer::Timer::new("my method");
/// let values = vec![1, 2, 3];
/// // would send to log info a message like:
/// // [my method | read input size: 3] elapsed 0.231 sec [qps: 2314]
/// t.qps("read input", values.len());
/// ```
///
///
/// # [RAII](https://en.cppreference.com/w/cpp/language/raii) would look like
pub struct Timer {
    start: Arc<RwLock<Instant>>,
    label: String,
    extra_label: Option<String>,
    size: Option<usize>,
    silent: bool,
}

/// Semantics assumes that imports happen as:
///
/// ```
/// use common::timer;
/// // AND NOT LIKE: private_id::timer{Timer, Builder};
/// // that makes it clear where does the Builder belong:
/// let t = timer::Builder::new().build();
/// ```
pub struct Builder {
    start: Arc<RwLock<Instant>>,
    label: String,
    extra_label: Option<String>,
    size: Option<usize>,
    silent: bool,
}

impl Builder {
    pub fn new() -> Builder {
        Builder {
            start: Arc::new(RwLock::new(Instant::now())),
            label: String::from(""),
            extra_label: None,
            size: None,
            silent: false,
        }
    }

    pub fn qps(label: &str, qps: usize) -> Timer {
        let mut t = Timer::new(label);
        t.size = Some(qps);
        t.silent = false;
        t
    }

    pub fn build(&self) -> Timer {
        Timer {
            start: self.start.clone(),
            label: String::from(&self.label),
            extra_label: self.extra_label.as_ref().map(String::from),
            size: self.size,
            silent: self.silent,
        }
    }

    pub fn size(&mut self, size: usize) -> &mut Builder {
        self.size = Some(size);
        self
    }

    pub fn label(&mut self, label: &str) -> &mut Builder {
        self.label = String::from(label);
        self
    }

    pub fn extra_label(&mut self, extra_label: &str) -> &mut Builder {
        self.extra_label = Some(String::from(extra_label));
        self
    }

    pub fn silent(&mut self, silent: bool) -> &mut Builder {
        self.silent = silent;
        self
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Timer {
    /// Returns a new instance or PoorManTimer
    ///
    /// # Arguments
    ///
    /// * label - will work as a prefix to all outputs of a timer
    ///
    /// # Example
    ///
    /// ```
    /// use common::timer;
    /// {
    ///     // execution block to meter RAII
    ///     let mut timer = timer::Timer::new("my method");
    ///     timer.set_extra_label("perf");
    ///     timer.set_size(100);
    /// } // on exiting the execution block the timer will fire
    /// ```
    pub fn new(label: &str) -> Timer {
        Timer {
            start: Arc::new(RwLock::new(Instant::now())),
            label: String::from(label),
            extra_label: None,
            size: None,
            silent: false,
        }
    }
    /// A silent timer means, timer will not fire on exiting the
    /// execution block
    pub fn new_silent(label: &str) -> Timer {
        let mut t = Timer::new(label);
        t.silent = true;
        t
    }

    pub fn set_size(&mut self, sz: usize) {
        self.size = Some(sz);
    }

    pub fn set_extra_label(&mut self, label: &str) {
        self.extra_label = Some(String::from(label));
    }

    /// Returns time elaped in millis  if is_millis else in nanos
    pub fn _elapsed(&self, is_millis: bool) -> u128 {
        if let Ok(t) = self.start.clone().read() {
            if is_millis {
                t.elapsed().as_millis()
            } else {
                t.elapsed().as_nanos()
            }
        } else {
            panic!("Unable to get elapsed")
        }
    }

    /// Returns a formatted string with labels and elapsed times
    ///
    /// # Arguments
    ///
    /// - label - optional extra label
    ///
    /// - size - optional size of operation required for qps output
    pub fn qps_str(&self, label: Option<&str>, size: Option<usize>) -> String {
        let e = (self._elapsed(false) as f64) / (1e9 as f64);

        // TODO: do better than String::from("")
        let fixed_label = label
            .map(|x| format!(" | {}", x))
            .unwrap_or_else(|| String::from(""));

        let fixed_size = size
            .map(|x| format!(" size: {}", x))
            .unwrap_or_else(|| String::from(""));

        let fixed_qps = size
            .map(|x| format!(" [qps: {:.0}]", (x as f64) / e))
            .unwrap_or_else(|| String::from(""));

        let res = format!(
            "[{}{}{}] elapsed: {:.5} sec{}",
            self.label, fixed_label, fixed_size, e, fixed_qps
        );
        self.reset();
        res
    }

    /// Resets the duration of an internal timer
    /// useful when reusing the timer
    pub fn reset(&self) {
        if cfg!(target_arch = "wasm32") {
            panic!("Reset not implemented for wasm-timer")
        } else if let Ok(mut t) = self.start.clone().write() {
            let z = t.elapsed();
            t.sub_assign(z);
        } else {
            panic!("Unable to reset the timer")
        }
    }

    /// Returns formatted string _without_ QPS part
    /// usefull when QPS is not the part of timing
    pub fn elapsed_str(&self, label: Option<&str>) -> String {
        self.qps_str(label, None)
    }

    /// Wrapper method that sends formatted string without QPS
    /// to `log.info`
    pub fn elapsed_log(&self, label: Option<&str>) {
        info!("{}", self.qps_str(label, None))
    }

    /// Wrapper method that sends formatted string with QPS
    /// to `log.info`
    pub fn opqps(&self, label: Option<&str>, size: Option<usize>) {
        info!("{}", self.qps_str(label, size));
    }

    /// Wrapper method that sends formatted string with QPS
    /// to `log.info`
    pub fn qps(&self, label: &str, size: usize) {
        info!("{}", self.qps_str(Some(label), Some(size)));
    }
}

impl std::fmt::Debug for Timer {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{}", format!("{}, label: {}", "timer", self.label))
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if !self.silent {
            let k = self.size;
            let mut z = self.extra_label.clone();
            let kk = z.as_mut().map(|x| &**x);
            self.opqps(kk, k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_timer_and_gen_string() {
        let timer = Timer::new("timer");
        timer.reset(); // should just be there
        let s = timer.qps_str(Some("hello"), Some(100500));
        assert!(s.len() > 10);
    }

    #[test]
    fn init_timer_via_builder() {
        {
            let _ = Builder::new()
                .label("foo")
                .extra_label("bar")
                .size(199)
                .build();
        }
    }

    #[test]
    fn test_qps() {
        let t = Builder::new()
            .label("foo")
            .extra_label("bar")
            .size(199)
            .build();
        t.qps("test", 10);
    }

    #[test]
    fn test_silent() {
        let t = Builder::default()
            .label("foo")
            .silent(true)
            .extra_label("bar")
            .size(199)
            .build();
        assert!(t.silent);
    }

    #[test]
    fn test_elapsed_str() {
        let t = Builder::new()
            .label("foo")
            .silent(true)
            .extra_label("bar")
            .size(199)
            .build();
        t.elapsed_str(Some("1"));
        t.elapsed_log(Some("1"));
    }
}
