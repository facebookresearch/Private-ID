//! This module is similar as s3_path where the only difference is that it
//! calls the Google Cloud Storage SDK for read and write file in GCS.

use std::io::Write;
use std::path::Path;
use std::str::FromStr;

use regex::Regex;
use tokio::fs::File;
use tokio_util::codec::BytesCodec;
use tokio_util::codec::FramedRead;

lazy_static::lazy_static! {
    /// Constant regex that matches an GCS path
    /// format: https://storage.cloud.google.com/{bucket_name}/{key}
    static ref GCS_PATH_REGEX: Regex = Regex::new(r"^https?://storage\.cloud\.google\.com/(.*?)/(.*)$")
        .expect("Failed to build GCS_PATH_REGEX");
}

/// Error that occurs if a path could not be parsed as an GCS path.
#[derive(Debug, thiserror::Error)]
pub enum GCSPathError {
    #[error("Failed to parse {0} as an GCS Path")]
    ParseError(String),
}

/// Struct which references a specific object on GCS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GCSPath {
    bucket: String,
    key: String,
}

impl GCSPath {
    pub fn get_bucket_name(&self) -> &String {
        &self.bucket
    }

    pub fn get_key(&self) -> &String {
        &self.key
    }

    pub async fn copy_to_local(&self) -> Result<String, std::io::Error> {
        let gcs_client = cloud_storage::Client::default();
        let data = gcs_client
            .object()
            .download(self.get_bucket_name(), self.get_key())
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to read input file from GCS",
                )
            })?;
        let mut gcs_tempfile = tempfile::NamedTempFile::new()?;
        gcs_tempfile.write_all(&data)?;
        gcs_tempfile.flush()?;
        let (_file, path) = gcs_tempfile.keep()?;
        let res_path = path.to_str().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Path could not be converted to str",
            )
        })?;

        Ok(res_path.to_string())
    }

    pub async fn copy_from_local(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let file = File::open(path).await?;
        let stream = FramedRead::new(file, BytesCodec::new());
        let gcs_client = cloud_storage::Client::default();
        gcs_client
            .object()
            .create_streamed(self.get_bucket_name(), stream, None, self.get_key(), "text")
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to writeinput file to GCS",
                )
            })?;
        Ok(())
    }
}

impl FromStr for GCSPath {
    type Err = GCSPathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(caps) = GCS_PATH_REGEX.captures(s) {
            Ok(GCSPath {
                bucket: caps[1].to_string(),
                key: caps[2].to_string(),
            })
        } else {
            let message = format!("Failed to parse {} as an GCSPath", &s);
            Err(GCSPathError::ParseError(message))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_str_gcs_path() {
        let path = "https://storage.cloud.google.com/test-bucket/fbpcs-e2e-dev/lift/partner/partner_e2e_input.csv";
        let path = GCSPath::from_str(&path).expect("Failed to read GCSPath from str");
        assert_eq!(path.get_bucket_name(), &"test-bucket");
        assert_eq!(
            path.get_key(),
            &"fbpcs-e2e-dev/lift/partner/partner_e2e_input.csv"
        );
    }

    #[test]
    fn test_gcs_path_from_str_local_path() {
        let path = "/tmp/local_path.txt";
        let res = GCSPath::from_str(&path);
        assert!(res.is_err());
    }
}
