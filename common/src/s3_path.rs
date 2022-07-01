//! This module implements the `S3Path` struct which is used to refer to a
//! specific object on S3. This module itself does not provide any functionality
//! for actually reading or writing to that object, but that sort of behavior
//! can easily be built on top of this using the rust-s3 crate.

use std::io::Write;
use std::path::Path;
use std::str::FromStr;

use regex::Regex;

lazy_static::lazy_static! {
    /// Constant regex that matches an S3 path
    /// format: https://{bucket_name}.s3.{region}.amazonaws.com{key}
    static ref S3_PATH_REGEX: Regex = Regex::new(r"^https?://(.*)\.s3.(.*)\.amazonaws\.com/(.*)$")
        .expect("Failed to build S3_PATH_REGEX");
}

/// Error that occurs if a path could not be parsed as an S3 path.
#[derive(Debug, thiserror::Error)]
pub enum S3PathError {
    #[error("Failed to parse {0} as an S3Path")]
    ParseError(String),
}

/// Struct which references a specific object on S3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3Path {
    bucket: String,
    region: String,
    key: String,
}

impl S3Path {
    pub fn get_bucket_name(&self) -> &String {
        &self.bucket
    }

    pub fn get_region(&self) -> &String {
        &self.region
    }

    pub fn get_key(&self) -> &String {
        &self.key
    }

    pub async fn copy_to_local(&self) -> Result<String, std::io::Error> {
        let region = aws_sdk_s3::Region::new(self.get_region().clone());
        let aws_cfg = aws_config::from_env().region(region).load().await;
        let client = aws_sdk_s3::Client::new(&aws_cfg);
        let resp = client
            .get_object()
            .bucket(self.get_bucket_name())
            .key(self.get_key())
            .send()
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to read input file from S3",
                )
            })?;
        let data = resp.body.collect().await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to read body from S3 response",
            )
        })?;
        let mut s3_tempfile = tempfile::NamedTempFile::new()?;
        s3_tempfile.write_all(&data.into_bytes())?;
        s3_tempfile.flush()?;
        let (_file, path) = s3_tempfile.keep()?;

        let path = path.to_str().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Path could not be converted to str",
            )
        })?;

        Ok(path.to_string())
    }

    pub async fn copy_from_local(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let body = aws_sdk_s3::ByteStream::from_path(path.as_ref())
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to read path as ByteStream",
                )
            })?;
        let region = aws_sdk_s3::Region::new(self.get_region().clone());
        let aws_cfg = aws_config::from_env().region(region).load().await;
        let client = aws_sdk_s3::Client::new(&aws_cfg);
        client
            .put_object()
            .bucket(self.get_bucket_name())
            .key(self.get_key())
            .body(body)
            .send()
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "Failed to writeinput file to S3")
            })?;
        Ok(())
    }
}

impl FromStr for S3Path {
    type Err = S3PathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(caps) = S3_PATH_REGEX.captures(s) {
            Ok(S3Path {
                bucket: caps[1].to_string(),
                region: caps[2].to_string(),
                key: caps[3].to_string(),
            })
        } else {
            let message = format!("Failed to parse {} as an S3Path", &s);
            Err(S3PathError::ParseError(message))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_str_s3_path() {
        let path = "https://test-bucket.s3.us-west-2.amazonaws.com/key.txt";
        let path = S3Path::from_str(&path).expect("Failed to read S3Path from str");
        assert_eq!(path.get_bucket_name(), &"test-bucket");
        assert_eq!(path.get_region(), &"us-west-2");
        assert_eq!(path.get_key(), &"key.txt");
    }

    #[test]
    fn test_from_str_local_path() {
        let path = "/tmp/local_path.txt";
        let res = S3Path::from_str(&path);
        assert!(res.is_err());
    }
}
