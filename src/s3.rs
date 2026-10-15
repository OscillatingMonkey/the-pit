//! Minimal S3 client with AWS Signature Version 4: put, get and list. Works
//! with AWS S3, Cloudflare R2, Backblaze B2, MinIO and other S3-compatible stores.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::rail::vercel::urlencode;

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn encode_path(key: &str) -> String {
    key.split('/').map(urlencode).collect::<Vec<_>>().join("/")
}

pub struct Store<'a> {
    pub endpoint: Option<&'a str>,
    pub bucket: &'a str,
    pub region: &'a str,
    pub access: &'a str,
    pub secret: &'a str,
}

impl Store<'_> {
    fn location(&self, key: &str) -> Result<(String, String)> {
        Ok(match self.endpoint {
            Some(e) => {
                let host = e
                    .trim_end_matches('/')
                    .strip_prefix("https://")
                    .ok_or_else(|| Error::Invalid("S3 endpoint must start with https://".into()))?
                    .to_string();
                let path = if key.is_empty() {
                    format!("/{}", urlencode(self.bucket))
                } else {
                    format!("/{}/{}", urlencode(self.bucket), encode_path(key))
                };
                (host, path)
            }
            None => (
                format!("{}.s3.{}.amazonaws.com", self.bucket, self.region),
                format!("/{}", encode_path(key)),
            ),
        })
    }

    /// One signed request. `query` pairs are sent sorted, as SigV4 requires.
    fn request(
        &self,
        method: &str,
        key: &str,
        query: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let (host, path) = self.location(key)?;
        let mut q: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (urlencode(k), urlencode(v)))
            .collect();
        q.sort();
        let qs = q
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let now = time::OffsetDateTime::now_utc();
        let amz_date = now
            .format(&time::macros::format_description!(
                "[year][month][day]T[hour][minute][second]Z"
            ))
            .map_err(|e| Error::Invalid(e.to_string()))?;
        let date = &amz_date[..8];
        let payload_hash = hex::encode(Sha256::digest(body));
        let canonical = format!(
            "{method}\n{path}\n{qs}\nhost:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n\nhost;x-amz-content-sha256;x-amz-date\n{payload_hash}"
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let k_date = hmac(format!("AWS4{}", self.secret).as_bytes(), date.as_bytes());
        let k_region = hmac(&k_date, self.region.as_bytes());
        let k_service = hmac(&k_region, b"s3");
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex::encode(hmac(&k_signing, to_sign.as_bytes()));
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}",
            self.access
        );
        let url = if qs.is_empty() {
            format!("https://{host}{path}")
        } else {
            format!("https://{host}{path}?{qs}")
        };
        let req = crate::rail::http::agent()
            .request(method, &url)
            .set("x-amz-date", &amz_date)
            .set("x-amz-content-sha256", &payload_hash)
            .set("Authorization", &auth);
        let r = if method == "PUT" {
            req.set("Content-Type", "application/octet-stream")
                .send_bytes(body)
        } else {
            req.call()
        };
        match r {
            Ok(resp) => {
                let mut out = vec![];
                std::io::Read::read_to_end(&mut resp.into_reader(), &mut out)?;
                Ok(out)
            }
            Err(ureq::Error::Status(code, _)) => {
                Err(Error::Remote(format!("S3 answered HTTP {code}")))
            }
            Err(ureq::Error::Transport(t)) => Err(Error::Remote(format!("network: {}", t.kind()))),
        }
    }

    pub fn put(&self, key: &str, body: &[u8]) -> Result<()> {
        self.request("PUT", key, &[], body).map(|_| ())
    }

    pub fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.request("GET", key, &[], b"")
    }

    /// Object keys under a prefix (first 1000).
    pub fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let body = self.request("GET", "", &[("list-type", "2"), ("prefix", prefix)], b"")?;
        let text = String::from_utf8_lossy(&body);
        Ok(text
            .split("<Key>")
            .skip(1)
            .filter_map(|s| s.split("</Key>").next())
            .map(|k| k.replace("&amp;", "&"))
            .collect())
    }
}
