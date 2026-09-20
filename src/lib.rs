//! ledger-client:ledger.ohmygh.com 标准客户端(REQ-063,全舰队唯一实现,各仓 CLI 引用本 crate)。
//!
//! 职责边界(用户裁 2026-09-20):各仓 CLI **只增** issue 与产物;
//! 关闭(status 推进)与删除集中 omc 工位(开发工作台经 herdr 委托 omc 执行)。
//! 本 crate 因此不提供 status/promote/demote/delete 面。
//!
//! 签名道:五头 + 签名基 v1(六行换行连)+ Ed25519 + base64url;
//! 幂等:同键同内容回放,同键不同内容 409 由服务端拒,调用方换键重试。

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const BASE_URL: &str = "https://ledger.ohmygh.com";

#[derive(thiserror::Error, Debug)]
pub enum LedgerError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("ledger {status}: {message}")]
    Api { status: u16, message: String },
    #[error("key: {0}")]
    Key(String),
}

pub type Result<T> = std::result::Result<T, LedgerError>;

/// 最小公钥 JWK(字母键序紧凑形,kid 约定派生源)。
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub key_id: String,
    signing: SigningKey,
    pub public_jwk: String,
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

impl KeyPair {
    /// 现生成新钥(私钥由调用方持久化到本地密档,零入仓)。
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self::from_signing(signing)
    }

    pub fn from_signing(signing: SigningKey) -> Self {
        let vk: VerifyingKey = signing.verifying_key();
        let x = b64url(vk.as_bytes());
        let public_jwk = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
        // kid = sha256hex(字母键序紧凑 JSON)
        let key_id = sha256_hex(public_jwk.as_bytes());
        Self {
            key_id,
            signing,
            public_jwk,
        }
    }

    /// 从本地密档读私钥(原始 32 字节 hex 或 base64url;不进 argv 不进仓)。
    pub fn load_secret_hex(hex: &str) -> std::result::Result<Self, LedgerError> {
        let bytes = hex_to_bytes(hex.trim())
            .ok_or_else(|| LedgerError::Key("私钥非 32 字节 hex".into()))?;
        let sk = SigningKey::from_bytes(&{
            let mut a = [0u8; 32];
            a.copy_from_slice(&bytes);
            a
        });
        Ok(Self::from_signing(sk))
    }

    fn sign(&self, message: &str) -> String {
        b64url(&self.signing.sign(message.as_bytes()).to_bytes())
    }
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..32)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn nonce() -> String {
    let r: [u8; 12] = rand::random();
    b64url(&r)
}

/// 产物 kind 白名单(服务端同表;沉淀加原型加实现记录为语义面)。
pub const ARTIFACT_KINDS: &[&str] = &[
    "binary",
    "image",
    "wasm",
    "sbom",
    "schema",
    "openapi",
    "eval-set",
    "benchmark",
    "runbook",
    "decision",
    "attested-report",
    "experience",
    "lesson",
    "research",
    "prototype",
];

/// 验证类 attest(追加证据;promote/demote 归 omc)。
pub const ATTEST_TYPES: &[&str] = &["attest_dev", "attest_prod", "verification_failed"];

/// 标准客户端:GET 免签,POST 五头签名道。
pub struct Ledger {
    repo_id: String,
    key: Option<KeyPair>,
    base: String,
    http: reqwest::blocking::Client,
}

impl Ledger {
    pub fn new(repo_id: impl Into<String>, key: KeyPair) -> Self {
        Self {
            repo_id: repo_id.into(),
            key: Some(key),
            base: BASE_URL.to_string(),
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("http client"),
        }
    }

    /// 只读构造（GET 面免签免私钥；写面调用即报错）。
    pub fn read_only(repo_id: impl Into<String>) -> Self {
        Self {
            repo_id: repo_id.into(),
            key: None,
            base: BASE_URL.to_string(),
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("http client"),
        }
    }

    #[cfg(test)]
    fn with_base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into();
        self
    }

    fn repos(&self) -> String {
        format!("{}/repos/{}", self.base, self.repo_id)
    }

    fn get(&self, path: &str) -> Result<Value> {
        let resp = self.http.get(format!("{}/{}", self.repos(), path)).send()?;
        Self::decode(resp)
    }

    fn post_signed(&self, path_tail: &str, body: &Value, idem: &str) -> Result<Value> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| LedgerError::Key("只读构造无私钥，写面不可用".into()))?;
        let body_text = serde_json::to_string(body).map_err(|e| LedgerError::Key(e.to_string()))?;
        let path = format!("/repos/{}/{}", self.repo_id, path_tail);
        let ts = now_secs().to_string();
        let nc = nonce();
        let body_hash = sha256_hex(body_text.as_bytes());
        let base = ["v1", "POST", &path, &ts, &nc, idem, &body_hash].join("\n");
        let sig = key.sign(&base);
        let resp = self
            .http
            .post(format!("{}/{}", self.repos(), path_tail))
            .header("Idempotency-Key", idem)
            .header("X-Key-Id", &key.key_id)
            .header("X-Timestamp", &ts)
            .header("X-Nonce", &nc)
            .header("X-Signature", sig)
            .json(body)
            .send()?;
        Self::decode(resp)
    }

    fn decode(resp: reqwest::blocking::Response) -> Result<Value> {
        let status = resp.status().as_u16();
        // 硬化:非 JSON 回体(如误入 HTML 仓页)必须报错,静默 Null 是 v0.1.0 假空的直接根因
        let v: Value = match resp.json() {
            Ok(v) => v,
            Err(e) => {
                return Err(LedgerError::Api {
                    status,
                    message: format!("回体非 JSON({e});疑 URL 或路由错入"),
                })
            }
        };
        if status >= 400 {
            return Err(LedgerError::Api {
                status,
                message: v["error"].as_str().unwrap_or("回执不识别").to_string(),
            });
        }
        Ok(v)
    }

    // ---- issue 面(增与读;status 推进/删除归 omc) ----

    pub fn issue_new(
        &self,
        title: &str,
        kind: &str,
        acceptance: &str,
        body: Option<&str>,
    ) -> Result<u64> {
        let v = self.post_signed(
            "issues",
            &json!({ "title": title, "kind": kind, "acceptance": acceptance, "body": body }),
            &format!("open-{}-{}", now_secs(), &nonce()[..6]),
        )?;
        Ok(v["issue"].as_u64().unwrap_or(0))
    }

    pub fn issue_list(&self, limit: u32, before: Option<u64>) -> Result<Value> {
        let mut q = format!("issues?limit={limit}&more=1");
        if let Some(b) = before {
            q.push_str(&format!("&before={b}"));
        }
        self.get(&q)
    }

    pub fn issue_show(&self, n: u64) -> Result<Value> {
        self.get(&format!("issues/{n}"))
    }

    // ---- artifact 面(增与读) ----

    pub fn artifact_publish(
        &self,
        name: &str,
        kind: &str,
        digest: &str,
        version: Option<&str>,
        git_range: Option<&str>,
        deps: &[String],
        note: Option<&str>,
    ) -> Result<String> {
        self.artifact_publish_full(
            name, kind, digest, version, git_range, deps, note, None, None, None,
        )
    }

    /// 完整形（v0.1.3）：summary 一行摘要与 outcome 结果倾向（success|failure）与
    /// git_sha（提交锚，服务端落 artifacts 表）为结构化字段，非正文拼接。
    #[allow(clippy::too_many_arguments)]
    pub fn artifact_publish_full(
        &self,
        name: &str,
        kind: &str,
        digest: &str,
        version: Option<&str>,
        git_range: Option<&str>,
        deps: &[String],
        note: Option<&str>,
        summary: Option<&str>,
        outcome: Option<&str>,
        git_sha: Option<&str>,
    ) -> Result<String> {
        let v = self.post_signed(
            "artifacts",
            &json!({ "name": name, "kind": kind, "digest": digest, "version": version, "git_range": git_range, "deps": deps, "body": note, "summary": summary, "outcome": outcome, "git_sha": git_sha }),
            &format!("pub-{}-{}", now_secs(), &nonce()[..6]),
        )?;
        Ok(v["artifact_id"].as_str().unwrap_or_default().to_string())
    }

    pub fn artifact_attest(
        &self,
        artifact_id: &str,
        attest_type: &str,
        checks: Value,
        note: Option<&str>,
    ) -> Result<Value> {
        self.post_signed(
            &format!("artifacts/{artifact_id}/attestations"),
            &json!({ "type": attest_type, "payload": { "checks": checks }, "body": note }),
            &format!("att-{}-{}", now_secs(), &nonce()[..6]),
        )
    }

    pub fn artifact_list(&self, current: bool, env: Option<&str>) -> Result<Value> {
        let mut q = String::from("artifacts?");
        if current {
            q.push_str("current=1&");
        }
        if let Some(e) = env {
            q.push_str(&format!("env={e}&"));
        }
        self.get(q.trim_end_matches('&'))
    }
}

/// 正文/记录哈希(digest 恒 sha256:<64hex>;沉淀与原型类以正文哈希为身份)。
pub fn content_digest(text: &str) -> String {
    format!("sha256:{}", sha256_hex(text.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn kid_convention_matches_fleet() {
        // 约定:sha256hex(字母键序紧凑 {crv,kty,x});与 hst/ark/reader/officecli/ohmycloud 一致
        let kp = KeyPair::generate();
        let recomputed = sha256_hex(kp.public_jwk.as_bytes());
        assert_eq!(kp.key_id, recomputed);
        assert!(kp
            .public_jwk
            .starts_with("{\"crv\":\"Ed25519\",\"kty\":\"OKP\""));
    }

    #[test]
    fn signature_base_and_verify_roundtrip() {
        let kp = KeyPair::generate();
        let base = [
            "v1",
            "POST",
            "/repos/x/issues",
            "1789000000",
            "n1",
            "idem1",
            &sha256_hex(b"body"),
        ]
        .join("\n");
        let sig_b64 = kp.sign(&base);
        let sig = ed25519_dalek::Signature::from_bytes(&{
            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(sig_b64)
                .unwrap();
            let mut a = [0u8; 64];
            a.copy_from_slice(&raw);
            a
        });
        assert!(kp
            .signing
            .verifying_key()
            .verify(base.as_bytes(), &sig)
            .is_ok());
    }

    #[test]
    fn secret_hex_roundtrip() {
        let kp = KeyPair::generate();
        let hex: String = kp
            .signing
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let kp2 = KeyPair::load_secret_hex(&hex).unwrap();
        assert_eq!(kp.key_id, kp2.key_id);
    }

    #[test]
    fn read_only_writes_fail_and_reads_ok_shape() {
        let ro = Ledger::read_only("github.com/x/y");
        let wr = ro.issue_new("t", "bug", "a", None);
        assert!(wr.is_err(), "只读构造写面必须报错（缺私钥早拦，不触网）");
    }

    #[test]
    fn content_digest_shape() {
        let d = content_digest("x");
        assert!(d.starts_with("sha256:") && d.len() == 71);
    }
}
