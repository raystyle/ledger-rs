# ledger-client(ledger-rs)

ledger.ohmygh.com 全舰队标准客户端 crate(REQ-063)。各仓 CLI 引用本 crate,不自研副本。

## 职责边界(用户裁 2026-09-20)

- 各仓 CLI **只增**:issue new 加 artifact publish/attest,读面 list/show
- **关闭(status 推进)与删除集中 omc 工位**(开发工作台经 herdr 委托 omc 执行):`omc ledger issue status|delete`
- 本 crate 无 status/promote/demote/delete 面,边界即防线

## 用法

```rust
let key = ledger_client::KeyPair::load_secret_hex(&std::fs::read_to_string("~/.config/<repo>/ledger-key")?)?;
let lg = ledger_client::Ledger::new("github.com/raystyle/<repo>", key);
let n = lg.issue_new("标题", "bug", "验收标准", None)?;
let id = lg.artifact_publish("名", "experience", &ledger_client::content_digest("正文"), None, None, &[], None)?;
lg.artifact_attest(&id, "attest_dev", serde_json::json!([{ "name": "e2e", "result": "pass" }]), None)?;
```

## 依赖引入(各仓)

```toml
ledger-client = { git = "https://github.com/raystyle/ledger-rs", tag = "v0.1.0" }
```

## 约定

- kid = sha256hex(字母键序紧凑 JWK {crv,kty,x});私钥本地密档,零入仓零 argv
- 幂等:同键不同内容 409,换键;同键同内容回放不耗配额
- 配额 per-key 50/UTC 日
