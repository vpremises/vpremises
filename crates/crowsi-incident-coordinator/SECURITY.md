# Security boundary

本 crate は Zero Trust の incident coordination authority です。ネットワーク制御、IdP、Policy Administrator、PEP、独立観測、checkpoint signer、monotonic anchor/store を別の侵害ドメインとして扱います。deserialize、通信路の認証、単一署名、PEP receipt、current-head の read のいずれも単独では信頼判断になりません。

## 保護する性質

- incident owner だけが明示的な対応操作を開始できること
- 別 deployment、incident、epoch、target、grant の artifact を混在させないこと
- 未 commit の分岐や rollback state から command を公開しないこと
- containment/restore の結果を独立観測なしに成功へ昇格しないこと
- 侵害後に user が即時封じ込めを選べ、復旧は別の高保証承認なしに開始されないこと
- replay、二重 grant 消費、競合 receipt、古い restore attempt を拒否すること

availability より integrity を優先します。clock、anchor、head store、署名、revocation 情報が不明な場合は停止します。

## Production 必須構成

1. Deployment 設定に trust bundle digest を root pin し、鍵 material と key ID を全 role 間で一意にする。
2. Incident owner、IdP、PA、PEP、independent verifier、recovery、checkpoint、anchor を別 role/scope とし、checkpoint と anchor は管理主体・鍵を分離する。
3. 完全な `CoordinatorStateV1` と checkpoint chain を authenticated encryption、append-only audit、backup retention 付き durable store に保存する。
4. `(deployment_id, incident_id)` head の更新を linearizable CAS にし、`confirm_checkpoint_commit` より前に永続化する。
5. `MonotonicHeadReaderV1` は同じ authenticated authoritative store を直接参照する。cache や process memory を使わない。
6. `AtomicReleaseConsumerV1` は current head 照合と command digest の一回限り予約を同一 transaction、または失効を強制できる lease で行う。
7. PA は reservation 後に original signed authorization chain を ledger から再取得し、current revocation と proof-of-possession を再検証する。
8. PEP command は security domain、release/checkpoint digest、monotonic fence、reservation、grant、expiry、expected resource version を署名対象に含める。
9. PEP/provider は実変更時に latest fence、one-use、revocation、expiry、resource CAS を再検証する。read と mutation を分離しない。
10. 管理 lifeline、break-glass path、audit export を隔離対象 network から独立させ、封じ込め演習と復旧演習を定期実施する。

## 明示的な本番ブロッカー

現行 `IsolationCommandV1`、PA reservation input/ledger、PEP adapter には release reservation と monotonic fence を end-to-end に署名・消費・provider CAS する field/実装がありません。そのため本 crate が生成する plan/release だけでは安全な production isolation を保証できません。

次の全てが実装されるまで、production adapter は fail closed にしてください。

- `IsolationCommandV2` に deployment/security domain、incident、release digest、checkpoint sequence/digest、fence token、reservation ID、expected resource version を追加
- PA の durable ledger で grant JTI と release reservation を一回だけ原子的に消費
- PEP/provider で latest fence と resource version を mutation と同じ transaction で比較
- A が検証後に B が head を進めた場合、A の reservation/mutation が拒否される競合試験
- timeout/unknown result を成功扱いせず、read-back と reconciliation を要求する実装

`AtomicReleaseConsumerV1` は PEP executor ではありません。これを直接 provider mutation に接続すると PA を迂回するため禁止します。

## Subject / Federated Identity の注意

authorization は pairwise subject、actor、device、workload、profile、proof key、revocation epoch を完全一致させます。グローバルな subject identifier を command や audit export に露出させず、deployment/service ごとの pairwise identifier を使用してください。

Subject Registry や federated identity linking は侵害時の blast radius、相関による privacy loss、誤 link、IdP/registry outage、unlink 遅延を集中させます。registry は authentication authority にせず、link provenance、confidence、issuer namespace、validity、revocation、user-visible unlink を保存してください。高影響操作では linked identity だけを根拠にせず、fresh phishing-resistant step-up と device/workload posture を再評価します。

## 侵害・運用シナリオ

- Owner credential compromise: 短命 event、proof key、step-up、revocation、rate limit、別 lifeline からの owner/session revoke が必要です。owner 署名だけで provider を直接操作しません。
- PA compromise: PA と PEP/provider の双方で fence、grant one-use、resource CAS を検証し、独立 audit と anomaly detection を置きます。
- PEP compromise: PEP receipt を成功根拠にせず、別 authority/key の sensor evidence を必須にします。
- Checkpoint signer compromise: 独立 anchor と current-head CAS は rollback を抑止しますが、悪意ある新 state の署名は防げません。signer policy、HSM、quorum、audit alert を追加してください。
- Monotonic store compromise: rollback protection 全体の root です。hardware-backed key、quorum/consensus、WORM audit、geo-replicated recovery を推奨します。
- Isolationによる自己ロックアウト: management lifeline と audit path を data plane から分離し、対象 graph と cut impact を表示して user が承認できるようにします。
- Trust rotation: online rotation は本 crate では未実装です。新 revision/digest を外部設定へ pin し、検証済み migration/restart を行うまで旧/新 bundle の混在を拒否します。
- Availability attack: signature、clock、anchor、store の障害は fail closed になります。冗長化は可用性対策であり、検証 bypass は許可しません。

## Incident UX の要件

Hatter/Crowsi の UI は user が関与する network、identity、source、service、active session と trust relation を一覧化し、対象ごとの「隔離」「credential revoke」「egress 制限」「接続解除」を明示してください。操作前には blast radius と management lifeline を表示し、操作後は command、receipt、独立観測、未確認項目を区別して表示します。

「要求済み」を「隔離済み」と表示してはいけません。partial、failed、unknown、stale、reconciliation pending は独立した状態として残し、復旧操作には新しい承認、最新 topology、最新 revocation、expected resource version を要求してください。

## Disclosure

鍵 material、proof key、subject link、checkpoint store、PA/PEP adapter に関する問題は公開 issue に秘密情報を含めず、管理された security reporting channel へ報告してください。

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
