# Changelog

## [0.18.0](https://github.com/yaad-index/darbaan/compare/v0.17.2...v0.18.0) (2026-08-12)


### Features

* render hold-card reason in operator terms ([#262](https://github.com/yaad-index/darbaan/issues/262), [#268](https://github.com/yaad-index/darbaan/issues/268)) ([#278](https://github.com/yaad-index/darbaan/issues/278)) ([00c5972](https://github.com/yaad-index/darbaan/commit/00c5972787cf160c07b7a6f0ca55dd74bab0c7e4))


### Bug Fixes

* anchor hold-card truncation caveat ahead of the gloss clauses ([#282](https://github.com/yaad-index/darbaan/issues/282)) ([#283](https://github.com/yaad-index/darbaan/issues/283)) ([ef4cdbe](https://github.com/yaad-index/darbaan/commit/ef4cdbec78880ba9d3b1dae379dd66435a9f3151))
* store agent credential digests at construction ([#266](https://github.com/yaad-index/darbaan/issues/266)) ([#279](https://github.com/yaad-index/darbaan/issues/279)) ([95f1717](https://github.com/yaad-index/darbaan/commit/95f1717909077c4a35720cc7e8c249ec34cdf39d))

## [0.17.2](https://github.com/yaad-index/darbaan/compare/v0.17.1...v0.17.2) (2026-08-11)


### Bug Fixes

* neutralize banner markers to a fixpoint so a rewrite cannot leave a live one ([#274](https://github.com/yaad-index/darbaan/issues/274)) ([#275](https://github.com/yaad-index/darbaan/issues/275)) ([5ea38aa](https://github.com/yaad-index/darbaan/commit/5ea38aad117e63908dae52079295c7ab16240f4f))
* neutralize forged trust banners in the body instead of deleting them ([#238](https://github.com/yaad-index/darbaan/issues/238) C37) ([#273](https://github.com/yaad-index/darbaan/issues/273)) ([43467b2](https://github.com/yaad-index/darbaan/commit/43467b2b7bf0936bb09a37f67fe0ddc593234775))
* validate serve config, escape admin client paths, surface dropped audit errors ([#238](https://github.com/yaad-index/darbaan/issues/238)) ([#269](https://github.com/yaad-index/darbaan/issues/269)) ([6e07f89](https://github.com/yaad-index/darbaan/commit/6e07f8962c76f6723f55f18383208d5afc8fb2ed))
* widen admin-addr exposure warning to all-interface binds; demonstrate slash escaping ([#271](https://github.com/yaad-index/darbaan/issues/271)) ([#272](https://github.com/yaad-index/darbaan/issues/272)) ([d6ad353](https://github.com/yaad-index/darbaan/commit/d6ad353241dfe270a44a4894e6659cdc8aa4b88d))

## [0.17.1](https://github.com/yaad-index/darbaan/compare/v0.17.0...v0.17.1) (2026-08-11)


### Bug Fixes

* compare agent credentials in constant time over fixed-width hashes ([#238](https://github.com/yaad-index/darbaan/issues/238) C31) ([#264](https://github.com/yaad-index/darbaan/issues/264)) ([42877e2](https://github.com/yaad-index/darbaan/commit/42877e2ecc057e9e1926e17e1016958681412c33))
* render the decoded body in the hold surfaces, not the raw message source ([#265](https://github.com/yaad-index/darbaan/issues/265)) ([5c1bac7](https://github.com/yaad-index/darbaan/commit/5c1bac722c5ed3e24a53bf9984102beea9218488))

## [0.17.0](https://github.com/yaad-index/darbaan/compare/v0.16.1...v0.17.0) (2026-08-11)

### Upgrade notes

**Expect repeated label-write deferrals for messages stored before this series, and do not chase them as a fault.** The X-GM-LABELS writer now refuses a label write whenever the mailbox validity is unknown on either side. Messages recorded before the validity field existed therefore defer their label writes instead of replicating them, and because reconcile clears the dirty flag only on success, each one re-attempts and logs a deferral on every sync. That is the intended trade: writing into an unconfirmed UID space is the worse outcome. The deferrals stop once those records carry a validity; a backfill is tracked separately.

**Assessment holds may differ slightly if you previously lowered `threshold`.** Recipient-skew scoring was corrected, so a deployment tuned around the old behaviour will hold marginally less than before. The `assessment:` settings are the supported way to re-tune.

### Features

* wire assessment tunables, agent advisory, identity-less scoring ([#233](https://github.com/yaad-index/darbaan/issues/233) part 3) ([#252](https://github.com/yaad-index/darbaan/issues/252)) ([9ac2b75](https://github.com/yaad-index/darbaan/commit/9ac2b75bb88258a2ec5c340b74af97386bd7b244))


### Bug Fixes

* add outbound re-send verb, surface send failures, guard send-attempt state ([#243](https://github.com/yaad-index/darbaan/issues/243)) ([6568faa](https://github.com/yaad-index/darbaan/commit/6568faab77748a7e655cdffbbb669c0646853f80))
* audit tail-truncation detection, inbound verdicts + attribution ([#236](https://github.com/yaad-index/darbaan/issues/236)) ([#246](https://github.com/yaad-index/darbaan/issues/246)) ([35bcccb](https://github.com/yaad-index/darbaan/commit/35bcccbd4792d74b11d382d51bf71eaa284f1e82))
* bound X-GM-LABELS writes to mailbox validity and honor ctx in sync ([#235](https://github.com/yaad-index/darbaan/issues/235) part 2) ([#256](https://github.com/yaad-index/darbaan/issues/256)) ([672cc3d](https://github.com/yaad-index/darbaan/commit/672cc3d67607fa7c5bc2abb086d80f3936fe755d))
* harden injection detector against evasion ([#233](https://github.com/yaad-index/darbaan/issues/233) part 2) ([#250](https://github.com/yaad-index/darbaan/issues/250)) ([5f71624](https://github.com/yaad-index/darbaan/commit/5f71624f9d095413aba687c6d07c183a4967d697))
* harden outbound approve/queue path — pre-commit ApproveAs, transient enqueue, sanitize operator tables ([#241](https://github.com/yaad-index/darbaan/issues/241)) ([b7f33f6](https://github.com/yaad-index/darbaan/commit/b7f33f671f5bed916ab335aad78f13e866612789))
* harden the Telegram operator surface against oversized and unfetchable messages ([#234](https://github.com/yaad-index/darbaan/issues/234)) ([#259](https://github.com/yaad-index/darbaan/issues/259)) ([20830bf](https://github.com/yaad-index/darbaan/commit/20830bfe77a378888ac378019b7272b480a87ff9))
* hold messages whose content cannot be decoded for assessment ([#233](https://github.com/yaad-index/darbaan/issues/233) part 1) ([#249](https://github.com/yaad-index/darbaan/issues/249)) ([bd01b62](https://github.com/yaad-index/darbaan/commit/bd01b62e5d5012e9f02b70d810924c19f7f241bb))
* reconcile no longer retracts a concurrently-synced message + cleans superseded-validity orphans ([#235](https://github.com/yaad-index/darbaan/issues/235) part 1) ([#253](https://github.com/yaad-index/darbaan/issues/253)) ([e2e57aa](https://github.com/yaad-index/darbaan/commit/e2e57aa50cd76c196093df5bb2e6d90e4b944851))
* refuse send on removed inbox sender, reject header/envelope From mismatch ([#244](https://github.com/yaad-index/darbaan/issues/244)) ([0fcdc57](https://github.com/yaad-index/darbaan/commit/0fcdc57dca3611334224c1a35b85379b028e80e8))

## [0.16.1](https://github.com/yaad-index/darbaan/compare/v0.16.0...v0.16.1) (2026-08-08)


### Bug Fixes

* close ADR 0032 tombstone SEARCH/FLAGS leak + assess pre-flip backlog ([#239](https://github.com/yaad-index/darbaan/issues/239)) ([215d5c6](https://github.com/yaad-index/darbaan/commit/215d5c6c3a58baf87dd2de6a6f18dff18149e9e2))

## [0.16.0](https://github.com/yaad-index/darbaan/compare/v0.15.0...v0.16.0) (2026-08-08)


### Features

* document eager-at-ingest injection assessment + invisible/tombstone model (ADR 0032 A1) ([#230](https://github.com/yaad-index/darbaan/issues/230)) ([355e4ac](https://github.com/yaad-index/darbaan/commit/355e4ac8204acbe884941feb9a7854adc41296bb))

## [0.15.0](https://github.com/yaad-index/darbaan/compare/v0.14.0...v0.15.0) (2026-08-08)


### Features

* ADR 0032 slice 4b — live ingest integration (default-off) ([#225](https://github.com/yaad-index/darbaan/issues/225)) ([4d935a2](https://github.com/yaad-index/darbaan/commit/4d935a2a0efee586325b5e2814966c68394f996c))
* **assessor:** ADR 0032 slice 3 — isolated zero-access injection assessor ([#223](https://github.com/yaad-index/darbaan/issues/223)) ([c45504f](https://github.com/yaad-index/darbaan/commit/c45504fe004c48aa30a59fe19bc76ec608bb0f3f))
* **mailtext:** ADR 0032 slice 2 — bounded/inert content extraction ([#221](https://github.com/yaad-index/darbaan/issues/221)) ([b11cd62](https://github.com/yaad-index/darbaan/commit/b11cd62a27dc2609b0cdf531a5f53592ffe3ff9a))
* **riskscore:** ADR 0032 slice 1 — deterministic scoring + config core ([#219](https://github.com/yaad-index/darbaan/issues/219)) ([24ea5e8](https://github.com/yaad-index/darbaan/commit/24ea5e86eff282940f6132d2e64b5bc8117a149d))
* **screener:** ADR 0032 slice 4a — assessment orchestrator (pure) ([#224](https://github.com/yaad-index/darbaan/issues/224)) ([c4d154a](https://github.com/yaad-index/darbaan/commit/c4d154ab02e8f9135b8f92a9dc425a0cf448f5b6))

## [0.14.0](https://github.com/yaad-index/darbaan/compare/v0.13.0...v0.14.0) (2026-07-23)


### Features

* **inboxcfg:** per-inbox per-sender trust rules + resolution (ADR 0031 slice 1) ([#212](https://github.com/yaad-index/darbaan/issues/212)) ([08ac72a](https://github.com/yaad-index/darbaan/commit/08ac72a749ba877385d5efb02a561865856b7a3c))
* **listener:** serve-path sanitize-then-stamp backstop (ADR 0030 slice 5) ([#207](https://github.com/yaad-index/darbaan/issues/207)) ([5a765c2](https://github.com/yaad-index/darbaan/commit/5a765c23547c5e8cc6a09d62b7293df27c60cdf9))
* **provenance:** optional fenced body banner for top-level text/plain (ADR 0030 slice 4) ([#206](https://github.com/yaad-index/darbaan/issues/206)) ([80282bd](https://github.com/yaad-index/darbaan/commit/80282bdeabc9a7693cf7fda8fb9039efb26c5653))
* **provenance:** stamp X-Darbaan-Note from per-inbox config (ADR 0030 slice 3) ([#205](https://github.com/yaad-index/darbaan/issues/205)) ([0a7eb05](https://github.com/yaad-index/darbaan/commit/0a7eb0536f9e592ecbdcd8d03c4c347f3f8a76cc))
* **provenance:** stamp X-Darbaan-Trust from per-inbox config at the chokepoint (ADR 0030 slice 2) ([#204](https://github.com/yaad-index/darbaan/issues/204)) ([e655f1c](https://github.com/yaad-index/darbaan/commit/e655f1c18bb6c985542cfaa3b3ddeb878dbaa3e1))
* **provenance:** strip X-Darbaan-* at the content-write chokepoint (ADR 0030 slice 1) ([#202](https://github.com/yaad-index/darbaan/issues/202)) ([dc2ff87](https://github.com/yaad-index/darbaan/commit/dc2ff876d30af3655ab43cd6e783454ec2eceb25))

## [0.13.0](https://github.com/yaad-index/darbaan/compare/v0.12.1...v0.13.0) (2026-07-17)


### Features

* **sync:** per-account sync-health observability + stall alert ([#195](https://github.com/yaad-index/darbaan/issues/195)) ([#198](https://github.com/yaad-index/darbaan/issues/198)) ([4b73868](https://github.com/yaad-index/darbaan/commit/4b73868ae3f95bda050ecced418e8d2965bd11a3))

## [0.12.1](https://github.com/yaad-index/darbaan/compare/v0.12.0...v0.12.1) (2026-07-17)


### Bug Fixes

* **imapsync:** don't hang the client on an unresolvable upstream UID ([#190](https://github.com/yaad-index/darbaan/issues/190)) ([#191](https://github.com/yaad-index/darbaan/issues/191)) ([86dde41](https://github.com/yaad-index/darbaan/commit/86dde41308f040e196de0b94d498f08e9d9fb0b0))

## [0.12.0](https://github.com/yaad-index/darbaan/compare/v0.11.0...v0.12.0) (2026-07-09)


### Features

* **admincfg:** admin_clients config schema + scope vocabulary (ADR 0029 slice 1) ([#185](https://github.com/yaad-index/darbaan/issues/185)) ([1eec69d](https://github.com/yaad-index/darbaan/commit/1eec69dae8a2cf552ce85e5d71e615a0a770b154))
* **admin:** enforce per-client scopes in the auth middleware (ADR 0029 slice 2) ([#187](https://github.com/yaad-index/darbaan/issues/187)) ([c9fad8e](https://github.com/yaad-index/darbaan/commit/c9fad8e1e2328eeda37d02dce53c81769153192a))
* **admin:** wire scoped admin clients + docs + finalize ADR 0029 ([#59](https://github.com/yaad-index/darbaan/issues/59)) ([#188](https://github.com/yaad-index/darbaan/issues/188)) ([d9d3e0e](https://github.com/yaad-index/darbaan/commit/d9d3e0e5e446d983233117daed28d4f124244396))

## [0.11.0](https://github.com/yaad-index/darbaan/compare/v0.10.1...v0.11.0) (2026-07-08)


### Features

* **telegram:** push a proactive alert on reconcile cap-latch ([#149](https://github.com/yaad-index/darbaan/issues/149)) ([#182](https://github.com/yaad-index/darbaan/issues/182)) ([bea9c91](https://github.com/yaad-index/darbaan/commit/bea9c91bb267f17f95d8d8c51847906ea14f3692))

## [0.10.1](https://github.com/yaad-index/darbaan/compare/v0.10.0...v0.10.1) (2026-07-07)


### Bug Fixes

* **telegram:** retry Change-sender identity fetch in the poll loop ([#160](https://github.com/yaad-index/darbaan/issues/160)) ([#180](https://github.com/yaad-index/darbaan/issues/180)) ([e5dce5f](https://github.com/yaad-index/darbaan/commit/e5dce5f9a2c28a2a4207dcda25dd599499f39721))

## [0.10.0](https://github.com/yaad-index/darbaan/compare/v0.9.0...v0.10.0) (2026-07-04)


### Features

* **sync:** log successful on-demand inbound sync pulls (ADR 0028) ([#177](https://github.com/yaad-index/darbaan/issues/177)) ([41715f2](https://github.com/yaad-index/darbaan/commit/41715f2a23d6f963b19186aca302682b542376c0))

## [0.9.0](https://github.com/yaad-index/darbaan/compare/v0.8.0...v0.9.0) (2026-07-04)


### Features

* **sync:** STATUS triggers debounced on-demand inbound sync (ADR 0028) ([#174](https://github.com/yaad-index/darbaan/issues/174)) ([a3a4214](https://github.com/yaad-index/darbaan/commit/a3a4214233f8bd7998ec34570629cc6ee59ae56e))

## [0.8.0](https://github.com/yaad-index/darbaan/compare/v0.7.0...v0.8.0) (2026-07-01)


### Features

* **agents:** audit inbox + docs + finalize ADR 0027 (slice 4) ([#167](https://github.com/yaad-index/darbaan/issues/167)) ([458f305](https://github.com/yaad-index/darbaan/commit/458f30575b8fd2d4febad0c410d95abc72341572))
* **agents:** IMAP read-scoping + per-agent INBOX (ADR 0027 slice 2a) ([#164](https://github.com/yaad-index/darbaan/issues/164)) ([803afc1](https://github.com/yaad-index/darbaan/commit/803afc195926d9707db9d3b1d193024f0d43f114))
* **agents:** multi-agent config schema + per-agent auth (ADR 0027 slice 1) ([#162](https://github.com/yaad-index/darbaan/issues/162)) ([3138352](https://github.com/yaad-index/darbaan/commit/3138352fbf4e610fa6fa4b974b878ad0fae0f16b))
* **agents:** principal/mail-owner decoupling + bounce two-key-space (ADR 0027 slice 2b) ([#165](https://github.com/yaad-index/darbaan/issues/165)) ([1b187b4](https://github.com/yaad-index/darbaan/commit/1b187b49152a2d88c9477020251b14f9e9377520))
* **agents:** SMTP send-scoping + per-agent send catch-all (ADR 0027 slice 3) ([#166](https://github.com/yaad-index/darbaan/issues/166)) ([ce7ae4f](https://github.com/yaad-index/darbaan/commit/ce7ae4fbc1b666cec51732c284753ea8b41e2a6a))

## [0.7.0](https://github.com/yaad-index/darbaan/compare/v0.6.0...v0.7.0) (2026-07-01)


### Features

* **admin,telegram:** Change-sender at the approval gate ([#139](https://github.com/yaad-index/darbaan/issues/139)) ([#158](https://github.com/yaad-index/darbaan/issues/158)) ([b446747](https://github.com/yaad-index/darbaan/commit/b446747d1165e82da808f057675778c406452f69))

## [0.6.0](https://github.com/yaad-index/darbaan/compare/v0.5.0...v0.6.0) (2026-06-30)


### Features

* **admin:** reconcile status + release operator UX (ADR 0026) ([#153](https://github.com/yaad-index/darbaan/issues/153)) ([afb78f3](https://github.com/yaad-index/darbaan/commit/afb78f3e7a17d61cad9d1719eab2d2069ee6553c)), closes [#140](https://github.com/yaad-index/darbaan/issues/140)
* **imapsync:** ListUpstreamUIDs — current present-set for reconciliation ([#143](https://github.com/yaad-index/darbaan/issues/143)) ([e40eb7b](https://github.com/yaad-index/darbaan/commit/e40eb7b764e59bae07493ee4626074ad5ef2436c))
* **imapsync:** Reconcile — retract messages that left the source ([#146](https://github.com/yaad-index/darbaan/issues/146)) ([c488bde](https://github.com/yaad-index/darbaan/commit/c488bde14ac2a7affbd7750c4e4751ec82f4b4fe))
* **inbound:** RemoveSynced — hard-retract a synced message ([#142](https://github.com/yaad-index/darbaan/issues/142)) ([86c0fb9](https://github.com/yaad-index/darbaan/commit/86c0fb982acef529101dac16efb146e634068a3a))
* **inboxcfg:** per-inbox reconcile opt-in + interval ([#145](https://github.com/yaad-index/darbaan/issues/145)) ([d7fe0de](https://github.com/yaad-index/darbaan/commit/d7fe0dede5cf21ed63cc4d411882e19017c01f01))
* **reconcile:** operator-ack release — clear latch + cap-bypassed purge ([#150](https://github.com/yaad-index/darbaan/issues/150)) ([5a170aa](https://github.com/yaad-index/darbaan/commit/5a170aadf76d6567a1332cf37d3585a52eea4952))
* **reconcile:** safety-cap latch — hold a too-large purge (ADR 0026) ([#148](https://github.com/yaad-index/darbaan/issues/148)) ([3253688](https://github.com/yaad-index/darbaan/commit/32536882f4b6967309d84539c2cfe9efa83d1b8b))
* **serve:** reconcile cadence loop + shared audit log (ADR 0026) ([#152](https://github.com/yaad-index/darbaan/issues/152)) ([59211fb](https://github.com/yaad-index/darbaan/commit/59211fb006364079117073ce48e13c443bce789b))


### Bug Fixes

* **reconcile:** release refuses a non-held inbox ([#154](https://github.com/yaad-index/darbaan/issues/154)) ([#155](https://github.com/yaad-index/darbaan/issues/155)) ([8be819b](https://github.com/yaad-index/darbaan/commit/8be819bf907f3b6ff65cf49d50b19a6e2f5dcb06))

## [0.5.0](https://github.com/yaad-index/darbaan/compare/v0.4.0...v0.5.0) (2026-06-29)


### Features

* **admin:** aggregate held-list across inboxes (ADR 0023 3c-iii) ([#136](https://github.com/yaad-index/darbaan/issues/136)) ([388dfb9](https://github.com/yaad-index/darbaan/commit/388dfb9b0afa70f404a6b894b4e4b3cf5c873fdc))
* **bounceguard:** bounce-shape detection + spoof verdict (ADR 0024) ([#124](https://github.com/yaad-index/darbaan/issues/124)) ([bce92ce](https://github.com/yaad-index/darbaan/commit/bce92ce3eb411353af784e9ad7520f8f1dc9e923))
* **filter:** per-inbox default_visibility (ADR 0022) ([#116](https://github.com/yaad-index/darbaan/issues/116)) ([4d52109](https://github.com/yaad-index/darbaan/commit/4d5210944fffc05e40720d60c41331ad230d8cb8))
* **guard:** wire bounce-spoof guard into read face + held-list + config (ADR 0024) ([#126](https://github.com/yaad-index/darbaan/issues/126)) ([03c2fa9](https://github.com/yaad-index/darbaan/commit/03c2fa9f2a8f74c6c67c2f4d7b97f251b00fbb11))
* **imapsync:** sync writes per-inbox (ADR 0023 2b) ([#131](https://github.com/yaad-index/darbaan/issues/131)) ([ca3810d](https://github.com/yaad-index/darbaan/commit/ca3810db98edeae835d661d40f7a596fce1fb035))
* **inbound:** thread (owner,inbox) through the store + synced-index (ADR 0023 2a) ([#129](https://github.com/yaad-index/darbaan/issues/129)) ([3dca26d](https://github.com/yaad-index/darbaan/commit/3dca26d59d1c00073fafcd4fb3eb06c62cd00eeb))
* **inboxcfg:** EnvPrefix mangle + per-inbox secret-env collision guard (ADR 0023 3c-i) ([#134](https://github.com/yaad-index/darbaan/issues/134)) ([d4d7190](https://github.com/yaad-index/darbaan/commit/d4d719058102ee86da844eee161549471f4da6cc))
* **inboxcfg:** inbox config schema + implicit-default resolve (ADR 0023) ([#128](https://github.com/yaad-index/darbaan/issues/128)) ([d490723](https://github.com/yaad-index/darbaan/commit/d490723ad9ae4e54eaf1e1f2b9bec1856c518983))
* **listener:** read face serves N mailboxes per inbox (ADR 0023 3b) ([#133](https://github.com/yaad-index/darbaan/issues/133)) ([e08d07d](https://github.com/yaad-index/darbaan/commit/e08d07d3a243e0e187081f24cbd9581d7e2973b3))
* **outbound:** per-inbox senders + send dispatch by inbox (ADR 0023 4b) ([#138](https://github.com/yaad-index/darbaan/issues/138)) ([e14678a](https://github.com/yaad-index/darbaan/commit/e14678a0366550843f8fcaefe7b35ac2f6d0fc8a))
* **outbound:** route submission From→inbox, reject unmatched (ADR 0023 4a) ([#137](https://github.com/yaad-index/darbaan/issues/137)) ([7c752f7](https://github.com/yaad-index/darbaan/commit/7c752f7b64ac934b8f23984ab9a75f37547b22fb))
* **serve:** consume inboxcfg → per-inbox filter map + filter_file (ADR 0023 3a) ([#132](https://github.com/yaad-index/darbaan/issues/132)) ([9244237](https://github.com/yaad-index/darbaan/commit/9244237591953f6b33e6a24a8a94ddd9e723b1ca))
* **serve:** N syncers per inbox + per-inbox secret/fetch dispatch (ADR 0023 3c-ii) ([#135](https://github.com/yaad-index/darbaan/issues/135)) ([19a2c00](https://github.com/yaad-index/darbaan/commit/19a2c00094f7e27c29846552f4374357d1a4f845))
* **signer:** add Verify for the inbound bounce-spoof trust check (ADR 0024) ([#122](https://github.com/yaad-index/darbaan/issues/122)) ([8e60eb2](https://github.com/yaad-index/darbaan/commit/8e60eb2b9cfddc006d41c353269180e52ee12453))
* **telegram:** attach full message body when it overflows the inline cap (ADR 0025) ([#118](https://github.com/yaad-index/darbaan/issues/118)) ([9881aad](https://github.com/yaad-index/darbaan/commit/9881aad496e215b4143a28b4692b1ed13ae97821))

## [0.4.0](https://github.com/yaad-index/darbaan/compare/v0.3.0...v0.4.0) (2026-06-27)


### Features

* **filter:** inbound filter engine + serve-time allow/hide (ADR 0021 21a) ([#107](https://github.com/yaad-index/darbaan/issues/107)) ([8d07600](https://github.com/yaad-index/darbaan/commit/8d07600d0d69bbcb9902a846d6f72ba31733acdd))
* **imapsync:** Gmail X-GM-LABELS write-through (ADR 0020 20c) ([#102](https://github.com/yaad-index/darbaan/issues/102)) ([eff3ec3](https://github.com/yaad-index/darbaan/commit/eff3ec332f0fc2299c3a0566818ed99bd660e812))
* **imapsync:** inbound-max-age recency cutoff via SEARCH SINCE (ADR 0008) ([#96](https://github.com/yaad-index/darbaan/issues/96)) ([f1a4ab1](https://github.com/yaad-index/darbaan/commit/f1a4ab183172ffc2d63c98a740f377f3b66350a3))
* **inbound:** hold-for-human queue + UIDNEXT-from-full-store (ADR 0021 21b) ([#108](https://github.com/yaad-index/darbaan/issues/108)) ([3d28d8b](https://github.com/yaad-index/darbaan/commit/3d28d8ba14eba9bb3ca9942c975129c6e218822f))
* **inbound:** keyword write-through — STORE to local-canonical + best-effort upstream (ADR 0020 20b) ([#99](https://github.com/yaad-index/darbaan/issues/99)) ([657dfeb](https://github.com/yaad-index/darbaan/commit/657dfeb00a06d309da10db48d8d930e05ded7e04))
* **inbound:** read upstream keywords into metadata + serve on FETCH FLAGS (ADR 0020 20a) ([#98](https://github.com/yaad-index/darbaan/issues/98)) ([b647e74](https://github.com/yaad-index/darbaan/commit/b647e741487fe6fe4ade52d83b5cd6306a967ccd))
* **inbound:** serve ENVELOPE/RFC822Size/header-search from stored metadata (ADR 0019 Inc 3b-iii) ([#94](https://github.com/yaad-index/darbaan/issues/94)) ([2f3fe19](https://github.com/yaad-index/darbaan/commit/2f3fe19690e67f16a863926f4eb172386449de72))
* **telegram:** inbound hold-for-human surface (ADR 0021 21c) ([#109](https://github.com/yaad-index/darbaan/issues/109)) ([ce3bdad](https://github.com/yaad-index/darbaan/commit/ce3bdade229c95f173902396b81cefa8f04b3b56))


### Bug Fixes

* **inbound:** don't reconcile keyword writes on local-only records (ADR 0020) ([#100](https://github.com/yaad-index/darbaan/issues/100)) ([8685066](https://github.com/yaad-index/darbaan/commit/8685066ee9bef47a790f36947e42fecfba02d101))

## [0.3.0](https://github.com/yaad-index/darbaan/compare/v0.2.0...v0.3.0) (2026-06-27)


### Features

* **imapsync:** inbound mailbox sync engine (ADR 0019, Inc 1) ([#87](https://github.com/yaad-index/darbaan/issues/87)) ([c73f609](https://github.com/yaad-index/darbaan/commit/c73f609acf3e854cc0cb89d3f6ebc9827a6ec82f))
* **imapsync:** wire inbound sync into serve, config-gated (ADR 0019, Inc 2) ([#88](https://github.com/yaad-index/darbaan/issues/88)) ([7abef76](https://github.com/yaad-index/darbaan/commit/7abef763e6c0815f30e112ca9f9fe8a769699b43))
* **inbound:** headers-only sync + per-FETCH lazy read face (ADR 0019 Inc 3b-ii) ([#92](https://github.com/yaad-index/darbaan/issues/92)) ([c857248](https://github.com/yaad-index/darbaan/commit/c857248979017b0f8e9891d988bbfd6763c2bc14))
* **inbound:** idempotent sync via upstream-UID dedup (ADR 0019 Inc 3a) ([#90](https://github.com/yaad-index/darbaan/issues/90)) ([77df436](https://github.com/yaad-index/darbaan/commit/77df4361188fa7e75c8222c05930cd175cf21523))
* **inbound:** pending content state + on-demand FetchContent (ADR 0019 Inc 3b-i) ([#91](https://github.com/yaad-index/darbaan/issues/91)) ([5fb162d](https://github.com/yaad-index/darbaan/commit/5fb162d2719456697362967f8e6274f44e5fbf98))
* **storage:** reclaim orphan blobs at store-open ([#83](https://github.com/yaad-index/darbaan/issues/83)) ([#84](https://github.com/yaad-index/darbaan/issues/84)) ([8fb84d7](https://github.com/yaad-index/darbaan/commit/8fb84d7a87143f6a3757de57b58c9a03882df77d))


### Bug Fixes

* **imapsync:** concrete UIDNEXT bound + streamed fetch (live-test bug) ([#89](https://github.com/yaad-index/darbaan/issues/89)) ([c9c2def](https://github.com/yaad-index/darbaan/commit/c9c2defd4b192a0a4f2bec78b29d6ad02b897b7d))

## [0.2.0](https://github.com/yaad-index/darbaan/compare/v0.1.0...v0.2.0) (2026-06-26)


### Features

* **inbound:** tier raw content to filesystem blobs (ADR 0018) ([#82](https://github.com/yaad-index/darbaan/issues/82)) ([e2a8105](https://github.com/yaad-index/darbaan/commit/e2a81052dc3dd8ee674129fbce578537b4278e34)), closes [#78](https://github.com/yaad-index/darbaan/issues/78)
* **sluice:** tier raw content to filesystem blobs (ADR 0018) ([#80](https://github.com/yaad-index/darbaan/issues/80)) ([ed2a92d](https://github.com/yaad-index/darbaan/commit/ed2a92d639cafc951c4318b72f5dc19d553021a3))
* **telegram:** show + upload trapped attachments for operator review ([#76](https://github.com/yaad-index/darbaan/issues/76)) ([20e2060](https://github.com/yaad-index/darbaan/commit/20e206005a4c9fc52cc9cae11abac48c65eaa8d4))


### Bug Fixes

* **telegram:** thread attachment uploads under their decision message ([#81](https://github.com/yaad-index/darbaan/issues/81)) ([fae208c](https://github.com/yaad-index/darbaan/commit/fae208c09bc1c48057fd9a2f465cf440e820d635))

## 0.1.0 (2026-06-26)


### Features

* abstract storage; separate, pluggable, optional audit ([08dd043](https://github.com/yaad-index/darbaan/commit/08dd043dfa4aec959acc4b2f6b673d70bc1a4f27))
* abstract storage; separate, pluggable, optional audit ([2ba8c6a](https://github.com/yaad-index/darbaan/commit/2ba8c6a7c6de43130cf49f893912ffb7cb40d6e8))
* approval pipeline — approver interface, registry, router, manual approver ([53d35fd](https://github.com/yaad-index/darbaan/commit/53d35fd9b7116ab4c49a2db0dbff17b1cb4a6341))
* approval pipeline (approver, registry, router, manual approver) ([59d64da](https://github.com/yaad-index/darbaan/commit/59d64da5d70b0fd845cdaedf76a4880718a5d93b))
* bounce generation on reject (DSN into a separate inbound store) ([385fea3](https://github.com/yaad-index/darbaan/commit/385fea32ca5c42dcace688be94ca641d19facd18))
* bounce generation on reject (DSN into a separate inbound store) ([3b85da2](https://github.com/yaad-index/darbaan/commit/3b85da2bf918d89621f4927a9ff5540f4a92f437))
* darbaan telegram subcommand skeleton (admin-API client) ([#61](https://github.com/yaad-index/darbaan/issues/61)) ([76131c8](https://github.com/yaad-index/darbaan/commit/76131c8fc408716e21f3fccb4c28c68a7b7d783e))
* DKIM-sign bounces (ed25519), fail-closed; dkim-pubkey ([#37](https://github.com/yaad-index/darbaan/issues/37)) ([7209530](https://github.com/yaad-index/darbaan/commit/7209530aa41d12c379b57db4dfd96bf853015c7d))
* Docker support — distroless image, compose, dockerignore ([#47](https://github.com/yaad-index/darbaan/issues/47)) ([4dffd21](https://github.com/yaad-index/darbaan/commit/4dffd215867676818bd8ca7ff4d0a76dcfe29767))
* IMAP read face — serve signed bounces from the inbound store ([#38](https://github.com/yaad-index/darbaan/issues/38)) ([53d22ef](https://github.com/yaad-index/darbaan/commit/53d22efc302fd2aad1b0568981ecaa9fe4c1d025))
* kong CLI + layered config (file &lt; env &lt; flag) ([adf8437](https://github.com/yaad-index/darbaan/commit/adf8437c548537a0a2c24cf79950755b76eb74af))
* kong CLI + layered config (file &lt; env &lt; flag) ([a3bc3eb](https://github.com/yaad-index/darbaan/commit/a3bc3eb4e202778799dc28a33d2340ed419ce405))
* real Gmail SMTP Sender (the opt-in default-deny flip) ([#45](https://github.com/yaad-index/darbaan/issues/45)) ([382bf50](https://github.com/yaad-index/darbaan/commit/382bf50c905b27cb72621178d727354549d216e5))
* SMTP submission face + outbound sluice ([8653c96](https://github.com/yaad-index/darbaan/commit/8653c96826ab5eb1407eab74c8801c7d220b0303))
* SMTP submission face + outbound sluice ([2fc0a94](https://github.com/yaad-index/darbaan/commit/2fc0a943d91200ce651a54e79d8c3e97a3a46cb6))
* Subject in queue Meta, derived at list time ([#62](https://github.com/yaad-index/darbaan/issues/62)) ([17bbb2f](https://github.com/yaad-index/darbaan/commit/17bbb2fc8534b850652f52e167a7ecc197e1a7b2))
* telegram Approve callback ([#60](https://github.com/yaad-index/darbaan/issues/60) Inc 3) ([#64](https://github.com/yaad-index/darbaan/issues/64)) ([5f75dd6](https://github.com/yaad-index/darbaan/commit/5f75dd6e81501ffcec10f9abb47b2234266bb110))
* telegram notification shows display-name addresses + flags hidden recipients ([#68](https://github.com/yaad-index/darbaan/issues/68)) ([5a92083](https://github.com/yaad-index/darbaan/commit/5a92083bb75c1da3a69ee1e5c1ebdfbfae176544))
* telegram notification shows message body + map hardening ([#66](https://github.com/yaad-index/darbaan/issues/66)) ([#67](https://github.com/yaad-index/darbaan/issues/67)) ([38f5e70](https://github.com/yaad-index/darbaan/commit/38f5e70d8ea4783a4dfe976d01a97bb241e4902e))
* telegram queue notify with decision keyboard ([#60](https://github.com/yaad-index/darbaan/issues/60) Inc 2) ([#63](https://github.com/yaad-index/darbaan/issues/63)) ([dd50fb1](https://github.com/yaad-index/darbaan/commit/dd50fb107dfbabb7d53159e01b830b60266d6234))
* telegram Reject + force-reply reason ([#60](https://github.com/yaad-index/darbaan/issues/60) Inc 4) ([#65](https://github.com/yaad-index/darbaan/issues/65)) ([811a07e](https://github.com/yaad-index/darbaan/commit/811a07e2eeb69f1ec1d26bfd90ddb754df98069c))


### Bug Fixes

* audit hash must-panic + dedupe itob into seqkey ([9de0dd4](https://github.com/yaad-index/darbaan/commit/9de0dd4d9f9993258a10a760c0ed219195f4b221))
* DARBAAN_CONFIG file selection + []string env splitting ([768041d](https://github.com/yaad-index/darbaan/commit/768041d4e190b22e6f37c77b022f41efbc246c7f))
* distinguish bounce-delivery failure from reject failure ([#40](https://github.com/yaad-index/darbaan/issues/40)) ([3d07613](https://github.com/yaad-index/darbaan/commit/3d07613271aec0c8b89cd997f91eaa8747267bf7))
* DSN Final-Recipient = intended recipient(s); guard SEARCH ToLower ([#57](https://github.com/yaad-index/darbaan/issues/57)) ([6918b3b](https://github.com/yaad-index/darbaan/commit/6918b3b5e53ddac439fd71ae697e86f42285cdaf))
* honor DARBAAN_CONFIG for file selection; split []string env values ([0cfd014](https://github.com/yaad-index/darbaan/commit/0cfd014cfd1a82bdad2d44fd82adc3fc9f505f32))
* imap read face — uidNext=1 for empty mailbox; sync Seen in-session ([#41](https://github.com/yaad-index/darbaan/issues/41)) ([41bbefb](https://github.com/yaad-index/darbaan/commit/41bbefb855aa236162ea7c14086b6032a7b67a89))
* implement IMAP SEARCH (was NO [SERVERBUG], broke real clients) ([#55](https://github.com/yaad-index/darbaan/issues/55)) ([6cfbdfd](https://github.com/yaad-index/darbaan/commit/6cfbdfd3b33a66502a032f8cc1ff67a4ff63b03b))
* operator admin API for running serve (queue CLI becomes thin client) ([#52](https://github.com/yaad-index/darbaan/issues/52)) ([a910e0d](https://github.com/yaad-index/darbaan/commit/a910e0d9491ab5521a589ee82ef04698cee5f1ef))
* panic on audit hash-marshal error; extract shared seqkey helper ([153529b](https://github.com/yaad-index/darbaan/commit/153529b74649b9350a884daf6b92ca25b3ebddd8))
* telegram actually removes the keyboard on edit (empty slice, not nil) ([#70](https://github.com/yaad-index/darbaan/issues/70)) ([92fde50](https://github.com/yaad-index/darbaan/commit/92fde50b73eef55a1de216e60a78f7c1389a8818))
* telegram pre-checks message status, explains stale taps ([#71](https://github.com/yaad-index/darbaan/issues/71)) ([d962134](https://github.com/yaad-index/darbaan/commit/d96213460b3dcd19cabe873b33e9db04d1163205))
* telegram strips the reject keyboard immediately with an interim state ([#69](https://github.com/yaad-index/darbaan/issues/69)) ([02189ab](https://github.com/yaad-index/darbaan/commit/02189ab41f99d6d12a8711b5e40d4f8e07afe61a))


### Miscellaneous Chores

* release v0.1.0 ([00e4b95](https://github.com/yaad-index/darbaan/commit/00e4b95a72d76efb85ec1f578c256363c51c14a3))
