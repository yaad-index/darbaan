# Changelog

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
