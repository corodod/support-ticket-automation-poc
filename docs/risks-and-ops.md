# Ключевые риски и эксплуатация

## Highload и надёжность

1. **Разные latency-контуры.** Средний поток `2,3/s`, пик `16,7–33,3/s`; fast routing завершается durable route за p95 `<500 ms`, а retrieval/generation идут через отдельную очередь. Generation первой отключается при нагрузке, intake и risky routing сохраняются.
2. **Burst и доставка.** Durable broker, priority queues и autoscale по oldest-message age буферизуют 14× burst. Семантика at-least-once: composite event idempotency, atomic decision+audit+outbox и stable delivery ID; bounded retry с backoff+jitter заканчивается DLQ, а не бесконечным штормом.
3. **Недоступность generator/KB/DB.** Auto-template не вызывает generator; его outage затрагивает только operator-suggest, где fallback остаётся невидимым пользователю. KB miss/conflict → human; при недоступной decision/audit DB нельзя send или ACK — retry→DLQ+alert.
4. **Массовый инцидент.** Dedupe выполняется после event-id dedupe и только на redacted text; кластер — `incident_candidate`, подтверждаемый incident manager. После подтверждения подавляются per-ticket LLM calls и используется approved status template/cache, но auto-close ждёт разрешения инцидента.

## Privacy, safety и risk

1. **PII boundary.** Raw ticket хранится отдельно encrypted/RBAC/TTL; downstream получает typed/redacted representation. Email/phone маскируются без high-risk, а card/credential/one-time-code/passport/SNILS/payment запрещают auto-path. PoC detectors не считаются полноценным DLP.
2. **Human-only и fail-closed.** Payments/refunds, takeover, legal/threat/self-harm, data deletion, secrets, OOD, mixed/unsupported scope и classifier↔retrieval conflict всегда идут человеку. Verification-code/password — только operator-suggest; auto — exact language template после всех независимых gates. Ошибка только уменьшает capability.
3. **Prompt injection.** Phrase rules PoC — лишь red-team signal, не защита. Основной барьер: user/KB text как untrusted data, bounded schema, approved content, no tools/secrets, policy вне prompt, запрет новых URL/claims и independent output validation.
4. **Аудит и доступ.** Решение хранит candidate/effective action, delivery/outcome, reason codes, article/template hash и версии всех gates; append-only transition реплицируется в WORM. PoC SHA-256 fingerprint — idempotency, не анонимизация; production использует keyed fingerprint и pre-send revocation/authorization TTL.

Подробные failure modes и алерты: [architecture.md](architecture.md) и [monitoring.md](monitoring.md).
