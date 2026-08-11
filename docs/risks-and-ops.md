# Ключевые риски и эксплуатация

## Highload и надёжность

1. **Разные latency-контуры.** Средний поток `2,3/s`, пик `16,7–33,3/s`; fast routing завершается durable route за p95 `<500 ms`, а retrieval/generation идут через отдельную очередь. Generation первой отключается при нагрузке, intake и risky routing сохраняются.
2. **Burst и доставка.** Durable broker, priority queues и autoscale по oldest-message age буферизуют 14× burst. Семантика at-least-once: composite event idempotency, atomic decision+audit+outbox и stable delivery ID; bounded retry с backoff+jitter заканчивается DLQ, а не бесконечным штормом.
3. **Недоступность generator/KB/DB.** Eligible safe candidate может получить только неизменённый current approved template после всех gates; иначе human. При недоступной decision/audit DB нельзя send или ACK — retry→DLQ+alert; «не записанный human fallback» не считается доставкой оператору.
4. **Массовый инцидент.** Dedupe выполняется после event-id dedupe и только на redacted text; кластер — `incident_candidate`, подтверждаемый incident manager. После подтверждения подавляются per-ticket LLM calls и используется approved status template/cache, но auto-close ждёт разрешения инцидента.

## Privacy, safety и risk

1. **PII boundary.** Raw ticket хранится отдельно encrypted/RBAC/TTL; ML, retrieval, generator, audit и metrics получают redacted/tokenized representation. Email/phone маскируются без автоматического high-risk, а card/credential/payment запрещают auto-path. Во внешний LLM raw PII не отправляется.
2. **Human-only и fail-closed.** Payments/refunds, account takeover, legal/threat/self-harm, data deletion, credentials, policy conflict, OOD и low margin всегда идут человеку. Auto — пересечение allowlist, model/retrieval margins, approved/current KB и output policy; ошибка/timeout только уменьшает coverage.
3. **Prompt injection.** Phrase rules PoC — лишь red-team signal, не защита. Основной барьер: user/KB text как untrusted data, bounded schema, approved content, no tools/secrets, policy вне prompt, запрет новых URL/claims и independent output validation.
4. **Аудит и доступ.** Каждое решение хранит reason codes и версии runtime/model/policy/KB/generator; append-only transition реплицируется в WORM, overrides принадлежат роли. PoC SHA-256 fingerprint — idempotency, не анонимизация короткого текста; production использует keyed fingerprint и отдельный restricted raw store.

Подробные failure modes и алерты: [architecture.md](architecture.md) и [monitoring.md](monitoring.md).
