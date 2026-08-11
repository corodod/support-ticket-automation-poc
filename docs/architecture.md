# Архитектура

## Рамка решения

Средний поток — `200 000 / 86 400 ≈ 2,3` тикета/с, пик — `10–20 тыс. / 10 мин ≈ 16,7–33,3` тикета/с. Это не hyperscale-задача; сложность создают 14-кратный burst, дубли одного инцидента, 15-минутный SLA и цена небезопасного ответа. Target проектируется на `100 events/s` с запасом, но масштабируется по возрасту очереди и SLA, а не только по CPU.

Граница fast route: от получения события routing-worker из broker до атомарно сохранённого маршрута — p95 `<500 ms`. Intake отдельно подтверждает канал только после durable enqueue, ориентир p95 `<100 ms`. Retrieval, генерация и доставка не входят в fast-route SLO и работают асинхронно.

![Целевая архитектура](diagrams/system.svg)

[Mermaid-исходник диаграммы](diagrams/system.mmd)

## Поток данных и состояния

1. Адаптер валидирует контракт, строит ключ `(channel, source_event_id)` и canonical fingerprint. PII tokenizer выдаёт redacted-текст и typed findings (`card_number`, `credential`), которые hard-risk rules видят без раскрытия значения. Raw-текст сохраняется отдельно в шифрованном хранилище с узким RBAC/TTL. Повтор того же ключа возвращает прежний результат, другой fingerprint означает collision и quarantine.
2. Durable broker буферизует burst. Idempotent worker сначала применяет hard-risk/PII rules, затем локальный intent classifier. Policy выбирает только маршрут — модель не вызывает tools и не совершает действий.
3. В одной Postgres-транзакции сохраняются `Decision`, append-only audit transition и outbox. Risky/unknown сразу попадает в приоритетную human queue; безопасный кандидат — в generation queue. До commit нет ни ответа, ни ACK исходного broker-message.
4. Slow path проверяет confirmed-incident cache, ищет статью только в approved/current KB, формирует exact template для auto-path либо LLM-draft для suggest, затем независимо проверяет output. Final state и outbox снова фиксируются атомарно; dispatcher отправляет по стабильному `delivery_id`.
5. Operator approve/edit/reject возвращается как versioned event в final transaction/outbox; human reply или approved draft отправляет тот же idempotent dispatcher. Reopen, CSAT и SLA затем попадают в warehouse и связываются с версиями модели, policy, KB и generator.

Production state machine: `accepted → routed_human | generation_pending → reply_authorized → send_pending → sent | failed`. Retry имеет ключ `event_id + stage + version` и не пересчитывает уже авторизованный текст.

Event/API contracts имеют явную версию, consumers поддерживают `N` и `N−1`. DB меняется по expand/contract: additive schema + dual-read/write, backfill, переключение feature flag, затем удаление старого поля только после обновления consumers. Старые schema/model/policy/KB artifacts сохраняются на время rollback.

## Компоненты и хранилища

| Компонент | Ответственность и выбор |
|---|---|
| Adapters + broker | Единый versioned event contract, at-least-once delivery, priority topics. Broker нужен для burst/backpressure; exactly-once не обещается. |
| Risk + intent workers | Stateless horizontal workers: детерминированный hard-risk и дешёвый локальный ML. Если ML недоступен, fail-closed routing; auto-path выключен. |
| Postgres + outbox | Источник истины для state transitions, idempotency и доставки без unsafe dual-write. Audit реплицируется из outbox в WORM; raw ticket здесь не хранится. |
| Human/generation queues | Payment/security/legal выше обычных тикетов; generation shed первой. Autoscale по oldest-message age и прогнозу SLA. |
| KB/retrieval | Target contract: `status`, `intent`, locale/product, owner, `valid_until`, `auto_reply_allowed`. Target search — metadata filter + BM25/dense + rerank; cache keyed by KB version. PoC реализует сокращённый contract. |
| Composer + output policy | Auto MVP отправляет только static approved template. Private/managed LLM допустим для operator-suggest; bounded structured context, без raw PII/tools. |
| Dispatcher | Идемпотентная отправка в CRM/канал, exponential backoff+jitter, retry budget и DLQ. Он читает outbox и не принимает semantic-решений. |
| Control plane | Подписанные model/policy/KB artifacts, staged rollout, allowlist категории, category/global kill switch, rollback без deploy. |

## Инварианты безопасности

- `high_risk OR human_only OR unknown ⇒ action != auto_reply`.
- `auto_reply` возможен только при одновременном прохождении class top-1/margin, OOD, KB status/expiry/allowlist/intent, retrieval score/margin, output и durable-audit gates.
- Raw PII не попадает в classifier/retrieval/generator logs и метрики; LLM видит только bounded redacted context. Email/phone маскируются, а card/credential/payment запрещают auto-path.
- Нет user-visible send до commit `decision + audit + outbox`; при недоступной БД событие не ACK, повторяется, затем DLQ+alert. Нельзя притвориться, что оно «передано человеку» без durable записи.
- User/KB text считается недоверенными данными. Prompt не может изменить policy; generator не имеет credentials, tools или права выбрать действие.

## Надёжность и деградации

| Сбой | Поведение |
|---|---|
| LLM timeout/unavailable | После всех pre-gates — неизменённый current approved template; иначе human. Fast route не ждёт LLM. |
| Retrieval/KB unavailable | Cache последней подписанной версии только для exact safe template; cache miss → human, не свободная генерация. |
| DB/audit unavailable | Не отправлять и не ACK; bounded retry → DLQ + page. Availability уступает auditability. |
| Burst/incident | Priority queues, autoscale по queue age; отключить suggest/generation первой. Redacted dedup создаёт лишь `incident_candidate`; incident manager подтверждает. |
| Poison message/provider outage | Schema quarantine либо bounded retry/backoff; DLQ имеет replay tooling и сохраняет idempotency key. |

Delivery — at-least-once с idempotent consumer/dispatcher. Два конкурентных worker могут повторить дешёвое вычисление до commit, но только одна транзакция создаёт decision/outbox; production reservation/state-stage keys дополнительно убирают повтор дорогой генерации.

## PoC и путь эволюции

PoC — modular monolith: dataclasses, redaction/Luhn, calibrated TF-IDF+LogReg, lexical retrieval, independent policies, mock composer, SQLite transaction, CLI, golden evaluation и fault tests. Он реально доказывает orchestration, abstain, template fallback, idempotency и audit-before-outbox; не реализует API, broker, dispatcher, RBAC/encryption, WORM или distributed concurrency.

Выбор осознанный: Kafka/FastAPI/vector DB/Kubernetes не улучшают доказательство при `33 events/s`. Следующий шаг — adapters + managed broker + Postgres/outbox и shadow integration с CRM; затем suggest; лишь после pilot safety gates — узкий exact-template auto-path. Смена TF-IDF на embeddings/LLM не меняет contracts и deterministic authorization policy.
