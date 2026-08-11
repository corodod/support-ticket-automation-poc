# Self-review

## Самая слабая часть

Главная слабость — данные, а не orchestration. Train/validation/red-team/golden синтетические, маленькие и созданы рядом с решением; `macro-F1=1,0` показывает лишь исполняемость baseline. На golden классификатор принимает 33,3% OOS, а offline global retrieval один раз ставит правильную статью второй; ранний scope gate оставляет этот case human. Три golden auto без ошибки дают лишь тривиальный rule-of-three upper 95% bound `100%`, поэтому safety в production не доказана.

Regex PII/risk и lexical safe-scope имеют неизбежные false negatives/positives даже после добавления passport/SNILS/password и mutation red-team. Маленькая KB не проверяет multilingual retrieval, конфликтующие статьи, stale content и indirect injection. SQLite демонстрирует атомарность, но не broker/dispatcher, distributed reservation, encryption/RBAC или реальную CRM-доставку; concurrent duplicates могут дважды выполнить дешёвое вычисление до единственного commit.

## Предположения и нерешённые риски

- Бизнес-вводные кейса верны; MVP автоматизирует 10% всего потока, 70% released capacity реализуется, inference upper bound — 1,5 ₽/auto, fixed Ops — 40 млн ₽/год.
- `event_id` в PoC глобально уникален; target использует `(channel, source_event_id)` и collision quarantine.
- Support/Policy owners могут поддерживать article status, expiry и allowlist; без этого технические gates бесполезны.
- Exact template предположительно достаточен только для первого language FAQ; verification-code/password остаются suggest-only, персонализированное состояние и действия — human.
- Реальные channel/language/product proportions, class imbalance, label agreement, provider limits и data-retention policy неизвестны.

## Что улучшить за два дополнительных дня

Сначала взял бы 300–500 обезличенных temporal tickets и 50–100 incident duplicates, сделал double-label для risk/intent/relevance, agreement и grouped split. Затем построил бы confusion/OOD и risk–coverage по slices, проверил calibration и retrieval no-result на реальном языке, добавил DLP/red-team cases. Параллельно заменил бы CLI-boundary на небольшой adapter contract, Postgres transaction/outbox и fault-injected dispatcher stub, чтобы доказать no-send при DB failure и stable delivery ID. Последний блок — shadow event schema для operator accept/edit/reject, reopen/CSAT/SLA и dashboard reason codes.

## До production

Нужны managed broker и Postgres, raw store с KMS/TLS/RBAC/TTL, secret management, schema registry/expand-contract migrations, dispatcher retries/DLQ/replay, WORM audit, signed model/policy/KB artifacts, category/global kill switches и tested rollback. До auto-mode обязательны privacy/security review, real incident drill, operator runbook/on-call, capacity/load test и независимый pilot audit минимум на тысячи кандидатов. Любой LLM сначала работает только в suggest и проходит отдельный groundedness/policy/cost evaluation.

## Что не автоматизировать полностью

Refund/payment decisions, account takeover/identity, blocking/unblocking, data deletion/privacy requests, legal/threat/self-harm, credentials, complaints, policy conflicts, unknown/low-margin, unsupported language, stale KB и подтверждение/закрытие инцидента требуют человека. Модель может суммаризировать или предложить источник, но не совершать действие и не утверждать, что оно выполнено.

## Какие данные остановят проект

Один critical unsafe auto-reply немедленно останавливает auto-mode; повтор после root-cause fix и узкого rerun заставит отказаться от автономного контура, оставив routing/suggest. Продукт целиком не стоит продолжать, если после достаточно мощного H1-пилота upper 95% CI снижения AHT остаётся <5% или acceptance <35%, а H2 не может достичь lower 95% CI precision 99,5% и North Star 9% без reopen >10%, CSAT delta ≤−0,10 либо ухудшения SLA. Также stop — подтверждённый net capacity effect ≤0 после фактических inference/Ops/reopen costs: высокая automation rate сама по себе не оправдывает вред или отрицательную экономику.
