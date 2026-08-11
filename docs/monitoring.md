# Наблюдаемость и эксплуатационный контроль

PoC audit связывает событие с `runtime/schema`, model+train hash, policy, retriever+KB, generator version, intent/risk/action и channel; raw text/PII в нём нет. Target contract дополнительно вводит language, product и incident flag. Audit пишется на 100% решений, а метрики агрегируются по этим безопасным полям.

## Что измеряем

| Уровень | Метрики |
|---|---|
| Технический | intake RPS/error; durable-ACK latency; oldest-message age по priority queue; fast-route p50/p95/p99; retry/DLQ; DB transaction/error; outbox lag; dispatcher delivery/error; generation/retrieval latency и availability. |
| ML/safety | intent macro-F1/per-class recall на delayed labels; abstain/coverage; score+margin distributions; ECE/Brier; rule–model conflicts; risky recall/FNR; OOS auto; retrieval Recall@k/MRR/no-result; output rejects, PII leaks, template fallback и unsafe auto. |
| Product/business | Safe Automated Resolution Rate; suggest acceptance/edit; AHT и transfers; 7-day reopen; CSAT; first-response SLA breach; released operator capacity; incident backlog/age. |
| Cost | ₽ на входящий/eligible/resolved ticket; LLM calls/tokens/GPU-seconds; cache/template hit; duplicate suppression; forecast к daily/monthly/category budget. В PoC inference cost = 0, target-планирование считает полный cost. |

Online proxy не заменяет labels. Safety quality считается на stratified audited sample с oversampling auto, risk, low-margin, new language/channel и incident cohorts; reopen/CSAT созревают с задержкой и фиксируются по cohort version.

## Стартовые SLO и алерты

| Severity | Условие | Автоматическое действие / владелец |
|---|---|---|
| P0 | Любой подтверждённый critical unsafe auto-reply или PII в outbound | Global kill switch auto-path, сохранить evidence, Security+Support incident. |
| P0 | Decision/audit DB недоступна или audit/outbox transaction errors >0,5% за 5 мин | Не ACK/не send; retry→DLQ, page SRE. Нельзя подменять это незафиксированным `human_review`. |
| P1 | fast-route p95 `>500 ms` 5 мин либо critical queue age `>60 s` | Autoscale workers, shed generation/suggest, сохранить risk routing; SRE. |
| P1 | Lower 95% confidence bound risky recall `<99%` при `n≥1000` audited risky; один risky auto не ждёт окна | Category kill switch, rollback model/policy, ML+Safety review. |
| P1 | 7-day reopen `>10%`, CSAT delta к control `<−0,10` или SLA breach `>5%` | Откат auto→suggest feature flag; Product owner. |
| P2 | Abstain/no-result/output-reject >2× 28-day same-weekday baseline 30 мин | Заморозить expansion, запустить drift diagnosis; ML/KB owner. |
| P2 | Forecast spend >110% budget или cost/resolved +20% WoW | Template/cache mode, ограничить LLM category quota; FinOps/ML. |

Для редкого safety event процентный alert недостаточен: один подтверждённый случай — P0. Для noisy traffic используются minimum-volume и burn-rate окна, чтобы малые знаменатели не создавали ложные страницы.

## Model degradation или изменившийся поток

1. Проверить pipeline health: schema errors, redaction, feature/index/model versions, latency и fixed golden replay. Если fixed set ухудшился на том же artifact — regression реализации/data contract; rollback.
2. Если fixed set стабилен, сравнить live channel/language/intent/OOD/PII/length distributions с reference (PSI/JSD + доли, не один aggregate). Одновременный рост OOD/abstain означает input/concept shift, а не обязательно поломку модели.
3. Сверить delayed human labels по стабильным slices. Stable input + падение label quality указывает на model/taxonomy decay; stable classifier + рост retrieval no-result — на KB freshness/index; рост reopen только у одной статьи — на content problem.
4. Не retrain автоматически. Собрать stratified sample, проверить разметку/seasonality/incident, обновить data card, прогнать temporal test и shadow candidate. Policy threshold/KB можно откатить независимо от model.

Reason-code dashboard показывает, *почему* меняется coverage: `UNKNOWN`, low class margin, low retrieval, expired/not-approved article, high risk, output reject или provider outage. Это отличает безопасное снижение автоматизации от незаметного роста unsafe coverage.

## Проверка исходной задачи и runbook

Главный граф — North Star и guardrails рядом с AHT/operator backlog и cost, обязательно против shadow/A/B control. Высокий macro-F1 без снижения SLA/AHT или при росте reopen не считается успехом. Incident view отдельно показывает duplicate suppression и oldest-ticket age.

При алерте on-call фиксирует affected cohort/versions, включает category/global kill switch, проверяет queue/outbox/DLQ и откатывает immutable artifact pointer. Replay выполняется с прежним idempotency key: решение/ответ не пересчитывается молча. После инцидента — sampled audit, root cause, новый regression case и явный owner/date исправления.
