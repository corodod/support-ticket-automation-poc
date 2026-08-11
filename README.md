# Support Ticket Automation PoC

Safety-first система для маршрутизации тикетов и ступенчатой автоматизации: `human_only`, `operator_suggest`, `auto_template`. Она сочетает risk-first PII/scope rules, локальный calibrated TF-IDF+LogReg classifier, неизменяемый global KB index, deterministic capability policy, exact-template renderer, mock composer только для оператора и атомарный SQLite `decision + audit + outbox`. Внешняя LLM, API-ключи и сеть во время работы не нужны.

## Зачем это бизнесу

Система снимает повторяющийся поиск и маршрутизацию, не превращая поддержку в неконтролируемого чат-бота. Пользователь быстрее получает утверждённый ответ по безопасному FAQ, а сложный случай сразу идёт нужной очереди. Оператор получает тему, risk, статью и draft вместо ручного чтения и поиска. Бизнес получает дополнительную ёмкость на пиках, измеряемый путь к снижению cost per resolved ticket и kill switch, который защищает CSAT, reopen и SLA.

Контекст кейса: `200k` тикетов/день (`≈2,3/s`), пики `10–20k / 10 мин` (`16,7–33,3/s`), первый ответ за 15 минут и fast-route ориентир `<500 ms`. Главный design trade-off — пожертвовать automation coverage, если нельзя доказать безопасность ответа.

## Быстрый запуск

Нужен Python 3.11. Команды ниже для macOS/Linux; в Windows используйте соответствующие пути `Scripts`.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/ticket-poc --demo
```

Demo выполняет три end-to-end сценария:

- happy: смена языка → classifier/retrieval consensus → exact template с состоянием `send_pending`;
- risky: двойное списание + валидная карта → ранний `payments_priority`, ML/retrieval не вызываются;
- degraded: generator unavailable → approved password suggestion только оператору, без user-visible send.

Отдельный case-specific сигнал массового инцидента:

```bash
.venv/bin/ticket-incident-demo
```

Он дедуплицирует повтор `event_id`, группирует только redacted near-duplicates и возвращает `incident_candidate`; auto-close всегда `false`.

## Проверка

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m scripts.evaluate
.venv/bin/python -m scripts.benchmark --iterations 500
.venv/bin/python -m scripts.verify_submission --allow-missing-ai-usage
```

Последняя команда — development-mode до появления `AI_USAGE.md`. Перед сдачей файл обязателен, и verifier нужно запускать без флага:

```bash
.venv/bin/python -m scripts.verify_submission
```

Зафиксированные результаты: 53 теста; на synthetic golden `risky escalation recall=1,0`, `unsafe auto=0`, `OOS auto=0`, safe-auto precision `1,0`, eligible-safe coverage `0,60`; оба неавторизованных safe-кандидата безопасно понижены до suggestion. Все 34 программные mixed-risk/scope mutations заблокированы. Global retrieval даёт Recall@1 `0,9444`, MRR `0,9722` на 18 golden rows; отдельный red-team disagreement не авторизован. Local warm benchmark на этом Mac: p99 `5,404 ms`, `355,07 tickets/s`. [`evaluation.json`](reports/evaluation.json) показывает три lane, отсутствие capability expansion и слабость малой выборки; [`benchmark.json`](reports/benchmark.json) помечен как local PoC, а не production SLO.

## Что реализовано, а что только спроектировано

| Реальный PoC | Production target |
|---|---|
| Один Python process, CLI | Channel adapters, durable broker, stateless workers |
| Synthetic data: 72 train / 24 validation / 55 red-team + 34 mutations / 30 golden | Обезличенный temporal+group split, data/label governance |
| Calibrated char-TF-IDF+LogReg и отдельный rules baseline | Registry, shadow/canary, OOD monitoring, rollback |
| 6 versioned KB articles, заранее построенный global lexical index + consensus | Approved hybrid retrieval, metadata filters, rerank/cache |
| Exact template напрямую для auto; mock/fallback только для operator-suggest | Private/managed LLM только в suggest после отдельной оценки |
| SQLite atomic decision/audit/outbox | Postgres, CDC→WORM audit, idempotent dispatcher, retries/DLQ |
| Fault injection, golden eval, local benchmark | CRM integration, RBAC/KMS/TTL, feature flags, on-call/runbooks |

PoC не отправляет ответы реальным пользователям и не закрывает CRM tickets: `auto_reply` означает лишь авторизацию, а `delivery_state=send_pending`; outcome остаётся `unknown`. В автономный режим допущен только ultra-narrow language FAQ; verification-code и password остаются operator-suggest из-за account-security ambiguity. Regex/lexical safety boundary, tiny synthetic corpus, small KB и single-process concurrency — ограничения, а не production claims. Zero unsafe на трёх golden auto-cases не доказывает безопасность в эксплуатации.

## Навигация

- [Продуктовый дизайн](docs/product.md)
- [Архитектура и проверенный SVG](docs/architecture.md)
- [ML, retrieval и LLM boundaries](docs/ml.md)
- [Monitoring и alerts](docs/monitoring.md)
- [Короткий risks & ops](docs/risks-and-ops.md)
- [WORKLOG](WORKLOG.md)
- [SELF_REVIEW](SELF_REVIEW.md)
- [Policy config](config/policy.json), [KB](data/knowledge_base.json), [tests](tests/)

Ключевой инвариант: `high risk / human-only / unknown / mixed scope / classifier↔retrieval conflict ⇒ never auto_reply`; любое разрешённое auto-сообщение — точный versioned template после всех gates и durable audit, но ещё не доказанная доставка или resolution.
