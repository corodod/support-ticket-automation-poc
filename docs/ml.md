# ML, retrieval и генерация

## Декомпозиция вместо «одной умной модели»

| Задача | MVP / PoC | Target и причина |
|---|---|---|
| Hard safety | Versioned rules для payment, account security, legal/privacy, prompt-injection signals и sensitive PII | Policy/risk engine с владельцами правил и emergency flags. Редкие критичные классы нельзя отдавать только ML. |
| Intent | char `TF-IDF 3–5` + balanced Logistic Regression + sigmoid calibration | Начать с интерпретируемого CPU-baseline; сравнить с compact multilingual encoder только при доказанном выигрыше risk–coverage/latency. |
| OOD/неуверенность | top-1 score + top1–top2 margin + `unknown`; конфликт с rules → human | Energy/distance/OOD model можно добавить после появления репрезентативного live-набора. Ошибка abstain дешевле unsafe auto. |
| KB retrieval | char TF-IDF cosine, topic filter, top-2 score/margin, article metadata | Hybrid BM25+dense + metadata filters + reranker при росте/мультиязычности KB. Vector DB для шести статей не нужен. |
| Ответ | Grounded mock composer; при outage — exact approved template | Auto MVP — только static template. Private/managed LLM сначала для summary/translation/operator-suggest, не для действий. |
| Incident signal | Redacted TF-IDF near-duplicate batch, без auto-close | Rolling clustering + burst detector + service telemetry; incident manager подтверждает кластер. |

LLM не определяет risk, маршрут, refund, блокировку аккаунта, policy или факт выполненной операции. У неё нет tools/credentials. User и retrieved text — недоверенные данные внутри bounded structured context; решение об отправке принимает внешний deterministic policy.

## Что реально обучается в PoC

[`classifier.py`](../ticket_automation/classifier.py) обучает локально модель из репозиторных данных: char-TF-IDF (`char_wb`, 3–5 grams, до 20k features) → class-balanced Logistic Regression → `CalibratedClassifierCV(method=sigmoid, cv=3)`. Открытые веса и внешние API не используются; зависимость — scikit-learn. Версия содержит hash train-файла.

`72` синтетических train-примера покрывают шесть intent, даты `2026-01-02…03-14`; `24` validation-примера идут позже, `2026-06-02…06-25`. Conversation IDs не пересекаются. На validation вручную сравниваются risk–coverage scenarios; выбраны консервативные abstain-пороги `0,45 / 0,15` и automation-пороги `0,65 / 0,35`, не автоматический optimum. Golden не использовался для threshold selection, но все наборы синтетические и лежат в одном репозитории: это процедурное разделение, не независимый production holdout.

KB — versioned JSON: `intent`, `status`, `auto_reply_allowed`, `version`, `valid_until`. Retrieval «нашёл статью» не означает «можно отправить»: дополнительно нужны intent match, score `≥0,10`, margin `≥0,06`, low risk и output pass. Низкие абсолютные cosine-пороги отражают маленькие длинные документы; они должны быть переоценены на relevance labels.

## Исполняемая оценка и её границы

Команда `python -m scripts.evaluate` воспроизводит [`evaluation.json`](../reports/evaluation.json). Development red-team (`36`) отделён от golden (`30`), зафиксированного после policy thresholds.

| Метрика | Результат | Интерпретация |
|---|---:|---|
| Validation closed-set macro-F1 / accuracy | `1,000 / 1,000` на 24 | Набор мал и лексически простой; это smoke gate, не прогноз live-качества. |
| Brier / ECE (10 bins) | `0,122 / 0,2903` | На 24 простых строках scores выглядят underconfident; calibration production не доказана, ECE здесь нестабилен. |
| Golden risky escalation recall / unsafe auto | `1,000 / 0` | Обязательный synthetic safety gate. |
| Golden safe-auto precision / eligible coverage | `1,000 / 0,625` | Policy сознательно теряет coverage ради precision. |
| Golden OOS classifier accept / OOS auto | `0,3333 / 0` | Классификатор ошибается на OOS, но KB/policy layers не дают отправить ответ. |
| Golden risk precision | `0,8889` | Есть безопасный false positive — лишняя human escalation, требующая улучшения rules/OOD. |
| Retrieval Recall@1 / MRR | `1,000 / 1,000` на 18 | По одному простому article/intent; production retrieval этим не доказан. |
| Raw PII leakage | `0` | Проверены decision, audit и outbox/draft на synthetic literals; regex coverage не заменяет DLP/red-team. |

Пять auto-кейсов без ошибки дают rule-of-three upper 95% bound около `60%`, а не «нулевой production-risk». Чтобы лишь приблизить верхнюю границу к `0,1%`, нужно около 3 000 независимо проверенных кандидатов без ошибки. Поэтому golden используется как regression, а не как основание включить auto-close.

## Production-данные, разметка и validation

Нужен обезличенный historical corpus с `created_at`, channel/language/product, conversation/user/incident group, intent, risk/human-only labels, релевантностью KB, operator edit/reject, resolution, reopen, CSAT и SLA. Risk и 1–2 pilot intents размечают два support SME; disagreement adjudicates policy owner, считаются agreement и confusion causes. PII удаляется до разметки; raw доступен лишь privacy-approved роли.

Split — temporal и одновременно group-aware по conversation/user/incident/template, иначе дубли массового сбоя попадут в train/test. Схема: train на прошлом окне, validation для threshold/calibration, один untouched test; затем rolling backtest по channel/language и incident/non-incident slices. Нельзя подбирать threshold на golden и им же доказывать качество.

Выбор threshold оптимизирует business cost и строит risk–coverage curve: hard gates — risky false-negative/unsafe auto; затем safe-auto precision, coverage и operator load. Для intent — macro-F1 и per-class recall; для calibration — Brier/ECE; для retrieval — Recall@k, MRR, no-result; end-to-end — unsafe auto, eligible coverage, PII leakage, fallback/reason distribution.

Feedback не означает auto-retrain: override/edit/reopen попадают в versioned snapshot, drift запускает labeling и offline evaluation; candidate проходит shadow и canary. Promotion требует approval и сохраняет прежние model/policy/KB версии для rollback.

## Где уместна LLM и как ограничивается

PoC внешнюю LLM не вызывает: mock доказывает contract, grounding/output check и outage injection, но ничего не говорит о языковом качестве. В target LLM полезна для grounded draft, summary, extraction и translation; на первом rollout только оператор видит результат. Auto-path остаётся exact approved template, пока пилот не докажет отдельный safety gate.

LLM-eval включает source attribution/groundedness, unsupported claims, policy/PII violations, operator acceptance/edit distance, latency и ₽/resolved ticket; human review обязательно стратифицируется по intent/risk/language. Cost controls: не вызывать LLM для duplicate/known template, token limits, cache по redacted request+KB version, cheap/default model cascade, daily/category budgets и circuit breaker. Timeout никогда не расширяет automation: approved template после всех gates либо human.
