# ML, retrieval и генерация

## Декомпозиция вместо «одной умной модели»

| Задача | MVP / PoC | Target и причина |
|---|---|---|
| Hard safety | Risk-first taxonomy для payment/security/privacy/self-harm, typed PII и full-request scope/multi-intent gate | Policy/risk engine с владельцами правил и emergency flags. Позитивный safe intent не считается отсутствием другого риска. |
| Intent | char `TF-IDF 3–5` + balanced Logistic Regression + sigmoid calibration | Начать с интерпретируемого CPU-baseline; сравнить с compact multilingual encoder только при доказанном выигрыше risk–coverage/latency. |
| OOD/неуверенность | top-1 score + top1–top2 margin + `unknown`; конфликт с rules → human | Energy/distance/OOD model можно добавить после появления репрезентативного live-набора. Ошибка abstain дешевле unsafe auto. |
| KB retrieval | Один immutable global char-TF-IDF index, top-2 score/margin и classifier↔article consensus | Hybrid BM25+dense + metadata filters + reranker при росте/мультиязычности KB. Disagreement уменьшает capability, а не усредняется. |
| Ответ | Exact template напрямую для auto; grounded mock/fallback только для operator-suggest | Private/managed LLM сначала для summary/translation/suggest, никогда не авторизует user-visible действие. |
| Incident signal | Redacted TF-IDF near-duplicate batch, без auto-close | Rolling clustering + burst detector + service telemetry; incident manager подтверждает кластер. |

LLM не определяет risk, маршрут, refund, блокировку аккаунта, policy или факт выполненной операции. У неё нет tools/credentials. User и retrieved text — недоверенные данные внутри bounded structured context; решение об отправке принимает внешний deterministic policy.

## Что реально обучается в PoC

[`classifier.py`](../ticket_automation/classifier.py) обучает локально модель из репозиторных данных: char-TF-IDF (`char_wb`, 3–5 grams, до 20k features) → class-balanced Logistic Regression → `CalibratedClassifierCV(method=sigmoid, cv=3)`. Открытые веса и внешние API не используются; зависимость — scikit-learn. Версия содержит hash train-файла.

`72` синтетических train-примера покрывают шесть intent, даты `2026-01-02…03-14`; `24` validation-примера идут позже, `2026-06-02…06-25`. Conversation IDs не пересекаются. На validation вручную сравниваются risk–coverage scenarios; выбраны консервативные abstain-пороги `0,45 / 0,15` и automation-пороги `0,65 / 0,35`, не автоматический optimum. Golden не использовался для threshold selection, но все наборы синтетические и лежат в одном репозитории: это процедурное разделение, не независимый production holdout.

KB — versioned JSON: `intent`, `status`, `auto_reply_allowed`, `version`, `valid_until`. Index обучается один раз на полной версии KB; query не меняет IDF, а approval/current проверяются policy после ranking. Retrieval «нашёл статью» не означает «можно отправить»: нужны agreement с classifier, score `≥0,10`, margin `≥0,06`, low risk, полный safe scope и output pass. Auto-capability в PoC есть только у language (`0,65/0,35`); verification-code намеренно `operator_suggest`, потому что unsolicited-code/account-takeover semantics нельзя надёжно исключить одной лексикой.

## Исполняемая оценка и её границы

Команда `python -m scripts.evaluate` воспроизводит [`evaluation.json`](../reports/evaluation.json). Development red-team (`55`) и 34 программно созданных mixed-risk/scope mutations отделены от golden (`30`), зафиксированного после policy thresholds.

| Метрика | Результат | Интерпретация |
|---|---:|---|
| Validation closed-set macro-F1 / accuracy | `1,000 / 1,000` на 24 | Набор мал и лексически простой; это smoke gate, не прогноз live-качества. |
| Brier / ECE (10 bins) | `0,122 / 0,2903` | На 24 простых строках scores выглядят underconfident; calibration production не доказана, ECE здесь нестабилен. |
| Golden risky escalation recall / unsafe auto | `1,000 / 0` | Обязательный synthetic safety gate. |
| Golden safe-auto precision / eligible coverage | `1,000 / 0,600` | Три language-template авторизованы; два слабых safe-кандидата понижены до operator-suggest. |
| Golden OOS classifier accept / OOS auto | `0,3333 / 0` | Классификатор ошибается на OOS, но KB/policy layers не дают отправить ответ. |
| Red-team + generated mutations unsafe auto | `0 + 0` | Все 34 transformations, включая вторую просьбу, account-security и unsupported script, лишены auto capability. |
| Golden risk precision / recall | `1,000 / 1,000` | На малой синтетике; rule paraphrases всё равно не дают production guarantee. |
| Global retrieval Recall@1 / MRR | `0,9444 / 0,9722` на 18 | Один offline rank miss виден; golden scope gate раньше оставляет case human, а отдельный red-team/test исполняет consensus reject. |
| Raw PII leakage | `0` | Проверены decision, audit и outbox/draft на synthetic literals; regex coverage не заменяет DLP/red-team. |

Executable hard gates запрещают unsafe/capability-expanding action, raw-PII leak, OOS/disagreement/mutation auto и потерю ожидаемого suggestion lane; дополнительно требуют хотя бы `0,50` coverage на независимо помеченном `safe_eligible` slice, чтобы вырожденная policy «всё человеку» не получила PASS.

Три golden auto-кейса без ошибки дают тривиальный rule-of-three upper 95% bound `100%`, а не «нулевой production-risk»; семь development red-team auto также не являются независимым holdout. Чтобы лишь приблизить верхнюю границу к `0,1%`, нужно около 3 000 независимо проверенных кандидатов без ошибки. Поэтому golden используется как regression, а не как основание включить auto-close.

## Production-данные, разметка и validation

Нужен обезличенный historical corpus с `created_at`, channel/language/product, conversation/user/incident group, intent, risk/human-only labels, релевантностью KB, operator edit/reject, resolution, reopen, CSAT и SLA. Risk и первый auto-pilot intent размечают два support SME; disagreement adjudicates policy owner, считаются agreement и confusion causes. PII удаляется до разметки; raw доступен лишь privacy-approved роли.

Split — temporal и одновременно group-aware по conversation/user/incident/template, иначе дубли массового сбоя попадут в train/test. Схема: train на прошлом окне, validation для threshold/calibration, один untouched test; затем rolling backtest по channel/language и incident/non-incident slices. Нельзя подбирать threshold на golden и им же доказывать качество.

Выбор threshold делается per intent как constrained optimization: максимальный эффект/coverage при lower confidence bound precision, risky false-negative=0 на gate, reopen/CSAT/SLA и operator load. Для intent — macro-F1, per-class recall и selective risk; для calibration — Brier/ECE; для retrieval — Recall@k, MRR, no-result/disagreement; end-to-end — три lane, mutation unsafe auto, PII leakage и reason distribution. Confidence и retrieval score не смешиваются в один непрозрачный балл.

Feedback не означает auto-retrain: override/edit/reopen попадают в versioned snapshot, но accept/reject лог сам по себе selection-biased, поэтому случайно аудируются также auto и abstain cohorts. Drift запускает labeling и offline evaluation; candidate проходит shadow и canary. Promotion требует approval и сохраняет прежние model/policy/KB версии для rollback.

## Где уместна LLM и как ограничивается

PoC внешнюю LLM не вызывает. Auto-path вообще обходит generator и рендерит exact approved template по article version/hash. Mock доказывает bounded redacted contract и outage только для `operator_suggest`; при сбое оператор видит точный approved fragment, пользователь — ничего. В target LLM полезна для grounded draft, summary, extraction и translation, но не меняет candidate/effective action.

LLM-eval включает source attribution/groundedness, unsupported claims, policy/PII violations, operator acceptance/edit distance, latency и ₽/resolved ticket; human review обязательно стратифицируется по intent/risk/language. Cost controls: не вызывать LLM для duplicate/known template, token limits, cache по redacted request+KB version, cheap/default model cascade, daily/category budgets и circuit breaker. Timeout никогда не расширяет automation: operator-suggest получает approved fragment либо human fallback, а auto-template от LLM не зависит.
