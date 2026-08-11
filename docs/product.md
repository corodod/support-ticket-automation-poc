# Продуктовый дизайн

## Проблема и ценность

Первичная боль — ограниченная пропускная способность поддержки: около 40% из 200 тыс. ежедневных тикетов типовые, но оператор всё равно тратит на каждый около 8 минут. Во время инцидентов это превращается в backlog и SLA-риск. MVP снимает повторяющуюся работу, не автоматизируя платежи, безопасность и другие чувствительные решения.

- **Пользователь:** получает утверждённый ответ по безопасному FAQ без ожидания, а сложный случай сразу попадает нужной команде без повторного объяснения.
- **Оператор:** видит intent/risk, релевантную статью и черновик с источником, поэтому меньше читает, ищет и переводит тикеты между очередями.
- **Бизнес:** получает измеримую ёмкость и устойчивость к пикам, а затем снижение переменной стоимости при ограниченных CSAT, reopen и safety-рисках.

## Приоритет гипотез

Эффект, риск и стоимость проверки: Н/С/В; охват — доля всего потока.

| № | Гипотеза | Охват | Эффект | Риск | Проверка |
|---:|---|---:|:---:|:---:|---|
| **H1** | Approved KB suggestion снизит AHT ≥10%, acceptance будет ≥50% | ≈40% | В | Н | С: shadow+A/B |
| **H2** | Exact-template auto-response даст 10% coverage и ≥9% mature safe resolutions | ≈10% | В | В | В: shadow+rollout |
| H3 | Intent/risk routing снизит transfers между очередями на 20% | 100% | С | С | Н: shadow |
| H4 | Incident dedup снизит пиковый backlog на 30% | <5% обычно | В в пик | С | С: incident replay |
| H5 | Hybrid retrieval повысит suggestion acceptance на 10 п.п. | ≈40% | С | С | С: offline+A/B |
| H6 | Summary длинных диалогов снизит AHT на 8% | ≈20% | Н/С | Н | Н: suggest pilot |

H1 первая: дёшево проверяет полезность ответа под контролем человека и собирает labels `accept/edit/reject` для H2. H2 вторая: проверяет основной экономический результат, но только после evidence H1. Routing нужен всему контуру, однако сам по себе не доказывает resolution; incident-функция ценна эпизодически.

### H1 — подсказка оператору

Для безопасных intent оператор получает approved KB fragment, версию источника и draft; отправка остаётся у него. PoC реализует это отдельной capability `operator_suggest`, не выдавая её за user-visible auto. Ожидание: AHT с 8 до ≤7,2 минуты. Проверка: 7 дней shadow на ≥50 тыс. тикетов, затем 14-дневный cluster A/B на 40 операторах, стратифицированных по каналу/опыту, ≥5 тыс. подходящих тикетов на группу. Успех: AHT лучше control ≥10% с 95% CI без нуля, acceptance ≥50%, guardrails соблюдены. Гипотеза отвергнута, если upper 95% CI выигрыша <5% либо acceptance <35%; UI выключается, reject/edit причины идут в retrieval/content backlog.

### H2 — узкое авторазрешение

PoC даёт static approved template только одному ultra-narrow intent — смене языка — при low risk, full-request grammar, score+margin, classifier↔retrieval consensus и current allowlisted KB. Verification-code/password остаются suggest-only из-за account-security ambiguity. Pilot может добавить второй FAQ лишь после отдельного evidence. Payments, security, complaints, mixed intent и uncertainty всегда human; generator в auto-path не вызывается. Проверка: 7 дней shadow на ≥20 тыс. кандидатов и double review 2 тыс.; затем 14 дней A/B с ramp `5%→25%` eligible traffic, ≥10 тыс. auto и control плюс 7 дней на reopen. Успех: lower 95% CI auto precision ≥99,5%, ≥90% без reopen, прогноз North Star ≥9%. Один critical unsafe немедленно выключает auto; reopen >10% или CSAT non-inferiority fail откатывает категорию в suggest.

## Метрики

**North Star — Safe Automated Resolution Rate:** доля всех созревших тикетов, закрытых без оператора, без reopen за 7 дней и без policy/safety violation; цель MVP **≥9%**.

Guardrails:

- CSAT point estimate ≥`4,2/5`, lower 95% CI delta к control `>−0,10`;
- 7-day reopen `≤10%` при baseline `9%`;
- first-response SLA: breach `≤5%`, то есть ≥95% ответов до 15 минут.

Safety не усредняется: допустимо `0` critical unsafe auto-replies; один случай активирует kill switch.

## Годовой эффект MVP

Assumptions: автоматизируем 25% типовых, то есть 10% всего потока; 70% высвобождённой capacity превращается в денежный эффект, остальное — SLA/peak buffer; reopen требует полной ручной обработки; fixed Ops 40 млн ₽/год. External-LLM cost выбранного auto-path равен `0 ₽`: он exact-template. Но в business case оставлен консервативный serving/inference reserve `1,5 ₽` на auto (compute, observability и возможные будущие suggest-вызовы); optional LLM-suggest оценивается отдельно после H1.

| Показатель | Расчёт | В год |
|---|---|---:|
| Весь / типовой поток | `200k×365`; `×40%` | 73,0 / 29,2 млн |
| Автозакрытия / зрелые решения без reopen | `73,0 млн×10%`; `×(1−9%)` | 7,30 / 6,64 млн |
| Gross / realized capacity | `7,30 млн×150 ₽`; `×70%` | 1 095,0 / 766,5 млн ₽ |
| Serving/inference reserve upper bound | `7,30 млн×1,5 ₽` | −10,95 млн ₽ |
| Reopen work при 9% | `7,30 млн×9%×150 ₽` | −98,55 млн ₽ |
| **Net capacity effect** | `766,5−10,95−98,55−40` | **≈617,0 млн ₽** |

Каждый `+1 п.п.` reopen уменьшает эффект ещё на `10,95 млн ₽/год`: при 10% остаётся ≈606,1 млн, при 12% — ≈584,2 млн. Это capacity-equivalent, не обещание cash saving; коэффициент реализации, inference и Ops заменяются фактами пилота.

## Раскатка и команда

| Майлстоун | Срок / масштаб | Gate |
|---|---|---|
| Offline replay → shadow | 1 неделя, 100% decisions только в log | 2 тыс. labels; latency, risk, PII и correctness gates |
| Suggest A/B | 2 недели, 40 операторов | Решение H1; acceptance/edit/reject |
| Narrow auto-response | 2 недели + 7 дней maturity, 5%→25% eligible | Решение H2; feature flag, on-call, kill switch |
| Category expansion | по 2 недели/category, 25%→100% внутри allowlist | Отдельное evidence и weekly safety review |

Минимальная команда: PM/rollout owner, ML engineer, backend/platform engineer, analyst, QA и два support SME/labeler; Security/Privacy утверждает allowlist, SRE владеет alerts/kill switch. Общая automation rate не цель сама по себе: category расширяется только после собственного safety и value evidence.
