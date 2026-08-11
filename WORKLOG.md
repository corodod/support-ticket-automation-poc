# WORKLOG

Работу строил от продуктовых решений к реализации. Сначала определил три режима обработки: точный автоматический шаблон для узкого безопасного FAQ, подсказка оператору и обязательная ручная обработка. Для рискованных, неоднозначных и неизвестных обращений выбрал fail-closed поведение.

Четырёхчасовую рамку распределил следующим образом:

- 30 минут — гипотезы, сценарии и границы MVP;
- 80 минут — pipeline и persistence;
- 55 минут — тесты и evaluation;
- 45 минут — target architecture и operations;
- 30 минут — product plan и финальная проверка.

Основные решения:

1. Внешний LLM не используется. Автоматический ответ формируется только из утверждённого статического шаблона.
2. PII и hard-risk обрабатываются до classifier, retrieval и composer.
3. Classifier только предлагает intent; право на автоматизацию выдаёт deterministic policy.
4. Auto разрешается лишь при согласии classifier и retrieval, достаточных score/margin, полном безопасном scope и актуальной allowlisted KB article.
5. Candidate action, effective action, delivery state и resolution outcome хранятся раздельно.
6. Decision, audit и outbox записываются одной SQLite-транзакцией до внешнего действия.
7. Ошибка, timeout, конфликт сигналов или неизвестный текст не расширяют capability.
8. Production design отделён от компактного PoC и включает durable broker, priority queues, operator inbox, dispatcher, immutable audit и kill switches.

Негативное тестирование выявило дополнительные варианты mixed intent, обфускации риска и нестандартных форматов PII. Эти случаи были добавлены в policy и regression suite.

Финальное состояние:

- 53 теста проходят;
- 34 generated mutations не получают auto capability;
- unsafe auto и OOS auto равны нулю на зафиксированных наборах;
- safe-auto precision — `1,0`, eligible-safe coverage — `0,60`;
- локальный p99 — `5,404 ms`;
- submission verifier проходит полностью.

Результаты получены на малых синтетических данных и рассматриваются как проверка механики PoC, а не как подтверждение production-качества.
