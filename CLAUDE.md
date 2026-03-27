# ovpn-admin project rules

## Docker builds

**ВСЕГДА собирать без кэша.** Никогда не использовать `docker compose up` без предварительного `build --no-cache`.

Правильная последовательность:
```bash
docker compose -f docker-compose.test.yml down -v
docker compose -f docker-compose.test.yml build --no-cache
docker compose -f docker-compose.test.yml up -d
```

Причина: docker-compose.test.yml сам собирает образ. Кэш Docker молча игнорирует изменения во фронтенде (packr2 встраивает статику в бинарник).
