# Running BWC Tests Locally

## Prerequisites

- Docker and Docker Compose installed

## Run tests

From the repository root:

```bash
docker-compose up --build --abort-on-container-exit --exit-code-from newman
```

This will:

1. Build and start the backup daemon container
2. Start a Newman container that waits for the daemon, then runs the Postman BWC test collection
3. Exit with Newman's exit code (0 = all tests passed)

## View results

- Console output shows test results in real time
- JUnit XML report is written to `postman/results.xml`

## Run only the daemon (without tests)

```bash
docker-compose up --build backup-daemon
```

## Clean up

```bash
docker-compose down
```
