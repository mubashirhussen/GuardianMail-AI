# E12.8 — Redis & Celery SRE Operations

* **Redis Persistence**: Configured with AOF (Append Only File) to prevent task tracking state loss.
* **Celery Workers**:
  * Concurrency: `worker_concurrency=4`
  * Prefetch: `worker_prefetch_multiplier=1`
  * Task recycling: `worker_max_tasks_per_child=100`
  * Dead-Letter routing maps failed tasks to `dlq_queue`.\n