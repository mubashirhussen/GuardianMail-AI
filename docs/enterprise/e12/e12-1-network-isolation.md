# E12.1 — Network Isolation Report

## 1. Exposed vs. Internal Container Ports

To adhere to the principle of least privilege, only the Nginx reverse proxy service exposes host ports to the public internet interface. All internal database, cache, and processing containers communicate strictly over the internal isolated bridge network (`guardianmail_net`).

| Service Name | Docker DNS Alias | Internal Port | Host Port Binding | Accessibility |
| :--- | :--- | :--- | :--- | :--- |
| `nginx` | `nginx` | `80` / `443` | `80:80` | **Public** |
| `frontend` | `frontend` | `80` | None | Internal to Nginx proxy only |
| `api` | `api` | `8000` | None | Internal to Nginx proxy only |
| `mongo` | `mongo` | `27017` | None | Internal to API and Celery workers only |
| `redis` | `redis` | `6379` | None | Internal to API and Celery workers only |
| `celery_worker` | `celery_worker` | None | None | Internal |
| `celery_beat` | `celery_beat` | None | None | Internal |

---

## 2. Verification Outcomes
* **Host Boundary Test**: Attempting to connect to `localhost:27017` or `localhost:6379` from the host system returns a Connection Refused error, validating that no public port leakage exists.
* **DNS Resolution**: Containers resolve adjacent services via internal Docker DNS names (`mongodb://mongo:27017` and `redis://redis:6379`).
