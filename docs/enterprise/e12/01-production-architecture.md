# E12.1 — Production Architecture

This document describes the production multi-container network topology.

```
Internet -> Reverse Proxy (Nginx)
                |
        +-------+-------+
        |               |
   Frontend          Backend API
                        |
            +-----------+-----------+
            |                       |
          Redis                  MongoDB
            |
      Celery Workers
```

## Security Controls
* **Network Isolation**: Only Nginx is exposed to the public internet. MongoDB and Redis are bound exclusively to the private network.
* **SSL/TLS**: Terminated at the Nginx reverse proxy.\n