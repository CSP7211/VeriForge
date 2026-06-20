# VeriForge Deployment Guide

## Table of Contents

- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Environment Variable Reference](#environment-variable-reference)
- [Health Check Endpoints](#health-check-endpoints)

---

## Docker Deployment

### Dockerfile

```dockerfile
FROM python:3.12-slim

# Security hardening
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r veriforge && useradd -r -g veriforge veriforge

WORKDIR /app

# Install dependencies
COPY setup.py pyproject.toml ./
COPY veriforge/ ./veriforge/
RUN pip install --no-cache-dir -e ".[dev]"

# Switch to non-root user
USER veriforge

# Environment variables (override at runtime)
ENV VERIFORGE_SECRET=""
ENV VERIFORGE_JWT_SECRET=""
ENV VERIFORGE_AUDIT_SECRET=""
ENV VERIFORGE_LOG_LEVEL="INFO"

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "from veriforge.engine import VeriForgeEngine; VeriForgeEngine().verify_code('x=1')" || exit 1

ENTRYPOINT ["python", "-m", "veriforge"]
CMD ["--help"]
```

### Build and Run

```bash
# Build image
docker build -t veriforge:0.4.0-hardened .

# Run with environment variables
docker run -it --rm \
    -e VERIFORGE_SECRET="$(openssl rand -hex 32)" \
    -e VERIFORGE_JWT_SECRET="$(openssl rand -hex 32)" \
    -e VERIFORGE_AUDIT_SECRET="$(openssl rand -hex 32)" \
    veriforge:0.4.0-hardened scan /path/to/code
```

### Docker Compose

```yaml
version: "3.8"
services:
  veriforge:
    build: .
    image: veriforge:0.4.0-hardened
    environment:
      VERIFORGE_SECRET: ${VERIFORGE_SECRET}
      VERIFORGE_JWT_SECRET: ${VERIFORGE_JWT_SECRET}
      VERIFORGE_AUDIT_SECRET: ${VERIFORGE_AUDIT_SECRET}
      VERIFORGE_LOG_LEVEL: INFO
      VERIFORGE_RATE_LIMIT: "100"
    volumes:
      - ./code:/code:ro
    command: ["scan", "/code"]
    restart: unless-stopped
```

---

## Kubernetes Deployment

### Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: veriforge
```

### ConfigMap (non-sensitive configuration)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: veriforge-config
  namespace: veriforge
data:
  VERIFORGE_LOG_LEVEL: "INFO"
  VERIFORGE_RATE_LIMIT: "100"
  VERIFORGE_RATE_WINDOW: "60"
  VERIFORGE_COMPLIANCE: "all"
```

### Secret (sensitive data — base64 encoded)

**Generate secrets:**
```bash
kubectl create secret generic veriforge-secrets \
  --namespace=veriforge \
  --from-literal=VERIFORGE_SECRET="$(openssl rand -hex 32)" \
  --from-literal=VERIFORGE_JWT_SECRET="$(openssl rand -hex 32)" \
  --from-literal=VERIFORGE_AUDIT_SECRET="$(openssl rand -hex 32)"
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: veriforge
  namespace: veriforge
  labels:
    app: veriforge
    version: 0.4.0-hardened
spec:
  replicas: 3
  selector:
    matchLabels:
      app: veriforge
  template:
    metadata:
      labels:
        app: veriforge
        version: 0.4.0-hardened
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 999
        runAsGroup: 999
        fsGroup: 999
      containers:
        - name: veriforge
          image: veriforge:0.4.0-hardened
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8080
              name: http
          envFrom:
            - configMapRef:
                name: veriforge-config
          envFrom:
            - secretRef:
                name: veriforge-secrets
          resources:
            requests:
              memory: "128Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          livenessProbe:
            exec:
              command:
                - python
                - -c
                - "from veriforge.engine import VeriForgeEngine; VeriForgeEngine().verify_code('x=1')"
            initialDelaySeconds: 10
            periodSeconds: 30
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            exec:
              command:
                - python
                - -c
                - "import veriforge; print(veriforge.__version__)"
            initialDelaySeconds: 5
            periodSeconds: 10
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
```

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: veriforge
  namespace: veriforge
spec:
  selector:
    app: veriforge
  ports:
    - port: 8080
      targetPort: 8080
      name: http
  type: ClusterIP
```

### HorizontalPodAutoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: veriforge-hpa
  namespace: veriforge
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: veriforge
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

### NetworkPolicy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: veriforge-netpol
  namespace: veriforge
spec:
  podSelector:
    matchLabels:
      app: veriforge
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - {}  # Allow all egress (restrict as needed)
```

### PodDisruptionBudget

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: veriforge-pdb
  namespace: veriforge
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: veriforge
```

### Deploy All

```bash
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f hpa.yaml
kubectl apply -f networkpolicy.yaml
kubectl apply -f pdb.yaml
```

---

## Environment Variable Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VERIFORGE_SECRET` | Yes | — | Primary HMAC signing secret (min 32 bytes) |
| `VERIFORGE_JWT_SECRET` | Yes | — | JWT token signing secret (min 32 bytes) |
| `VERIFORGE_AUDIT_SECRET` | Yes | — | Audit log HMAC chain secret (min 32 bytes) |
| `VERIFORGE_DB_URL` | No | `sqlite:///veriforge.db` | Database connection URL |
| `VERIFORGE_RATE_LIMIT` | No | `100` | Max requests per rate window |
| `VERIFORGE_RATE_WINDOW` | No | `60` | Rate limit window in seconds |
| `VERIFORGE_LOG_LEVEL` | No | `INFO` | Python logging level |
| `VERIFORGE_COMPLIANCE` | No | `all` | Active compliance mode |
| `VERIFORGE_MAX_FILE_SIZE` | No | `10485760` | Max file size in bytes (10 MB) |
| `VERIFORGE_EXTENSIONS` | No | `.py,.js,.go,.rs,.c,.cpp,.java` | Allowed file extensions |

### Secret Generation

```bash
# Generate secure secrets
export VERIFORGE_SECRET=$(openssl rand -hex 32)
export VERIFORGE_JWT_SECRET=$(openssl rand -hex 32)
export VERIFORGE_AUDIT_SECRET=$(openssl rand -hex 32)

# Verify length
echo "VERIFORGE_SECRET length: ${#VERIFORGE_SECRET}"
```

---

## Health Check Endpoints

### Liveness Probe

```python
# Kubernetes liveness check
from veriforge.engine import VeriForgeEngine
try:
    VeriForgeEngine().verify_code("x = 1")
    # Return HTTP 200
except Exception:
    # Return HTTP 503
```

### Readiness Probe

```python
# Kubernetes readiness check
import veriforge
# Return HTTP 200 with version
# {"status": "ready", "version": "0.4.0-hardened"}
```

### Startup Probe

```python
# Verify all imports and config are available
from veriforge.engine import VeriForgeEngine
from veriforge.auth import AuthManager
from veriforge.audit import ImmutableAuditLog
from veriforge.config import SecureConfig

config = SecureConfig()
config.validate()
# Return HTTP 200
```

### Health Check Script

```python
#!/usr/bin/env python3
"""veriforge_health.py — Health check for load balancers."""
import sys
from veriforge.engine import VeriForgeEngine
from veriforge.config import SecureConfig

def check():
    try:
        config = SecureConfig()
        errors = config.validate()
        if errors:
            return False, f"Config errors: {errors}"
        engine = VeriForgeEngine(config=config)
        result = engine.verify_code("x = 1")
        return result.verified, "OK"
    except Exception as exc:
        return False, str(exc)

if __name__ == "__main__":
    healthy, msg = check()
    if healthy:
        print(f"HEALTHY: {msg}")
        sys.exit(0)
    else:
        print(f"UNHEALTHY: {msg}", file=sys.stderr)
        sys.exit(1)
```
