# server-skeleton

This is a generic server node skeleton project designed to help you quickly build custom protocol nodes based on `xray-core` and `uniproxy` (e.g., `server-vless`, `server-vmess`, etc.).

This project comes pre-configured with logic for backend communication, configuration management, logging, and basic CLI operations. All you need to do is **replace the protocol-specific implementation logic**.

## 🚀 Getting Started

### 1. Clone & Rename
```bash
# 1. Clone this project
git clone https://github.com/GoAsyncFunc/server-skeleton.git server-your-protocol
cd server-your-protocol

# 2. Update the module name in go.mod
go mod edit -module github.com/GoAsyncFunc/server-your-protocol

# 3. Global Find & Replace (Optional)
# Update the 'Name' constant in cmd/server/main.go for logs and version info.
```

### 2. Implement Protocol Logic
The core logic is located in the `internal/pkg/service/` directory:

*   **`internal/pkg/service/inboundbuilder.go`**:
    *   **MUST MODIFY**.
    *   This file defines how to build the Xray Inbound based on the configuration (port, certs, transport, etc.) received from the API.
    *   The current implementation is an **EXAMPLE using Trojan**. You must replace it with the logic for your specific protocol (e.g., VLESS, VMess, Hysteria).

*   **`internal/pkg/service/userbuilder.go`**:
    *   **MUST MODIFY**.
    *   This file defines how to convert the UserInfo (`api.UserInfo`) returned by the API into user configurations (`protocol.User`) that Xray core can understand.
    *   You need to adapt this based on your protocol's requirements (e.g., UUID vs Password).

*   **`cmd/server/main.go`**:
    *   **Modify as Needed**.
    *   Update the `Name` field to match your project.
    *   Adjust the default `node_type` or other CLI flag defaults.

### 3. Build & Run
```bash
# Build
go build -o node cmd/server/main.go

# Run (Example)
./node --api https://your-api.com --token your-token --node 1
```

## 📂 Project Structure
```text
.
├── cmd/server/          # Application Entrypoint (main.go)
├── internal/
│   ├── app/server/      # Core Service Lifecycle Management (Usually no changes needed)
│   ├── pkg/
│       ├── service/     # [Focus Here] Business Logic (Builder, UserBuilder, InboundBuilder)
│       ├── dispatcher/  # Traffic Dispatch & Rules (Usually no changes needed)
├── go.mod               # Dependency Management
└── Makefile             # Build Scripts
```
