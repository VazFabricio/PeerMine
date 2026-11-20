# PeerMine

Túnel P2P nativo em **Rust + QUIC (`iroh`)** para jogar **Minecraft (LAN ou servidor local)** com amigos pela internet, **sem Hamachi, sem VPN e sem abrir portas no roteador**.

---

## Como funciona (100% P2P nativo)

```mermaid
sequenceDiagram
    autonumber
    participant MC_H as "Minecraft (Host 127.0.0.1:25565)"
    participant PM_H as "PeerMine Host (Rust)"
    participant PM_C as "PeerMine Amigo (Rust)"
    participant MC_C as "Minecraft Amigo (localhost:25565)"

    PM_H->>PM_H: "Gera 1 código único PM1:... (vale para todos os amigos)"
    PM_H-->>PM_C: "Você envia o código PM1:... no chat"
    PM_C<<->>PM_H: "Túnel QUIC P2P direto (TLS 1.3 + Hole Punching)"
    MC_C->>PM_C: "Conecta em localhost"
    PM_C<<->>PM_H: "Encaminha pacotes direto em Rust (TCP_NODELAY)"
    PM_H<<->>MC_H: "Entrega na porta LAN do Minecraft"
```

---

## Por que usar o PeerMine no lugar do Hamachi?
- **Sem driver de VPN no Windows:** não instala adaptador de rede virtual e não precisa de administrador.
- **Um único código para vários amigos:** o Host gera um código `PM1:...` e todos os amigos podem entrar usando esse mesmo código.
- **Menor latência:** o tráfego TCP do Minecraft é encaminhado diretamente em **Rust (`tokio` + `iroh`)** com `TCP_NODELAY` (sem passar pelo WebView2/JS), evitando o lag de servidores relay distantes.
- **Criptografia ponta a ponta:** QUIC com **TLS 1.3** obrigatório.
- **Isolamento:** CSP estrita (`script-src 'self'`), permissões Tauri mínimas (`core:default`), sem acesso a arquivos ou shell.

---

## Como usar
1. **Quem vai abrir o mundo (Host):**
   - Abra seu mundo no Minecraft → `ESC` → **Abrir para LAN** (anote a porta, ou use `25565` se for servidor).
   - No PeerMine, digite a porta e clique em **Hostear Mundo** → **Copiar Código** e mande para os amigos.
2. **Amigos:**
   - Cole o código `PM1:...` no PeerMine e clique em **Entrar no Mundo**.
   - No Minecraft, vá em **Multiplayer → Conexão Direta** e digite **`localhost`** (ou `127.0.0.1:<porta>`).
