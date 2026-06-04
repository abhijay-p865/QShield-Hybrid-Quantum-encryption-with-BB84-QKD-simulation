# QShield

A hybrid quantum-safe encryption system that combines classical RSA-4096 + AES-256-GCM encryption with a simulated BB84 Quantum Key Distribution protocol. Built as a TKS (The Knowledge Society) REP II project.

QShield is a **protocol testbed and architecture demonstrator** — it models the encryption pipeline a business would need when quantum computers become powerful enough to break RSA. The BB84 simulation runs classically on a CPU but models the physics correctly (photon loss, dark counts, basis reconciliation, privacy amplification), and the architecture defines a clear hardware slot for when real QKD hardware becomes accessible.

---

## Why This Matters

RSA encryption, which secures most of the internet today, will be breakable by sufficiently powerful quantum computers. Businesses will need to transition to quantum-safe architectures, but the key management infrastructure for that transition doesn't exist yet in most organizations. QShield demonstrates what that architecture looks like: a hybrid system where classical encryption is reinforced by quantum key distribution, with real-time eavesdropping detection based on the laws of quantum mechanics.

---

## How It Works

Alice wants to send a secret message to Bob. The system:

1. **Runs BB84 QKD** — Alice and Bob exchange 5000 simulated photons, each encoded in a random basis. They publicly compare bases, discard mismatches (sifting), sample a subset to estimate the error rate (QBER), reconcile remaining errors, and privacy-amplify the result into a shared secret key.

2. **Detects eavesdropping** — If an eavesdropper (Eve) intercepts photons, she disturbs the quantum states, which raises the QBER above 11%. The system detects this and aborts the session. On the channel page, every transmission has a 20% random chance of Eve being present — you don't know until the QBER is checked, just like real QKD.

3. **Encrypts with a hybrid key** — A random AES-256 session key is XORed with the QKD key material, then RSA-4096 wraps the hybrid result. The plaintext is encrypted with AES-256-GCM. This means an attacker would need to break both RSA and the QKD layer.

4. **Stores and decrypts** — The encrypted message is stored in PostgreSQL. Bob retrieves it by UUID, the system unwraps the RSA layer, XORs with the QKD key to recover the AES session key, and decrypts.

---

## BB84 Simulation Details

The QKD simulation in `qkd_sim.py` implements the full BB84 protocol with a realistic noise model based on ID Quantique Clavis3 parameters:

- **Channel noise**: photon loss (η = 0.85), dark counts (p = 0.001), basis misalignment (p = 0.01)
- **Sifting**: Alice and Bob discard bits where they chose different bases
- **QBER estimation**: 20% of sifted bits are sampled to compute the quantum bit error rate
- **Error reconciliation**: parity-based binary search correction on 16-bit blocks
- **Privacy amplification**: SHA-256 hash compressed by binary entropy factor `H₂(QBER)`
- **Eavesdropping threshold**: QBER > 0.11 (11%) flags the channel as compromised

When Eve is present, she intercepts each photon, measures it in a random basis, and resends her result. When her basis doesn't match Alice's, she introduces errors — this is what makes QKD fundamentally secure.

---

## Project Structure

```
app.py                Flask application — all API routes (port 5000)
orchestrator.py       Hybrid encrypt/decrypt pipeline (BB84 + RSA + AES-GCM)
qkd_sim.py            Full BB84 simulation with noise model
crypto_functions.py   AES-256-GCM and RSA-OAEP primitives
utils.py              Bit/byte conversion and XOR utilities
db.py                 PostgreSQL interface (encryption_db)
key_generation.py     One-time RSA-4096 key pair generator
templates/
  channel.html        Alice/Bob communication interface
  dashboard.html      Security monitoring dashboard
```

**Shelved (three-service architecture, correct but not used in MVP):**
```
alice_service.py      Alice's standalone Flask service (port 5001)
bob_service.py        Bob's standalone Flask service (port 5002)
alice_db.py           Alice's database interface
bob_db.py             Bob's database interface
setup_databases.sql   Database creation script for alice_db and bob_db
```

---

## Setup

**Requirements:** Python 3.12+, PostgreSQL

1. Install dependencies:
   ```
   pip install flask flask-cors psycopg2-binary pycryptodome
   ```

2. Create the database and tables in PostgreSQL:
   ```sql
   CREATE DATABASE encryption_db;
   \connect encryption_db

   CREATE TABLE messages (
       id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       encrypted_key TEXT NOT NULL,
       ciphertext    TEXT NOT NULL,
       nonce         TEXT NOT NULL,
       tag           TEXT NOT NULL,
       key_id        TEXT NOT NULL,
       qkd_key       TEXT NOT NULL,
       qber          FLOAT,
       sifted_bits   INTEGER,
       created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
   );

   CREATE TABLE eve_attempts (
       id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       qber       FLOAT NOT NULL,
       created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
   );
   ```

3. Generate RSA-4096 keys (run once):
   ```
   python key_generation.py
   ```

4. Set your PostgreSQL password and start the server:
   ```powershell
   $env:PGPASSWORD = "your_password"
   python app.py
   ```

5. Open in your browser:
   - **Channel:** http://127.0.0.1:5000/channel
   - **Dashboard:** http://127.0.0.1:5000/dashboard

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/encrypt` | POST | Encrypts a message. 20% random Eve chance. Accepts optional `eve_present: true` to force eavesdropping. Returns UUID on success, 422 if Eve detected. |
| `/decrypt` | POST | Decrypts a message by UUID. |
| `/metrics` | GET | Returns total messages, average QBER, threats detected, KGR, recent session data. |
| `/channel` | GET | Serves the Alice/Bob channel interface. |
| `/dashboard` | GET | Serves the security monitoring dashboard. |
| `/simulate-eve` | POST | Runs a standalone Eve simulation (used by dashboard). |

---

## Key Technical Parameters

- **RSA key size:** 4096 bits
- **AES mode:** AES-256-GCM (authenticated encryption)
- **Photons per session:** 5000
- **QBER threshold:** 0.11 (11%)
- **Noise model:** η=0.85, dark count p=0.001, misalignment p=0.01
- **KGR formula:** sifted_bits × (1 − H₂(QBER))
- **QKD key storage:** base64-encoded in PostgreSQL
