# Channel Binding API Comparison Across SCRAM Libraries

This document compares how different SCRAM implementations handle channel binding in their APIs to inform the design of RFC 9266 support for xdg-go/scram.

## Summary Table

| Library | Language | API Pattern | Channel Binding Data Format | Configuration Method |
|---------|----------|-------------|----------------------------|---------------------|
| scramp | Python | Tuple parameter | `('tls-unique', data)` | Parameter to client constructor |
| ongres/scram | Java | Builder pattern | `.channelBinding("tls-server-end-point", byte[])` | Method on builder |
| node-postgres | JavaScript | Boolean flag | Automatic (extracted internally) | `enableChannelBinding: true` |
| libpq (PostgreSQL) | C | Connection parameter | Automatic (extracted internally) | `channel_binding=require` |

## Detailed Analysis

### 1. Python: scramp Library

**GitHub**: https://github.com/tlocke/scramp

**API Design**:
```python
# Channel binding provided as tuple: (binding_type, binding_data)
channel_binding = ('tls-unique', ssl_socket.get_channel_binding())

# Alternative: use helper function
channel_binding = scramp.make_channel_binding('tls-unique', ssl_socket)

# Pass to client
client = scramp.ScramClient(['SCRAM-SHA-256', 'SCRAM-SHA-256-PLUS'],
                            username, password,
                            channel_binding=channel_binding)
```

**Key Features**:
- Tuple format: `(type_string, data_bytes)`
- Helper function `make_channel_binding()` to create tuple from SSL socket
- Supports mechanism negotiation (client lists acceptable mechanisms)
- "-PLUS" suffix indicates channel binding capability
- Python's `SSLSocket.get_channel_binding()` provides TLS data

**Pros**:
- Simple tuple format is Pythonic
- Helper function makes it easy to extract from SSL socket
- Clear separation: type + data

**Cons**:
- Tuple is less self-documenting than a struct/class
- Python-specific (relies on SSLSocket API)

---

### 2. Java: OnGres SCRAM Library

**GitHub**: https://github.com/ongres/scram

**API Design**:
```java
ScramClient scramClient = ScramClient.builder()
    .advertisedMechanisms(Arrays.asList("SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"))
    .username("user")
    .password("pencil".toCharArray())
    .channelBinding("tls-server-end-point", cbindData)
    .build();
```

**Key Features**:
- Builder pattern for client construction
- Method signature: `.channelBinding(String cbindType, byte[] cbindData)`
- External data provision (application provides byte array)
- Automatic mechanism negotiation based on advertised mechanisms
- Prefers PLUS variant when channel binding is configured

**Implementation Notes**:
- Version 3.0+ rewrote ScramClient to properly negotiate channel binding
- Implements tls-server-end-point extraction for convenience
- Multi-release modular JARs
- Integrated with PostgreSQL JDBC driver

**Pros**:
- Builder pattern is idiomatic Java
- Type-safe API
- Clear method chaining
- Automatic mechanism selection

**Cons**:
- More verbose (Java style)
- Builder pattern adds complexity

---

### 3. JavaScript/Node.js: node-postgres

**GitHub**: https://github.com/brianc/node-postgres/pull/3356

**API Design**:
```javascript
const client = new Client({
  host: 'localhost',
  database: 'mydb',
  user: 'myuser',
  password: 'mypassword',
  ssl: true,
  enableChannelBinding: true  // Simple boolean flag
});

// Or with Pool
const pool = new Pool({
  ...config,
  enableChannelBinding: true
});
```

**Key Features**:
- Boolean flag: `enableChannelBinding: true`
- **Automatic extraction** of channel binding data from TLS connection
- Only supports tls-server-end-point (via peer certificate hash)
- Opt-in to preserve backward compatibility
- Homegrown ASN.1 parsing to avoid dependencies

**Implementation Details**:
- Extracts certificate via `stream.getPeerCertificate().raw`
- Parses ASN.1 to identify signature algorithm
- Computes hash using identified algorithm (SHA-256, SHA-384, SHA-512, etc.)
- Automatically uses SCRAM-SHA-256-PLUS when enabled

**Pros**:
- Simplest API (just a boolean)
- No need for application to extract channel binding data
- Automatic mechanism selection

**Cons**:
- Less flexible (only tls-server-end-point)
- Tightly coupled to Node.js TLS implementation
- Can't support other binding types easily
- Higher library complexity (TLS integration)

---

### 4. C: PostgreSQL libpq

**API Design**:
```c
// Connection string parameter
connection = PQconnectdb("host=localhost dbname=mydb user=myuser "
                        "sslmode=require channel_binding=require");

// Or environment variable
setenv("PGCHANNELBINDING", "require");
```

**Key Features**:
- Connection parameter: `channel_binding=require` (or `prefer`, `disable`)
- **Automatic extraction** from OpenSSL connection
- Uses `X509_get_signature_nid()` to get certificate hash algorithm
- tls-server-end-point only (tls-unique was removed due to TLS 1.3)

**Implementation Details**:
- `be_tls_get_certificate_hash()` extracts certificate hash
- Requires OpenSSL 1.0.2+ (for `X509_get_signature_nid()`)
- Base64-encodes certificate hash
- Format: `"p=tls-server-end-point,," + base64(cert_hash)`

**Error Messages**:
- "channel binding not supported by this build" (if OpenSSL too old)
- "channel-binding-not-supported" SASL error if server doesn't support

**Pros**:
- Simple configuration (string parameter)
- Automatic extraction (user doesn't handle TLS details)
- Well-tested in production (PostgreSQL 11+)

**Cons**:
- Tightly coupled to OpenSSL
- Less flexible for other binding types
- C API constraints

---

## Common Patterns Across Implementations

### 1. Data Provision Approach

**Two main approaches:**

a) **Application-provided data** (scramp Python, ongres Java):
   - Library is TLS-implementation agnostic
   - Application extracts channel binding data from TLS connection
   - Library receives type + data
   - More flexible, supports different TLS libraries

b) **Library-extracted data** (node-postgres, libpq):
   - Library extracts channel binding data automatically
   - Simple API (boolean or string parameter)
   - Tightly coupled to specific TLS implementation
   - Less flexible but easier to use

### 2. Configuration Style

**By language/ecosystem:**
- **Python**: Tuple or helper function
- **Java**: Builder pattern
- **JavaScript**: Options object with boolean flag
- **C**: Connection string parameter
- **Go**: ??? (to be determined)

### 3. Mechanism Negotiation

**All implementations handle PLUS variant selection:**
- Client advertises both regular and PLUS variants
- When channel binding configured, prefer PLUS
- Automatic downgrade if server doesn't support PLUS
- Transparent to application layer

### 4. Supported Binding Types

**Most common:**
- **tls-server-end-point**: Universal support (works with TLS 1.3)
- **tls-unique**: Deprecated/removed (unsafe with TLS 1.3)
- **tls-exporter**: New for TLS 1.3 (RFC 9266) - limited support so far

---

## Recommendations for xdg-go/scram

Based on the analysis of other libraries, here are recommendations:

### 1. Data Provision: Application-Provided (Like Python/Java)

**Recommendation**: Follow scramp (Python) and ongres (Java) approach.

**Rationale**:
- Go ecosystem has multiple TLS implementations (crypto/tls, BoringSSL, etc.)
- Library should remain TLS-agnostic
- Keeps dependencies minimal
- More flexible for different use cases
- Aligns with Go philosophy: "mechanism, not policy"

**API Design**:
```go
type ChannelBinding struct {
    Type ChannelBindingType
    Data []byte
}

client.WithChannelBinding(ChannelBinding{
    Type: ChannelBindingTLSExporter,
    Data: cbData,
})
```

This matches our current plan ✓

### 2. Configuration: Method (Not Constructor Parameter)

**Recommendation**: Use `WithChannelBinding()` method (as planned).

**Rationale**:
- Consistent with existing Go patterns (functional options)
- Matches library's existing API (WithNonceGenerator, WithMinIterations)
- Channel binding is connection-specific
- Allows reconfiguration for different connections

**Go Idiomatic Example**:
```go
// Current plan (good):
client.WithChannelBinding(cb)

// Alternative (also idiomatic):
client, err := scram.SHA256.NewClient("user", "pass", "",
    scram.WithChannelBinding(cb))
```

Current plan is fine ✓

### 3. Support All Three Binding Types

**Recommendation**: Support tls-unique, tls-server-end-point, and tls-exporter.

**Rationale**:
- RFC 9266 is new (2022), implementations catching up
- Different users on different TLS versions
- Library shouldn't restrict what application can use
- Simple string constants (no implementation complexity)

Current plan supports all three ✓

### 4. No Automatic Extraction

**Recommendation**: Don't extract channel binding data from TLS connections.

**Rationale**:
- Go's crypto/tls doesn't have ExportKeyingMaterial in all versions
- ExportKeyingMaterial only added in Go 1.14
- BoringSSL bindings different from crypto/tls
- Keep library focused on SCRAM protocol

**User Responsibility**:
```go
// Application code (not library):
tlsConn := conn.(*tls.Conn)
cbData, err := tlsConn.ExportKeyingMaterial(
    "EXPORTER-Channel-Binding", nil, 32)

// Then pass to library:
client.WithChannelBinding(ChannelBinding{
    Type: ChannelBindingTLSExporter,
    Data: cbData,
})
```

Current plan follows this ✓

### 5. Consider Helper Example (Documentation Only)

**Recommendation**: Provide example helper functions in documentation/examples.

**Example** (in doc_test.go or examples/):
```go
// Example helper for tls-exporter (TLS 1.3)
func getTLSExporterBinding(conn *tls.Conn) ([]byte, error) {
    return conn.ExportKeyingMaterial(
        "EXPORTER-Channel-Binding",
        nil,
        32,
    )
}

// Example helper for tls-server-end-point
func getTLSServerEndpointBinding(conn *tls.Conn) ([]byte, error) {
    state := conn.ConnectionState()
    if len(state.PeerCertificates) == 0 {
        return nil, errors.New("no peer certificate")
    }

    cert := state.PeerCertificates[0]
    hashAlg := getHashAlgorithm(cert.SignatureAlgorithm)
    h := hashAlg.New()
    h.Write(cert.Raw)
    return h.Sum(nil), nil
}
```

**Rationale**:
- Helps users get started
- Shows best practices
- Keeps library code simple
- Not part of public API (can evolve)

---

## API Comparison: Our Plan vs Others

| Aspect | Our Plan | scramp (Python) | ongres (Java) | node-postgres (JS) |
|--------|----------|-----------------|---------------|-------------------|
| Data source | Application | Application | Application | Automatic |
| Config method | `.WithChannelBinding()` | Constructor param | Builder method | Boolean flag |
| Data format | `ChannelBinding{Type, Data}` | `(type, data)` tuple | Two params `(String, byte[])` | N/A |
| TLS coupling | None | Low (helper) | None | High |
| Flexibility | High | High | High | Low |
| Simplicity | Medium | High | Medium | Very High |
| Go idiomatic | Yes | N/A | N/A | N/A |

**Conclusion**: Our plan balances flexibility with usability and is idiomatic for Go.

---

## Potential API Enhancements (Future Consideration)

### 1. Functional Options Pattern

Alternative to current `WithChannelBinding()` method:

```go
// Instead of:
client, _ := scram.SHA256.NewClient("user", "pass", "")
client.WithChannelBinding(cb)

// Could support:
client, _ := scram.SHA256.NewClient("user", "pass", "",
    scram.WithChannelBinding(cb),
    scram.WithMinIterations(8192))
```

**Pros**: Single-line construction, immutable
**Cons**: Breaking change, different from current pattern

**Decision**: Keep current approach for consistency with existing API.

### 2. Channel Binding Builder

```go
cb := scram.NewChannelBinding().
    WithType(scram.ChannelBindingTLSExporter).
    WithData(cbData).
    Build()
```

**Pros**: More discoverable, validates at build time
**Cons**: Over-engineered for a simple struct

**Decision**: Struct literal is sufficient.

### 3. Type Safety for Binding Data

```go
type TLSExporterData []byte
type TLSServerEndpointData []byte

type ChannelBinding interface {
    channelBindingType() ChannelBindingType
    channelBindingData() []byte
}
```

**Pros**: Type-safe, prevents mixing binding types with wrong data
**Cons**: Complex, unnecessary indirection

**Decision**: Simple struct is better.

---

## Conclusion

Our current implementation plan aligns well with industry best practices:

✓ Application-provided data (like Python/Java)
✓ TLS-agnostic library (unlike JavaScript/C implementations)
✓ Method-based configuration (Go idiomatic)
✓ Simple struct for channel binding (clear, self-documenting)
✓ Support for all binding types (future-proof)

**No changes needed to the current plan based on this analysis.**

The main difference from node-postgres/libpq (automatic extraction) is intentional:
- Keeps library TLS-agnostic
- Supports diverse Go TLS implementations
- Follows Go's philosophy of explicit over implicit

**Recommended additions**:
- Example helpers in documentation (getTLSExporterBinding, etc.)
- Migration guide showing how to extract channel binding data
- Links to Go crypto/tls documentation
