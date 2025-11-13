# RFC 9266 Channel Binding Implementation Plan

## Overview

This document outlines the implementation plan for adding RFC 9266 (Channel Bindings for TLS 1.3) support to the xdg-go/scram library. This will also include RFC 5929 channel binding types and enable SCRAM-PLUS variants (SCRAM-SHA-1-PLUS, SCRAM-SHA-256-PLUS, SCRAM-SHA-512-PLUS).

## Background

### Current State

The codebase currently:
- **Explicitly rejects** channel binding requests (parse.go:52-54)
- Always uses gs2-cbind-flag of "n" (no channel binding support) (client_conv.go:144-149)
- Has parsing infrastructure that recognizes gs2-cbind-flag but doesn't use it
- Validates that channel binding data in client-final matches gs2-header (server_conv.go:120-126)

### Goal

Enable full channel binding support per RFC 5802, RFC 5929, and RFC 9266, allowing:
- Client and server to negotiate channel binding
- Support for tls-unique, tls-server-end-point, and tls-exporter binding types
- SCRAM-PLUS mechanism variants
- Backward compatibility with non-channel-binding clients/servers

## RFCs Summary

### RFC 5802: SCRAM Protocol

Defines three gs2-cbind-flag values:
- **"n"**: Client doesn't support channel binding
- **"y"**: Client supports channel binding but thinks server doesn't
- **"p=<cb-name>"**: Client requires channel binding with specified type

Channel binding data is included in the "c=" field of client-final-message.

### RFC 5929: Channel Bindings for TLS

Defines two primary channel binding types:
- **tls-unique**: Uses first TLS Finished message (not safe for TLS 1.3)
- **tls-server-end-point**: Uses hash of server certificate (works with TLS 1.3)

### RFC 9266: Channel Bindings for TLS 1.3

Defines:
- **tls-exporter**: Uses TLS Exported Keying Material (EKM)
  - Label: "EXPORTER-Channel-Binding" (no NUL terminator)
  - Empty but present context (use_context=1, contextlen=0)
  - Recommended for TLS 1.3
  - Can be used with TLS <1.3 if extended master secret (RFC 7627) enabled and renegotiation disabled

Updates RFCs 5801, 5802, 5929, and 7677 to prefer tls-exporter for TLS 1.3.

## Architecture Analysis

### Key Integration Points

1. **scram.go**: Hash generator factory pattern
   - Add PLUS variants: SHA1PLUS, SHA256PLUS, SHA512PLUS
   - OR: Keep existing and pass channel binding via Client/Server constructors

2. **common.go**: Shared types and utilities
   - Add ChannelBinding type/struct
   - Add ChannelBindingCallback function type

3. **client.go**: Client configuration
   - Add channel binding configuration (type + data callback)
   - Update NewClient/NewClientUnprepped to accept channel binding

4. **server.go**: Server configuration
   - Add channel binding configuration (expected type + data)
   - Update NewServer to accept channel binding

5. **client_conv.go**: Client conversation state machine
   - Update gs2Header() to include "p=<cb-type>" when configured
   - Include channel binding data in finalMsg "c=" field

6. **server_conv.go**: Server conversation state machine
   - Update firstMsg to extract and validate cb-type from gs2-header
   - Update finalMsg to validate channel binding data matches

7. **parse.go**: Message parsing
   - Update parseGS2Flag to accept and parse "p=<cb-type>"
   - Extract channel binding type into c1Msg struct

## Implementation Plan

### Phase 1: Core Types and Interfaces

**File: common.go**

1. Add channel binding type enumeration:
```go
type ChannelBindingType string

const (
    ChannelBindingNone            ChannelBindingType = ""
    ChannelBindingTLSUnique       ChannelBindingType = "tls-unique"
    ChannelBindingTLSServerEndpoint ChannelBindingType = "tls-server-end-point"
    ChannelBindingTLSExporter     ChannelBindingType = "tls-exporter"
)
```

2. Add channel binding configuration struct:
```go
type ChannelBinding struct {
    Type ChannelBindingType
    Data []byte
}
```

3. Add channel binding callback type:
```go
// ChannelBindingCallback returns channel binding data for a given type.
// Applications must implement this to provide TLS-layer channel binding data.
// Returns nil if the requested binding type is not available.
type ChannelBindingCallback func(ChannelBindingType) []byte
```

4. Add helper functions:
```go
func (cb ChannelBinding) IsSupported() bool
func (cb ChannelBinding) Matches(other ChannelBinding) bool
```

### Phase 2: Parser Updates

**File: parse.go**

1. Update c1Msg struct to include channel binding type:
```go
type c1Msg struct {
    gs2Header      string
    gs2BindFlag    string  // "n", "y", or "p"
    channelBinding string  // channel binding type name if gs2BindFlag is "p"
    authzID        string
    username       string
    nonce          string
    c1b            string
}
```

2. Update parseGS2Flag to handle "p=<cb-name>":
```go
func parseGS2Flag(s string) (flag string, cbType string, err error) {
    if strings.HasPrefix(s, "p=") {
        // Extract channel binding type
        cbType = strings.TrimPrefix(s, "p=")
        if len(cbType) == 0 {
            return "", "", errors.New("channel binding type missing after 'p='")
        }
        // Validate cb-name format: 1*(ALPHA / DIGIT / "." / "-")
        // TODO: Add validation
        return "p", cbType, nil
    }

    if s == "n" || s == "y" {
        return s, "", nil
    }

    return "", "", fmt.Errorf("invalid gs2-cbind-flag: %s", s)
}
```

3. Update parseClientFirst to use new parseGS2Flag:
```go
func parseClientFirst(c1 string) (msg c1Msg, err error) {
    // ... existing code ...

    msg.gs2BindFlag, msg.channelBinding, err = parseGS2Flag(fields[0])
    if err != nil {
        return
    }

    // ... rest of existing code ...
}
```

### Phase 3: Client-Side Implementation

**File: client.go**

1. Add channel binding fields to Client struct:
```go
type Client struct {
    sync.RWMutex
    username      string
    password      string
    authzID       string
    minIters      int
    nonceGen      NonceGeneratorFcn
    hashGen       HashGeneratorFcn
    cache         map[KeyFactors]derivedKeys
    channelBinding ChannelBinding  // NEW
}
```

2. Add WithChannelBinding configuration method:
```go
// WithChannelBinding configures channel binding for this client.
// The Data field should contain the channel binding data obtained from
// the TLS connection. For tls-exporter, this is the exported keying material
// using the label "EXPORTER-Channel-Binding".
func (c *Client) WithChannelBinding(cb ChannelBinding) *Client {
    c.Lock()
    defer c.Unlock()
    c.channelBinding = cb
    return c
}
```

**File: client_conv.go**

1. Add channel binding to ClientConversation:
```go
type ClientConversation struct {
    client         *Client
    nonceGen       NonceGeneratorFcn
    hashGen        HashGeneratorFcn
    minIters       int
    state          clientState
    valid          bool
    gs2            string
    nonce          string
    c1b            string
    serveSig       []byte
    channelBinding ChannelBinding  // NEW
}
```

2. Update NewConversation to copy channel binding:
```go
func (c *Client) NewConversation() *ClientConversation {
    c.RLock()
    defer c.RUnlock()
    return &ClientConversation{
        client:         c,
        nonceGen:       c.nonceGen,
        hashGen:        c.hashGen,
        minIters:       c.minIters,
        channelBinding: c.channelBinding,  // NEW
    }
}
```

3. Update gs2Header method:
```go
func (cc *ClientConversation) gs2Header() string {
    var cbFlag string

    if cc.channelBinding.Type != ChannelBindingNone && len(cc.channelBinding.Data) > 0 {
        cbFlag = fmt.Sprintf("p=%s", cc.channelBinding.Type)
    } else {
        cbFlag = "n"
        // TODO: Implement "y" flag logic for mechanism negotiation scenarios
    }

    if cc.client.authzID == "" {
        return cbFlag + ",,"
    }
    return fmt.Sprintf("%s,%s,", cbFlag, encodeName(cc.client.authzID))
}
```

4. Update finalMsg to include channel binding data:
```go
func (cc *ClientConversation) finalMsg(s1 string) (string, error) {
    // ... existing code up to c2wop creation ...

    // Include channel binding data in gs2 header sent in "c=" field
    var cbData []byte
    if cc.channelBinding.Type != ChannelBindingNone {
        cbData = cc.channelBinding.Data
    }

    // Create full channel binding data: gs2-header + channel-binding-data
    fullCBind := append([]byte(cc.gs2), cbData...)

    c2wop := fmt.Sprintf(
        "c=%s,r=%s",
        base64.StdEncoding.EncodeToString(fullCBind),
        cc.nonce,
    )

    // ... rest of existing code ...
}
```

### Phase 4: Server-Side Implementation

**File: server.go**

1. Add channel binding fields to Server struct:
```go
type Server struct {
    sync.RWMutex
    credentialCB   CredentialLookup
    nonceGen       NonceGeneratorFcn
    hashGen        HashGeneratorFcn
    channelBinding ChannelBinding  // NEW
    supportsPLUS   bool            // NEW: whether server offers PLUS variants
}
```

2. Add WithChannelBinding configuration method:
```go
// WithChannelBinding configures the expected channel binding for this server.
// When configured, the server will validate that clients using channel binding
// provide matching channel binding data.
func (s *Server) WithChannelBinding(cb ChannelBinding) *Server {
    s.Lock()
    defer s.Unlock()
    s.channelBinding = cb
    s.supportsPLUS = cb.Type != ChannelBindingNone
    return s
}
```

**File: server_conv.go**

1. Add fields to ServerConversation:
```go
type ServerConversation struct {
    nonceGen         NonceGeneratorFcn
    hashGen          HashGeneratorFcn
    credentialCB     CredentialLookup
    state            serverState
    credential       StoredCredentials
    valid            bool
    gs2Header        string
    username         string
    authzID          string
    nonce            string
    c1b              string
    s1               string
    channelBinding   ChannelBinding  // NEW: expected channel binding
    clientCBType     string          // NEW: what client requested
    clientCBFlag     string          // NEW: n, y, or p
}
```

2. Update NewConversation to copy channel binding:
```go
func (s *Server) NewConversation() *ServerConversation {
    s.RLock()
    defer s.RUnlock()
    return &ServerConversation{
        nonceGen:       s.nonceGen,
        hashGen:        s.hashGen,
        credentialCB:   s.credentialCB,
        channelBinding: s.channelBinding,  // NEW
    }
}
```

3. Update firstMsg to capture client's channel binding request:
```go
func (sc *ServerConversation) firstMsg(c1 string) (string, error) {
    msg, err := parseClientFirst(c1)
    if err != nil {
        sc.state = serverDone
        return "", err
    }

    sc.gs2Header = msg.gs2Header
    sc.clientCBFlag = msg.gs2BindFlag  // NEW
    sc.clientCBType = msg.channelBinding  // NEW
    sc.username = msg.username
    sc.authzID = msg.authzID

    // NEW: Validate channel binding negotiation
    if sc.clientCBFlag == "p" {
        // Client requires channel binding
        if sc.channelBinding.Type == ChannelBindingNone {
            sc.state = serverDone
            return "e=channel-binding-not-supported",
                   errors.New("client requires channel binding but server doesn't support it")
        }
        if ChannelBindingType(sc.clientCBType) != sc.channelBinding.Type {
            sc.state = serverDone
            return "e=unsupported-channel-binding-type",
                   fmt.Errorf("client requested %s but server only supports %s",
                              sc.clientCBType, sc.channelBinding.Type)
        }
    }

    // ... rest of existing code ...
}
```

4. Update finalMsg to validate channel binding data:
```go
func (sc *ServerConversation) finalMsg(c2 string) (string, error) {
    msg, err := parseClientFinal(c2)
    if err != nil {
        return "", err
    }

    // NEW: Validate channel binding data
    var expectedCBind []byte
    if sc.clientCBFlag == "p" {
        // Client used channel binding - validate it matches
        expectedCBind = append([]byte(sc.gs2Header), sc.channelBinding.Data...)
    } else {
        // Client didn't use channel binding - just expect gs2 header
        expectedCBind = []byte(sc.gs2Header)
    }

    if !hmac.Equal(msg.cbind, expectedCBind) {
        return "e=channel-bindings-dont-match",
               fmt.Errorf("channel binding mismatch: expected %x, got %x",
                         expectedCBind, msg.cbind)
    }

    // ... rest of existing code ...
}
```

### Phase 5: Testing

**New file: channel_binding_test.go**

1. Test client with channel binding:
   - Create client with tls-exporter binding
   - Verify gs2-header includes "p=tls-exporter"
   - Verify channel binding data included in client-final

2. Test server with channel binding:
   - Create server with expected binding
   - Verify accepts matching client binding
   - Verify rejects mismatched client binding

3. Test negotiation scenarios:
   - Client with binding + Server with binding = success
   - Client with binding + Server without binding = error
   - Client without binding + Server with binding = accepts (for backward compat)
   - Client with wrong binding type + Server = error

4. Test backward compatibility:
   - Existing tests should pass unchanged
   - Non-channel-binding clients work with new code

5. Test all three binding types:
   - tls-unique
   - tls-server-end-point
   - tls-exporter

6. Integration test:
   - Full client-server conversation with channel binding
   - Verify authentication succeeds
   - Verify channel binding data is properly validated

### Phase 6: Documentation

**Update files:**

1. **README.md**: Add section on channel binding support
   - Example of client with channel binding
   - Example of server with channel binding
   - How to obtain TLS channel binding data
   - Security considerations

2. **doc.go**: Update package documentation
   - Describe channel binding support
   - Link to relevant RFCs

3. **doc_test.go**: Add examples
   - Example_clientWithChannelBinding
   - Example_serverWithChannelBinding

4. **CHANGELOG.md**: Add entry for new version
   - Channel binding support (RFC 5929, RFC 9266)
   - SCRAM-PLUS variant support
   - Backward compatible

## Implementation Order

1. **Phase 1**: Core types (common.go)
2. **Phase 2**: Parser updates (parse.go)
3. **Phase 3**: Client implementation (client.go, client_conv.go)
4. **Phase 4**: Server implementation (server.go, server_conv.go)
5. **Phase 5**: Testing (channel_binding_test.go + update existing tests)
6. **Phase 6**: Documentation (README.md, doc.go, doc_test.go, CHANGELOG.md)

## Design Decisions

### 1. Configuration Approach

**Decision**: Use `WithChannelBinding()` method to configure channel binding on existing Client/Server instances, rather than creating separate PLUS variants.

**Rationale**:
- More flexible - same client can be reconfigured for different connections
- Follows existing pattern (`WithNonceGenerator()`, `WithMinIterations()`)
- Channel binding data is connection-specific, not mechanism-specific
- Avoids proliferation of factory methods

### 2. Channel Binding Data Source

**Decision**: Require application to provide channel binding data via `ChannelBinding` struct, rather than having library extract it from TLS connection.

**Rationale**:
- Library is TLS-implementation agnostic
- Different TLS libraries have different APIs
- Application already has access to TLS connection
- Keeps library dependencies minimal
- Follows principle of "mechanism, not policy"

### 3. Backward Compatibility

**Decision**: All existing APIs remain unchanged. Channel binding is opt-in via `WithChannelBinding()`.

**Rationale**:
- Doesn't break existing users
- Clear migration path
- Channel binding requires application support anyway

### 4. "y" Flag Support

**Decision**: Initially use "n" for no-binding case. Add "y" flag support in future if mechanism negotiation is needed.

**Rationale**:
- "y" flag is primarily for mechanism negotiation scenarios
- Most applications know upfront whether to use PLUS or non-PLUS
- Can be added later without breaking API

## Security Considerations

1. **Downgrade Attack Prevention**: The gs2-cbind-flag mechanism prevents downgrade attacks where an attacker strips channel binding.

2. **Constant-Time Comparison**: Use `hmac.Equal()` for all channel binding data comparisons (already done for other comparisons).

3. **TLS 1.3 Preference**: Documentation should recommend tls-exporter for TLS 1.3 connections.

4. **Renegotiation**: Document that tls-exporter MUST NOT be used when TLS renegotiation is enabled.

5. **Data Validation**: Validate channel binding type format per RFC 5056 (alphanumeric, dot, hyphen only).

## Testing Strategy

1. **Unit Tests**: Each phase includes unit tests for new functions
2. **Integration Tests**: Full client-server conversations with channel binding
3. **Compatibility Tests**: Verify backward compatibility with existing tests
4. **Negative Tests**: Error cases (mismatched binding, wrong type, etc.)
5. **RFC Compliance**: Test cases based on RFC 5802 examples

## Migration Guide for Users

### For Applications Using This Library

**Before** (no channel binding):
```go
client, _ := scram.SHA256.NewClient("user", "pass", "")
conv := client.NewConversation()
```

**After** (with channel binding):
```go
// Obtain channel binding data from TLS connection
// For tls-exporter with Go crypto/tls:
tlsConn := ... // your tls.Conn
cbData, _ := tlsConn.ExportKeyingMaterial(
    "EXPORTER-Channel-Binding",
    nil,
    32,
)

client, _ := scram.SHA256.NewClient("user", "pass", "")
client.WithChannelBinding(ChannelBinding{
    Type: ChannelBindingTLSExporter,
    Data: cbData,
})
conv := client.NewConversation()
```

## Open Questions

1. **Should we validate channel binding type format?** RFC 5056 specifies format, but should we enforce it?
   - **Decision**: Yes, add validation in Phase 2

2. **Should we provide helper functions for obtaining channel binding data?** E.g., `GetTLSExporterBinding(*tls.Conn)`
   - **Decision**: No, keep library TLS-agnostic. Document in examples.

3. **Should we support custom/unknown channel binding types?**
   - **Decision**: Yes, allow any string matching RFC 5056 format

4. **Should StoredCredentials be different for PLUS variants?**
   - **Decision**: No, same credentials work for both. Channel binding is separate from password hashing.

## References

- [RFC 5056: On Channel Binding](https://tools.ietf.org/html/rfc5056)
- [RFC 5802: SCRAM SASL Mechanism](https://tools.ietf.org/html/rfc5802)
- [RFC 5929: Channel Bindings for TLS](https://tools.ietf.org/html/rfc5929)
- [RFC 7627: TLS Session Hash and Extended Master Secret Extension](https://tools.ietf.org/html/rfc7627)
- [RFC 7677: SCRAM-SHA-256](https://tools.ietf.org/html/rfc7677)
- [RFC 9266: Channel Bindings for TLS 1.3](https://tools.ietf.org/html/rfc9266)
- [Issue #2: SCRAM variants with channel binding](https://github.com/xdg-go/scram/issues/2)
- [Issue #10: RFC 9266 support](https://github.com/xdg-go/scram/issues/10)
