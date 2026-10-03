package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Key is one signing key as GET /evidence/keys publishes it and a bundle's keys.json carries it.
type Key struct {
	KeyID     string     `json:"key_id"`
	Algorithm string     `json:"algorithm,omitempty"`
	PublicKey string     `json:"public_key"`
	Custody   string     `json:"custody,omitempty"`
	Provider  string     `json:"provider,omitempty"`
	State     string     `json:"state,omitempty"`
	ValidFrom time.Time  `json:"valid_from"`
	ValidTo   *time.Time `json:"valid_to,omitempty"`
}

// Custody values (ADR-087 §1).
const (
	CustodyVendor   = "vendor"
	CustodyCustomer = "customer"
)

// WindowGrace is how long before a key's valid_from a signed item may be dated: the snapshot is read
// before the key that signs it is created on an organisation's first use. It is the server's
// signing.SnapshotGrace; a test in cmd/assure keeps the two equal.
const WindowGrace = 5 * time.Minute

// ErrOutsideWindow is a signature dated outside its key's validity window.
var ErrOutsideWindow = errors.New("signature outside the key's validity window")

// CheckWindow reports whether an item dated at falls inside [validFrom − WindowGrace, validTo). A
// zero validFrom has no lower bound (the instance key published as retired); a nil validTo has no
// upper bound. It is the rule of the server's signing.CheckWindow.
func CheckWindow(validFrom time.Time, validTo *time.Time, at time.Time) error {
	if at.IsZero() {
		return fmt.Errorf("%w: the signed item carries no time", ErrOutsideWindow)
	}
	if !validFrom.IsZero() && at.Before(validFrom.Add(-WindowGrace)) {
		return fmt.Errorf("%w: dated %s, key valid from %s", ErrOutsideWindow,
			at.UTC().Format(time.RFC3339), validFrom.UTC().Format(time.RFC3339))
	}
	if validTo != nil && !at.Before(*validTo) {
		return fmt.Errorf("%w: dated %s, key valid until %s", ErrOutsideWindow,
			at.UTC().Format(time.RFC3339), validTo.UTC().Format(time.RFC3339))
	}
	return nil
}

// KeyID is the first 16 hex characters of SHA-256 over the raw Ed25519 public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// ParseKeys reads {"keys": [...]}, a bare array, or one key object.
func ParseKeys(raw []byte) ([]Key, error) {
	var list struct {
		Keys []Key `json:"keys"`
	}
	if err := json.Unmarshal(raw, &list); err == nil && list.Keys != nil {
		return list.Keys, nil
	}
	var arr []Key
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	var one Key
	if err := json.Unmarshal(raw, &one); err != nil || one.KeyID == "" {
		return nil, errors.New("not a key list: expected GET /evidence/keys, a keys.json array or one GET /evidence/key")
	}
	return []Key{one}, nil
}

// publicKey decodes the key and checks that its key id is the hash of the public key.
func (k Key) publicKey() (ed25519.PublicKey, error) {
	if k.Algorithm != "" && k.Algorithm != "ed25519" {
		return nil, fmt.Errorf("algorithm %q is not ed25519", k.Algorithm)
	}
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("the public key is not a base64 Ed25519 key")
	}
	if KeyID(raw) != k.KeyID {
		return nil, errors.New("the key id is not the hash of the public key")
	}
	return ed25519.PublicKey(raw), nil
}

// keyring is the key list the verifier trusts for this run, and what it learnt about each key.
type keyring struct {
	from    string // where the list came from ("" when there is none)
	keys    map[string]Key
	order   []string
	invalid map[string]string // key id → why it is unusable
	signed  map[string][]string
}

func newKeyring(from string, keys []Key) *keyring {
	kr := &keyring{from: from, keys: map[string]Key{}, invalid: map[string]string{}, signed: map[string][]string{}}
	for _, k := range keys {
		if _, dup := kr.keys[k.KeyID]; dup {
			kr.invalid[k.KeyID] = "listed twice"
			continue
		}
		kr.keys[k.KeyID] = k
		kr.order = append(kr.order, k.KeyID)
		if _, err := k.publicKey(); err != nil {
			kr.invalid[k.KeyID] = err.Error()
		}
	}
	return kr
}

// verify checks sig over msg with the named key, dated at; it records what the key signed.
func (kr *keyring) verify(item, keyID string, msg, sig []byte, at time.Time) error {
	k, ok := kr.keys[keyID]
	if !ok {
		return fmt.Errorf("key %s is not in the key list (%s)", keyID, kr.from)
	}
	if why, bad := kr.invalid[keyID]; bad {
		return fmt.Errorf("key %s is unusable: %s", keyID, why)
	}
	pub, err := k.publicKey()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("the Ed25519 signature does not verify against key %s", keyID)
	}
	if err := CheckWindow(k.ValidFrom, k.ValidTo, at); err != nil {
		return fmt.Errorf("key %s: %w", keyID, err)
	}
	kr.signed[keyID] = append(kr.signed[keyID], item)
	return nil
}

// custody prints every key of the list, its custody and what it signed here.
func (kr *keyring) custody(r *Report) {
	for _, id := range kr.order {
		k := kr.keys[id]
		kc := KeyCustody{KeyID: id, Custody: k.Custody, Provider: k.Provider, State: k.State, ValidTo: k.ValidTo, Signed: kr.signed[id]}
		if !k.ValidFrom.IsZero() {
			from := k.ValidFrom.UTC()
			kc.ValidFrom = &from
		}
		window := "no window of its own"
		if !k.ValidFrom.IsZero() {
			window = "valid from " + k.ValidFrom.UTC().Format(time.RFC3339)
			if k.ValidTo != nil {
				window += " until " + k.ValidTo.UTC().Format(time.RFC3339)
			}
		}
		switch k.Custody {
		case CustodyVendor:
			kc.Note = "custody vendor: Sixi holds this private key; a signature by it relies on the vendor's custodian and its key ceremony record"
		case CustodyCustomer:
			kc.Note = "custody customer: the organisation holds this private key; Sixi cannot sign with it"
		case "":
			kc.Custody = "unknown"
			kc.Note = "custody " + NotPresent + "; treat the key as held by Sixi"
		default:
			kc.Note = fmt.Sprintf("custody %q is neither vendor nor customer", k.Custody)
		}
		r.Keys = append(r.Keys, kc)
		st := Info
		detail := fmt.Sprintf("%s; provider %s, state %s, %s; signed here: %d item(s)", kc.Note, orNA(k.Provider), orNA(k.State), window, len(kc.Signed))
		if why, bad := kr.invalid[id]; bad {
			st, detail = Fail, "unusable: "+why
		} else if k.Custody != "" && k.Custody != CustodyVendor && k.Custody != CustodyCustomer {
			st = Fail
		}
		r.add(SectionKeys, "key "+id, st, "%s", detail)
	}
}

func orNA(s string) string {
	if s == "" {
		return NotPresent
	}
	return s
}
