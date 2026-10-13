package distribution

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
)

var (
	ErrInvalidSignature       = errors.New("signature du manifeste invalide ou corrompue")
	ErrSignatureLengthMismatch = errors.New("longueur de signature cryptographique invalide")
)

// DefaultPhase0PublicKey is a dedicated Ed25519 public key for platform distribution.
// (Hex-encoded 32 bytes)
const DefaultPhase0PublicKeyHex = "c59fd4e179c55a3dd2110785d9ae7a9b4adafc1e54ca3dcde54e2f3c3458645f"

// SignManifest creates an Ed25519 signature over manifest bytes and returns it in hex.
func SignManifest(manifestBytes []byte, privKey ed25519.PrivateKey) string {
	sig := ed25519.Sign(privKey, manifestBytes)
	return hex.EncodeToString(sig)
}

// VerifyManifest verifies that sigHex matches manifestBytes using pubKey.
func VerifyManifest(manifestBytes []byte, sigHex string, pubKey ed25519.PublicKey) error {
	sigHex = strings.TrimSpace(sigHex)
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return ErrInvalidSignature
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrSignatureLengthMismatch
	}
	if !ed25519.Verify(pubKey, manifestBytes, sig) {
		return ErrInvalidSignature
	}
	return nil
}
