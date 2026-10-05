package cert

import "encoding/pem"

// pemEncode wraps DER bytes in a PEM block. Kept in a separate file so
// cert.go stays readable.
func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}
