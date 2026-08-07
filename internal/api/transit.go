package api

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/transit"
)

func (h *Handler) transitCreateKey(w http.ResponseWriter, r *http.Request) {
	info, err := h.transit.CreateKey(r.Context(), r.PathValue("name"))
	if err != nil {
		writeTransitError(w, err)
		return
	}
	writeData(w, info)
}

func (h *Handler) transitRotateKey(w http.ResponseWriter, r *http.Request) {
	info, err := h.transit.Rotate(r.Context(), r.PathValue("name"))
	if err != nil {
		writeTransitError(w, err)
		return
	}
	writeData(w, info)
}

func (h *Handler) transitReadKey(w http.ResponseWriter, r *http.Request) {
	info, err := h.transit.ReadKey(r.Context(), r.PathValue("name"))
	if err != nil {
		writeTransitError(w, err)
		return
	}
	writeData(w, info)
}

func (h *Handler) transitListKeys(w http.ResponseWriter, r *http.Request) {
	names, err := h.transit.ListKeys(r.Context())
	if err != nil {
		writeTransitError(w, err)
		return
	}
	writeData(w, map[string]any{"keys": names})
}

func (h *Handler) transitDeleteKey(w http.ResponseWriter, r *http.Request) {
	if err := h.transit.DeleteKey(r.Context(), r.PathValue("name")); err != nil {
		writeTransitError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// transitEncrypt takes base64 plaintext and returns transit ciphertext.
func (h *Handler) transitEncrypt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Plaintext string `json:"plaintext"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		writeError(w, http.StatusBadRequest, "plaintext must be base64")
		return
	}
	ciphertext, err := h.transit.Encrypt(r.Context(), r.PathValue("name"), plaintext)
	if err != nil {
		writeTransitError(w, err)
		return
	}
	writeData(w, map[string]any{"ciphertext": ciphertext})
}

// transitDecrypt takes transit ciphertext and returns base64 plaintext.
func (h *Handler) transitDecrypt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	plaintext, err := h.transit.Decrypt(r.Context(), r.PathValue("name"), req.Ciphertext)
	if err != nil {
		writeTransitError(w, err)
		return
	}
	writeData(w, map[string]any{"plaintext": base64.StdEncoding.EncodeToString(plaintext)})
}

// transitRewrap re-encrypts a ciphertext under the key's latest version.
func (h *Handler) transitRewrap(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ciphertext, err := h.transit.Rewrap(r.Context(), r.PathValue("name"), req.Ciphertext)
	if err != nil {
		writeTransitError(w, err)
		return
	}
	writeData(w, map[string]any{"ciphertext": ciphertext})
}

// transitDataKey generates a random data key wrapped under the named key. The
// {mode} path segment is "plaintext" (return the key and its wrapped form) or
// "wrapped" (return only the wrapped form). An optional {"bits":N} body selects
// the key size (128/256/512; default 256).
func (h *Handler) transitDataKey(w http.ResponseWriter, r *http.Request) {
	mode := r.PathValue("mode")
	if mode != "plaintext" && mode != "wrapped" {
		writeError(w, http.StatusBadRequest, "mode must be plaintext or wrapped")
		return
	}
	req := struct {
		Bits int `json:"bits"`
	}{Bits: 256}
	if r.ContentLength != 0 {
		if !decodeJSON(w, r, &req) {
			return
		}
	}
	plaintext, wrapped, err := h.transit.GenerateDataKey(r.Context(), r.PathValue("name"), req.Bits)
	if err != nil {
		writeTransitError(w, err)
		return
	}
	out := map[string]any{"ciphertext": wrapped}
	if mode == "plaintext" {
		out["plaintext"] = base64.StdEncoding.EncodeToString(plaintext)
	}
	writeData(w, out)
}

func writeTransitError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, barrier.ErrSealed):
		writeError(w, http.StatusServiceUnavailable, "vault is sealed")
	case errors.Is(err, transit.ErrKeyNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, transit.ErrKeyExists),
		errors.Is(err, transit.ErrInvalidName),
		errors.Is(err, transit.ErrInvalidCiphertext),
		errors.Is(err, transit.ErrInvalidDataKeyBits):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeInternal(w, err)
	}
}
