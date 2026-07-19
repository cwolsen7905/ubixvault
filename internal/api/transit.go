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

func writeTransitError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, barrier.ErrSealed):
		writeError(w, http.StatusServiceUnavailable, "vault is sealed")
	case errors.Is(err, transit.ErrKeyNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, transit.ErrKeyExists),
		errors.Is(err, transit.ErrInvalidName),
		errors.Is(err, transit.ErrInvalidCiphertext):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}
