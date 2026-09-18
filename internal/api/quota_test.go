package api

import (
	"net/http"
	"testing"
)

func TestQuota_RateLimitCRUD(t *testing.T) {
	h, root := unsealedHandler(t)

	// Create.
	if rec := doAuth(t, h, "POST", "/v1/sys/quotas/rate-limit/apicap",
		`{"path":"secret/","rate":50,"burst":100}`, root); rec.Code != http.StatusNoContent {
		t.Fatalf("create: code=%d body=%s", rec.Code, rec.Body)
	}

	// Read back.
	rec := doAuth(t, h, "GET", "/v1/sys/quotas/rate-limit/apicap", "", root)
	if rec.Code != http.StatusOK {
		t.Fatalf("read: code=%d body=%s", rec.Code, rec.Body)
	}
	got := decode[struct {
		Data struct {
			Name, Type, Path string
			Rate, Burst      float64
		}
	}](t, rec)
	d := got.Data
	if d.Name != "apicap" || d.Type != "rate-limit" || d.Path != "secret/" || d.Rate != 50 || d.Burst != 100 {
		t.Errorf("read fields: %+v", d)
	}

	// List.
	rec = doAuth(t, h, "LIST", "/v1/sys/quotas/rate-limit", "", root)
	list := decode[struct{ Data struct{ Keys []string } }](t, rec)
	if len(list.Data.Keys) != 1 || list.Data.Keys[0] != "apicap" {
		t.Errorf("list keys = %v, want [apicap]", list.Data.Keys)
	}

	// Delete → gone.
	if rec := doAuth(t, h, "DELETE", "/v1/sys/quotas/rate-limit/apicap", "", root); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: code=%d", rec.Code)
	}
	if rec := doAuth(t, h, "GET", "/v1/sys/quotas/rate-limit/apicap", "", root); rec.Code != http.StatusNotFound {
		t.Errorf("read after delete: code=%d, want 404", rec.Code)
	}
}

func TestQuota_RateLimitRequiresAuth(t *testing.T) {
	h, _ := unsealedHandler(t)
	if rec := doAuth(t, h, "POST", "/v1/sys/quotas/rate-limit/x", `{"rate":1}`, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated create: code=%d, want 401", rec.Code)
	}
}

func TestQuota_RateLimitValidation(t *testing.T) {
	h, root := unsealedHandler(t)
	if rec := doAuth(t, h, "POST", "/v1/sys/quotas/rate-limit/bad", `{"path":"secret/","rate":0}`, root); rec.Code != http.StatusBadRequest {
		t.Errorf("zero-rate create: code=%d, want 400", rec.Code)
	}
}

// TestQuota_EnforcedInMiddleware proves a path-scoped quota is enforced end to end:
// requests under the quota's path get a 429 once the burst is spent, while a
// request on an unrelated path is unaffected.
func TestQuota_EnforcedInMiddleware(t *testing.T) {
	h, root := unsealedHandler(t)

	// rate 1, burst 2 on secret/ — two requests pass, the third is throttled.
	if rec := doAuth(t, h, "POST", "/v1/sys/quotas/rate-limit/secretcap",
		`{"path":"secret/","rate":1,"burst":2}`, root); rec.Code != http.StatusNoContent {
		t.Fatalf("create quota: code=%d body=%s", rec.Code, rec.Body)
	}

	// The endpoint itself would 404 (no secret written), but the quota is enforced
	// in the middleware *before* the handler, so status reflects the quota.
	codes := []int{}
	for i := 0; i < 3; i++ {
		codes = append(codes, doAuth(t, h, "GET", "/v1/secret/data/none", "", root).Code)
	}
	if codes[0] == http.StatusTooManyRequests || codes[1] == http.StatusTooManyRequests {
		t.Fatalf("first two requests should pass the quota; codes=%v", codes)
	}
	if codes[2] != http.StatusTooManyRequests {
		t.Errorf("third request should be 429 (burst spent); codes=%v", codes)
	}

	// A request on an unrelated path is not governed by the secret/ quota.
	if rec := doAuth(t, h, "GET", "/v1/sys/quotas/rate-limit/secretcap", "", root); rec.Code == http.StatusTooManyRequests {
		t.Error("unrelated path should not be throttled by the secret/ quota")
	}
}
