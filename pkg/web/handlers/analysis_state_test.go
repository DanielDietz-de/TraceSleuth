package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/pkg/web/storage"
	"github.com/google/uuid"
)

// Terminal analysis jobs require a new upload; /analyze must not return an
// optimistic 202 Accepted and then silently abandon the async worker.
func TestStartAnalysisRejectsCancelledAndFailedJobs(t *testing.T) {
	for _, terminal := range []storage.AnalysisStatus{storage.StatusCancelled, storage.StatusFailed} {
		t.Run(string(terminal), func(t *testing.T) {
			router, _, store := setupTestRouter(t)
			id := uuid.NewString()
			job, err := store.CreateJob(id, "capture.pcap", 1, filepath.Join(t.TempDir(), "capture.pcap"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.BeginAnalysis(id)
			if err != nil {
				t.Fatal(err)
			}
			if terminal == storage.StatusCancelled {
				err = store.CancelJob(id)
			} else {
				err = store.FailJob(id, "test failure")
			}
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/analyze/%s", job.ID), nil)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusConflict {
				t.Fatalf("terminal status %s received HTTP %d, want 409: %s", terminal, recorder.Code, recorder.Body.String())
			}
			updated, err := store.GetJob(id)
			if err != nil {
				t.Fatal(err)
			}
			if updated.Status != terminal {
				t.Fatalf("terminal state changed: %+v", updated)
			}
		})
	}
}

// Compile-time check: the actual HTTP handler still matches Gin's handler contract.
var _ gin.HandlerFunc = (*Handlers)(nil).StartAnalysis
