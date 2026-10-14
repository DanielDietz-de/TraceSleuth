// Storage package provides embedded Redis storage using miniredis
// This allows the application to run without any external dependencies

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// AnalysisStatus represents the current state of an analysis job
type AnalysisStatus string

const (
	StatusPending   AnalysisStatus = "pending"
	StatusUploading AnalysisStatus = "uploading"
	StatusAnalyzing AnalysisStatus = "analyzing"
	StatusCompleted AnalysisStatus = "completed"
	StatusFailed    AnalysisStatus = "failed"
	StatusCancelled AnalysisStatus = "cancelled"
)

// AnalysisJob represents a PCAP analysis job
type AnalysisJob struct {
	ID            string         `json:"id"`
	FileName      string         `json:"file_name"`
	FileSize      int64          `json:"file_size"`
	FilePath      string         `json:"file_path"`
	KeyLogPath    string         `json:"key_log_path,omitempty"` // Optional NSS SSL Key Log file for TLS decryption
	Status        AnalysisStatus `json:"status"`
	Progress      int            `json:"progress"`
	CurrentStep   string         `json:"current_step"`
	EstimatedTime int            `json:"estimated_time"` // seconds remaining
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	CompletedAt   *time.Time     `json:"completed_at,omitempty"`
	Error         string         `json:"error,omitempty"`
	ResultsPath   string         `json:"results_path,omitempty"`
	HTMLPath      string         `json:"html_path,omitempty"`
}

// Storage provides embedded Redis storage and file management
type Storage struct {
	mini       *miniredis.Miniredis
	client     *redis.Client
	dataDir    string
	uploadsDir string
	resultsDir string
	mu         sync.RWMutex

	// Progress subscribers for WebSocket updates
	subscribers map[string][]chan *AnalysisJob
	subMu       sync.RWMutex
}

// NewStorage creates a new storage instance with embedded Redis
// Upload bounds apply to actual bytes copied, not only multipart metadata.
const (
	MaxCaptureBytes int64 = 500 << 20
	MaxKeyLogBytes  int64 = 8 << 20
)

var ErrUploadTooLarge = fmt.Errorf("uploaded file exceeds configured size limit")

func NewStorage() (*Storage, error) {
	// Start embedded Redis
	mini, err := miniredis.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to start embedded Redis: %w", err)
	}

	// Create Redis client
	client := redis.NewClient(&redis.Options{
		Addr: mini.Addr(),
	})

	// Test connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		mini.Close()
		return nil, fmt.Errorf("failed to connect to embedded Redis: %w", err)
	}

	// Create data directories
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}

	dataDir := filepath.Join(homeDir, ".sdwan-triage")
	uploadsDir := filepath.Join(dataDir, "uploads")
	resultsDir := filepath.Join(dataDir, "results")

	for _, dir := range []string{dataDir, uploadsDir, resultsDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			mini.Close()
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		// Older installations may have created these sensitive paths world-readable.
		if err := os.Chmod(dir, 0700); err != nil {
			mini.Close()
			return nil, fmt.Errorf("failed to restrict data directory %s: %w", dir, err)
		}
	}

	s := &Storage{
		mini:        mini,
		client:      client,
		dataDir:     dataDir,
		uploadsDir:  uploadsDir,
		resultsDir:  resultsDir,
		subscribers: make(map[string][]chan *AnalysisJob),
	}

	// Load persisted data if exists
	if err := s.loadPersistedData(); err != nil {
		// Log but don't fail - fresh start is okay
		fmt.Printf("Note: Could not load persisted data: %v\n", err)
	}

	return s, nil
}

// Close shuts down the storage
func (s *Storage) Close() error {
	// Persist data before closing
	if err := s.persistData(); err != nil {
		fmt.Printf("Warning: Failed to persist data: %v\n", err)
	}

	if s.client != nil {
		s.client.Close()
	}
	if s.mini != nil {
		s.mini.Close()
	}
	return nil
}

// GetUploadsDir returns the uploads directory path
func (s *Storage) GetUploadsDir() string {
	return s.uploadsDir
}

// GetResultsDir returns the results directory path
func (s *Storage) GetResultsDir() string {
	return s.resultsDir
}

// GetDataDir returns the base data directory path
func (s *Storage) GetDataDir() string {
	return s.dataDir
}

// CreateJob creates a new analysis job
func (s *Storage) CreateJob(id, fileName string, fileSize int64, filePath string) (*AnalysisJob, error) {
	job := &AnalysisJob{
		ID:          id,
		FileName:    fileName,
		FileSize:    fileSize,
		FilePath:    filePath,
		Status:      StatusPending,
		Progress:    0,
		CurrentStep: "Waiting to start",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.saveJob(job); err != nil {
		return nil, err
	}

	// Add to history sorted set
	ctx := context.Background()
	s.client.ZAdd(ctx, "analysis:history", redis.Z{
		Score:  float64(job.CreatedAt.Unix()),
		Member: job.ID,
	})

	return job, nil
}

// GetJob retrieves an analysis job by ID
func (s *Storage) GetJob(id string) (*AnalysisJob, error) {
	ctx := context.Background()
	data, err := s.client.HGetAll(ctx, "job:"+id).Result()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("job not found: %s", id)
	}

	return s.parseJobData(data)
}

// UpdateJob updates an analysis job
func (s *Storage) UpdateJob(job *AnalysisJob) error {
	job.UpdatedAt = time.Now()
	if err := s.saveJob(job); err != nil {
		return err
	}

	// Notify subscribers
	s.notifySubscribers(job)
	return nil
}

// ErrAnalysisCancelled prevents any progress or terminal update from
// resurrecting a cancelled job while an expensive preflight is running.
var ErrAnalysisCancelled = errors.New("analysis cancelled")

// UpdateProgress updates job progress and notifies subscribers
func (s *Storage) UpdateProgress(id string, progress int, currentStep string, estimatedTime int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.GetJob(id)
	if err != nil {
		return err
	}
	if job.Status == StatusCancelled {
		return ErrAnalysisCancelled
	}
	if job.Status == StatusCompleted {
		return fmt.Errorf("analysis already completed")
	}
	job.Progress = progress
	job.CurrentStep = currentStep
	job.EstimatedTime = estimatedTime
	job.Status = StatusAnalyzing
	return s.UpdateJob(job)
}

// CompleteJob marks a job as completed
func (s *Storage) CompleteJob(id, resultsPath, htmlPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.GetJob(id)
	if err != nil {
		return err
	}
	if job.Status == StatusCancelled {
		return ErrAnalysisCancelled
	}

	now := time.Now()
	job.Status = StatusCompleted
	job.Progress = 100
	job.CurrentStep = "Analysis complete"
	job.EstimatedTime = 0
	job.CompletedAt = &now
	job.ResultsPath = resultsPath
	job.HTMLPath = htmlPath

	return s.UpdateJob(job)
}

// FailJob marks a job as failed
func (s *Storage) FailJob(id, errorMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.GetJob(id)
	if err != nil {
		return err
	}
	if job.Status == StatusCancelled {
		return ErrAnalysisCancelled
	}

	now := time.Now()
	job.Status = StatusFailed
	job.Error = errorMsg
	job.CompletedAt = &now
	job.CurrentStep = "Analysis failed"

	return s.UpdateJob(job)
}

// CancelJob marks a job as cancelled
func (s *Storage) CancelJob(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.GetJob(id)
	if err != nil {
		return err
	}
	if job.Status == StatusCompleted || job.Status == StatusFailed {
		return fmt.Errorf("analysis already finished")
	}
	if job.Status == StatusCancelled {
		return nil
	}

	now := time.Now()
	job.Status = StatusCancelled
	job.CompletedAt = &now
	job.CurrentStep = "Analysis cancelled"

	return s.UpdateJob(job)
}

// ListHistory returns all analysis jobs ordered by creation time (newest first)
func (s *Storage) ListHistory(limit, offset int) ([]*AnalysisJob, int64, error) {
	ctx := context.Background()

	// Get total count
	total, err := s.client.ZCard(ctx, "analysis:history").Result()
	if err != nil {
		return nil, 0, err
	}

	// Get job IDs in reverse order (newest first)
	ids, err := s.client.ZRevRange(ctx, "analysis:history", int64(offset), int64(offset+limit-1)).Result()
	if err != nil {
		return nil, 0, err
	}

	jobs := make([]*AnalysisJob, 0, len(ids))
	for _, id := range ids {
		job, err := s.GetJob(id)
		if err != nil {
			continue // Skip jobs that can't be loaded
		}
		jobs = append(jobs, job)
	}

	return jobs, total, nil
}

// DeleteJob removes a job and its associated files
func (s *Storage) DeleteJob(id string) error {
	job, err := s.GetJob(id)
	if err != nil {
		return err
	}

	// Refuse to remove any path outside the managed directories, including
	// paths from persisted legacy metadata that may contain traversal input.
	for _, f := range []struct{ root, path string }{
		{s.uploadsDir, job.FilePath},
		{s.uploadsDir, job.KeyLogPath},
		{s.resultsDir, job.ResultsPath},
		{s.resultsDir, job.HTMLPath},
	} {
		if f.path != "" && !isManagedFile(f.root, f.path) {
			return fmt.Errorf("refusing to delete unmanaged analysis file")
		}
	}
	for _, path := range []string{job.FilePath, job.KeyLogPath, job.ResultsPath, job.HTMLPath} {
		if path != "" {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	// Do not construct directory-removal paths from a request or persisted ID.
	// Empty owner-private job directories are intentionally left for a future
	// root-scoped retention sweep; no attacker-controlled path is removed.

	// Delete from Redis
	ctx := context.Background()
	s.client.Del(ctx, "job:"+id)
	s.client.ZRem(ctx, "analysis:history", id)

	return nil
}

// Subscribe creates a channel for receiving job updates
func (s *Storage) Subscribe(jobID string) chan *AnalysisJob {
	s.subMu.Lock()
	defer s.subMu.Unlock()

	ch := make(chan *AnalysisJob, 10)
	s.subscribers[jobID] = append(s.subscribers[jobID], ch)
	return ch
}

// Unsubscribe removes a subscription channel
func (s *Storage) Unsubscribe(jobID string, ch chan *AnalysisJob) {
	s.subMu.Lock()
	defer s.subMu.Unlock()

	subs := s.subscribers[jobID]
	for i, sub := range subs {
		if sub == ch {
			s.subscribers[jobID] = append(subs[:i], subs[i+1:]...)
			close(ch)
			break
		}
	}

	// Clean up empty subscriber lists
	if len(s.subscribers[jobID]) == 0 {
		delete(s.subscribers, jobID)
	}
}

// SaveUploadedFile preserves the existing API for normal packet captures.
func (s *Storage) SaveUploadedFile(id string, reader io.Reader, fileName string) (string, error) {
	return s.SaveUploadedFileLimited(id, reader, MaxCaptureBytes)
}

// SaveUploadedFileLimited writes at most maxBytes into a private, random-named
// file. Untrusted multipart filenames are display metadata only and must never
// become filesystem path components.
func (s *Storage) SaveUploadedFileLimited(id string, reader io.Reader, maxBytes int64) (string, error) {
	if _, err := uuid.Parse(id); err != nil {
		return "", fmt.Errorf("invalid upload job identifier: %w", err)
	}
	if maxBytes <= 0 {
		return "", fmt.Errorf("invalid upload size limit")
	}
	jobDir := filepath.Join(s.uploadsDir, id)
	if err := os.MkdirAll(jobDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create upload directory: %w", err)
	}
	if err := os.Chmod(jobDir, 0700); err != nil {
		return "", fmt.Errorf("failed to secure upload directory: %w", err)
	}
	file, err := os.CreateTemp(jobDir, "upload-*")
	if err != nil {
		return "", fmt.Errorf("failed to create upload file: %w", err)
	}
	filePath := file.Name()
	// Do not leave a partial file accessible if streaming or closing fails.
	written, copyErr := io.Copy(file, io.LimitReader(reader, maxBytes+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written > maxBytes {
		os.Remove(filePath)
		switch {
		case written > maxBytes:
			return "", ErrUploadTooLarge
		case copyErr != nil:
			return "", fmt.Errorf("failed to stream upload: %w", copyErr)
		default:
			return "", fmt.Errorf("failed to close upload: %w", closeErr)
		}
	}
	return filePath, nil
}

// GetResultsFile returns the path to a results file
func (s *Storage) GetResultsFile(id, fileType string) (string, error) {
	job, err := s.GetJob(id)
	if err != nil {
		return "", err
	}

	switch fileType {
	case "json":
		if job.ResultsPath == "" {
			return "", fmt.Errorf("JSON results not available")
		}
		if !isManagedFile(s.resultsDir, job.ResultsPath) {
			return "", fmt.Errorf("refusing unmanaged JSON results path")
		}
		return job.ResultsPath, nil
	case "html":
		if job.HTMLPath == "" {
			return "", fmt.Errorf("HTML report not available")
		}
		if !isManagedFile(s.resultsDir, job.HTMLPath) {
			return "", fmt.Errorf("refusing unmanaged HTML results path")
		}
		return job.HTMLPath, nil
	default:
		return "", fmt.Errorf("unknown file type: %s", fileType)
	}
}

// GetResultsPath returns the JSON results path for a job, or empty string if not available
func (s *Storage) GetResultsPath(id string) string {
	// Every result-reading API must pass through the same containment check.
	path, err := s.GetResultsFile(id, "json")
	if err != nil {
		return ""
	}
	return path
}

// ListJobs returns completed analysis jobs (simplified version for trends)
func (s *Storage) ListJobs(limit, offset int) ([]*AnalysisJob, error) {
	jobs, _, err := s.ListHistory(limit, offset)
	if err != nil {
		return nil, err
	}
	return jobs, nil
}

// Internal helper methods

func (s *Storage) saveJob(job *AnalysisJob) error {
	ctx := context.Background()

	data := map[string]interface{}{
		"id":             job.ID,
		"file_name":      job.FileName,
		"file_size":      job.FileSize,
		"file_path":      job.FilePath,
		"key_log_path":   job.KeyLogPath,
		"status":         string(job.Status),
		"progress":       job.Progress,
		"current_step":   job.CurrentStep,
		"estimated_time": job.EstimatedTime,
		"created_at":     job.CreatedAt.Format(time.RFC3339),
		"updated_at":     job.UpdatedAt.Format(time.RFC3339),
		"error":          job.Error,
		"results_path":   job.ResultsPath,
		"html_path":      job.HTMLPath,
	}

	if job.CompletedAt != nil {
		data["completed_at"] = job.CompletedAt.Format(time.RFC3339)
	}

	return s.client.HSet(ctx, "job:"+job.ID, data).Err()
}

func (s *Storage) parseJobData(data map[string]string) (*AnalysisJob, error) {
	job := &AnalysisJob{
		ID:          data["id"],
		FileName:    data["file_name"],
		FilePath:    data["file_path"],
		KeyLogPath:  data["key_log_path"],
		Status:      AnalysisStatus(data["status"]),
		CurrentStep: data["current_step"],
		Error:       data["error"],
		ResultsPath: data["results_path"],
		HTMLPath:    data["html_path"],
	}

	// Parse numeric fields
	fmt.Sscanf(data["file_size"], "%d", &job.FileSize)
	fmt.Sscanf(data["progress"], "%d", &job.Progress)
	fmt.Sscanf(data["estimated_time"], "%d", &job.EstimatedTime)

	// Parse time fields
	if t, err := time.Parse(time.RFC3339, data["created_at"]); err == nil {
		job.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, data["updated_at"]); err == nil {
		job.UpdatedAt = t
	}
	if data["completed_at"] != "" {
		if t, err := time.Parse(time.RFC3339, data["completed_at"]); err == nil {
			job.CompletedAt = &t
		}
	}

	return job, nil
}

func (s *Storage) notifySubscribers(job *AnalysisJob) {
	s.subMu.RLock()
	defer s.subMu.RUnlock()

	subs := s.subscribers[job.ID]
	for _, ch := range subs {
		select {
		case ch <- job:
		default:
			// Channel full, skip
		}
	}
}

// Persistence methods for data survival across restarts

func (s *Storage) persistData() error {
	ctx := context.Background()

	// Get all job IDs
	ids, err := s.client.ZRange(ctx, "analysis:history", 0, -1).Result()
	if err != nil {
		return err
	}

	jobs := make([]*AnalysisJob, 0, len(ids))
	for _, id := range ids {
		job, err := s.GetJob(id)
		if err != nil {
			continue
		}
		jobs = append(jobs, job)
	}

	// Save to file
	data, err := json.MarshalIndent(jobs, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(s.dataDir, "history.json"), data, 0644)
}

func (s *Storage) loadPersistedData() error {
	data, err := os.ReadFile(filepath.Join(s.dataDir, "history.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No persisted data, that's okay
		}
		return err
	}

	var jobs []*AnalysisJob
	if err := json.Unmarshal(data, &jobs); err != nil {
		return err
	}

	ctx := context.Background()
	for _, job := range jobs {
		// Only restore completed or failed jobs
		if job.Status == StatusCompleted || job.Status == StatusFailed {
			s.saveJob(job)
			s.client.ZAdd(ctx, "analysis:history", redis.Z{
				Score:  float64(job.CreatedAt.Unix()),
				Member: job.ID,
			})
		}
	}

	return nil
}

// isManagedFile uses path components rather than prefix comparisons. A
// filename like /data/results-extra must not be treated as /data/results.
func isManagedFile(root, candidate string) bool {
	if candidate == "" {
		return false
	}
	base, baseErr := filepath.Abs(root)
	file, fileErr := filepath.Abs(candidate)
	if baseErr != nil || fileErr != nil {
		return false
	}
	rel, err := filepath.Rel(base, file)
	return err == nil && rel != "." && rel != ".." &&
		!strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
