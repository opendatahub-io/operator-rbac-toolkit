package graceful

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// backoffTracker stores per-resource denial counts for exponential backoff.
type backoffTracker struct {
	mu     sync.Mutex
	counts map[string]int
}

func newBackoffTracker() *backoffTracker {
	return &backoffTracker{counts: make(map[string]int)}
}

func (b *backoffTracker) increment(key string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.counts[key]++
	return b.counts[key]
}

func (b *backoffTracker) reset(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.counts, key)
}

// NOTE: resetAll() was intentionally removed. When Do() succeeds, we don't know
// which resource the fn() operated on, so clearing all backoff entries would
// incorrectly reset backoff for resources that are still failing (e.g., a
// success on secrets would reset backoff for still-denied configmaps).
// Instead, callers who know the resource key can call ResetBackoff(key)
// explicitly. Stale entries in the counts map are harmless: each entry is a
// string key + int count, and the map resets when the Handler is garbage
// collected.

// Handler wraps controller-runtime client operations with permission-aware error handling.
type Handler struct {
	recorder record.EventRecorder
	opts     Options
	backoff  *backoffTracker
}

func NewHandler(recorder record.EventRecorder, options ...Option) *Handler {
	opts := defaultOptions()
	for _, o := range options {
		o(&opts)
	}
	return &Handler{
		recorder: recorder,
		opts:     opts,
		backoff:  newBackoffTracker(),
	}
}

// Do wraps a client operation with permission-aware error handling. When the
// operation returns a Forbidden error, Do sets status conditions, emits events,
// and returns a RequeueAfter result with exponential backoff. The obj must
// implement both client.Object and StatusProvider.
//
// Returns (ctrl.Result{}, nil) on success so callers can continue reconciliation.
// Returns (ctrl.Result{RequeueAfter: d}, nil) on Forbidden so the reconciler retries.
// Returns (ctrl.Result{}, err) for non-Forbidden errors.
func (h *Handler) Do(ctx context.Context, c client.Client, obj client.Object, fn func() error) (ctrl.Result, error) {
	err := fn()
	if err == nil {
		sp, ok := obj.(StatusProvider)
		if ok {
			prev := findCondition(sp, ConditionTypePermissionGranted)
			if prev != nil && prev.Status == metav1.ConditionFalse {
				SetPermissionGranted(sp, true, "All permissions available")
				if updateErr := UpdateStatus(ctx, c, obj); updateErr != nil {
					return ctrl.Result{}, fmt.Errorf("updating status after permission restored: %w", updateErr)
				}
				h.recorder.Event(obj, corev1.EventTypeNormal, EventReasonPermissionRestored, "Permission restored")
			}
		}
		return ctrl.Result{}, nil
	}

	if !errors.IsForbidden(err) {
		return ctrl.Result{}, err
	}

	msg := parseForbiddenMessage(err)
	backoffKey := backoffKeyFromError(err)

	count := h.backoff.increment(backoffKey)
	requeue := h.calculateBackoff(count)

	sp, ok := obj.(StatusProvider)
	if ok {
		SetPermissionGranted(sp, false, msg)
		if updateErr := UpdateStatus(ctx, c, obj); updateErr != nil {
			return ctrl.Result{}, fmt.Errorf("updating degraded status: %w", updateErr)
		}
	}

	h.recorder.Event(obj, corev1.EventTypeWarning, EventReasonPermissionDenied, msg)

	return ctrl.Result{RequeueAfter: requeue}, nil
}

func (h *Handler) calculateBackoff(count int) time.Duration {
	d := h.opts.RequeueAfter
	for i := 1; i < count; i++ {
		d = time.Duration(float64(d) * h.opts.BackoffFactor)
		if d > h.opts.MaxRequeue {
			return h.opts.MaxRequeue
		}
	}
	return d
}

func (h *Handler) ResetBackoff(key string) {
	h.backoff.reset(key)
}

// backoffKeyFromError extracts a structured key from a Forbidden error based on
// the resource group/resource/name, avoiding unbounded map growth from arbitrary
// error messages. The fallback truncates to 100 chars to prevent unbounded key
// growth from wrapped errors with variable suffixes.
func backoffKeyFromError(err error) string {
	if statusErr, ok := err.(*errors.StatusError); ok {
		d := statusErr.ErrStatus.Details
		if d != nil {
			return fmt.Sprintf("%s/%s/%s", d.Group, d.Kind, d.Name)
		}
	}
	s := err.Error()
	if len(s) > 100 {
		s = s[:100]
	}
	return s
}

func parseForbiddenMessage(err error) string {
	if statusErr, ok := err.(*errors.StatusError); ok {
		return statusErr.ErrStatus.Message
	}
	s := err.Error()
	if idx := strings.Index(s, "forbidden:"); idx >= 0 {
		return strings.TrimSpace(s[idx:])
	}
	return s
}
