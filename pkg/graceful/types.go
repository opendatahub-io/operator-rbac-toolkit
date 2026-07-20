package graceful

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	ConditionTypePermissionGranted = "PermissionGranted"
	ConditionTypeDegraded          = "Degraded"

	ReasonAllPermissionsAvailable = "AllPermissionsAvailable"
	ReasonMissingPermissions      = "MissingPermissions"
	ReasonInsufficientRBAC        = "InsufficientRBAC"
	ReasonFullyOperational        = "FullyOperational"
	ReasonProvisioningPending     = "ProvisioningPending"
	ReasonProvisioningInProgress  = "ProvisioningInProgress"
	ReasonPermissionDenied        = "PermissionDenied"

	EventReasonPermissionDenied   = "PermissionDenied"
	EventReasonPermissionRestored = "PermissionRestored"

	DefaultRequeueAfter   = 30 * time.Second
	DefaultMaxRequeue     = 5 * time.Minute
	DefaultMaxConcurrency = 10
	DefaultBackoffFactor  = 2.0
)

type ResourceSpec struct {
	Group    string
	Resource string
	Verbs    []string
}

type PermissionSpec struct {
	Resources      []ResourceSpec
	Namespaces     []string
	MaxConcurrency int
}

type PermissionResult struct {
	Group     string
	Resource  string
	Verb      string
	Namespace string
	Allowed   bool
}

type PermissionReport struct {
	Granted []PermissionResult
	Denied  []PermissionResult
	Summary string
}

type Options struct {
	RequeueAfter           time.Duration
	MaxRequeue             time.Duration
	BackoffFactor          float64
	ManagedRoleBindingName string
	DirectReader           client.Reader
}

func defaultOptions() Options {
	return Options{
		RequeueAfter:  DefaultRequeueAfter,
		MaxRequeue:    DefaultMaxRequeue,
		BackoffFactor: DefaultBackoffFactor,
	}
}

type Option func(*Options)

func WithRequeueAfter(d time.Duration) Option {
	return func(o *Options) {
		o.RequeueAfter = d
	}
}

func WithMaxRequeue(d time.Duration) Option {
	return func(o *Options) {
		o.MaxRequeue = d
	}
}

func WithBackoffFactor(f float64) Option {
	return func(o *Options) {
		if f < 1.0 {
			f = DefaultBackoffFactor
		}
		o.BackoffFactor = f
	}
}

func WithManagedRoleBindingName(name string) Option {
	return func(o *Options) {
		o.ManagedRoleBindingName = name
	}
}

func WithDirectReader(reader client.Reader) Option {
	return func(o *Options) {
		o.DirectReader = reader
	}
}

// StatusProvider gives the library access to a CR's status conditions.
// CRs that embed metav1.Condition slices in their status should implement this.
type StatusProvider interface {
	GetConditions() []metav1.Condition
	SetConditions([]metav1.Condition)
}
