package operator

import (
	"context"
	"fmt"
	"time"
)

type Client interface {
	EnsureCRD(context.Context) error
	ListClusters(context.Context, string) ([]SSHProxyCluster, error)
	Apply(context.Context, map[string]interface{}) error
	UpdateStatus(context.Context, string, string, SSHProxyClusterStatus) error
}

type Reconciler struct {
	Client    Client
	Namespace string
	Now       func() time.Time
}

func (r *Reconciler) ReconcileAll(ctx context.Context) error {
	if r == nil || r.Client == nil {
		return fmt.Errorf("operator client is required")
	}
	namespace := firstNonEmpty(r.Namespace, DefaultNamespace)
	if err := r.Client.EnsureCRD(ctx); err != nil {
		return err
	}
	clusters, err := r.Client.ListClusters(ctx, namespace)
	if err != nil {
		return err
	}
	for _, cluster := range clusters {
		if err := r.ReconcileCluster(ctx, cluster); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) ReconcileCluster(ctx context.Context, cluster SSHProxyCluster) error {
	if r == nil || r.Client == nil {
		return fmt.Errorf("operator client is required")
	}
	cluster.Normalize(firstNonEmpty(cluster.Metadata.Namespace, r.Namespace, DefaultNamespace))
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	if err := cluster.Validate(); err != nil {
		status := SSHProxyClusterStatus{
			ObservedGeneration: cluster.Metadata.Generation,
			Phase:              "Error",
			Message:            err.Error(),
			LastReconciledAt:   now,
		}
		_ = r.Client.UpdateStatus(ctx, cluster.Namespace(), cluster.Metadata.Name, status)
		return err
	}
	rendered, err := RenderResources(cluster)
	if err != nil {
		status := SSHProxyClusterStatus{
			ObservedGeneration: cluster.Metadata.Generation,
			Phase:              "Error",
			Message:            err.Error(),
			LastReconciledAt:   now,
		}
		_ = r.Client.UpdateStatus(ctx, cluster.Namespace(), cluster.Metadata.Name, status)
		return err
	}
	for _, obj := range rendered.Objects {
		if err := r.Client.Apply(ctx, obj); err != nil {
			status := SSHProxyClusterStatus{
				ObservedGeneration: cluster.Metadata.Generation,
				Phase:              "Error",
				Message:            err.Error(),
				ResourceNames:      rendered.ResourceNames,
				LastReconciledAt:   now,
			}
			_ = r.Client.UpdateStatus(ctx, cluster.Namespace(), cluster.Metadata.Name, status)
			return err
		}
	}
	status := SSHProxyClusterStatus{
		ObservedGeneration: cluster.Metadata.Generation,
		Phase:              "Ready",
		Message:            "Reconciled successfully",
		ResourceNames:      rendered.ResourceNames,
		LastReconciledAt:   now,
	}
	return r.Client.UpdateStatus(ctx, cluster.Namespace(), cluster.Metadata.Name, status)
}
