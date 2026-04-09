package operator

import (
	"fmt"
	"sort"
	"strings"
)

type RenderedResources struct {
	Objects       []map[string]interface{}
	ResourceNames map[string]string
}

func RenderResources(cluster SSHProxyCluster) (RenderedResources, error) {
	cluster.Normalize(cluster.Namespace())
	if err := cluster.Validate(); err != nil {
		return RenderedResources{}, err
	}

	labels := clusterLabels(cluster)
	ownerRef := map[string]interface{}{
		"apiVersion":         cluster.APIVersion,
		"kind":               cluster.Kind,
		"name":               cluster.Metadata.Name,
		"uid":                cluster.Metadata.UID,
		"controller":         true,
		"blockOwnerDeletion": true,
	}

	resourceNames := map[string]string{
		"serviceAccount":         cluster.Metadata.Name + "-sa",
		"configMap":              cluster.Metadata.Name + "-config",
		"secret":                 cluster.Metadata.Name + "-secret",
		"controlPlaneService":    cluster.Metadata.Name + "-control-plane",
		"dataPlaneService":       cluster.Metadata.Name + "-data-plane",
		"controlPlaneDeployment": cluster.Metadata.Name + "-control-plane",
		"dataPlaneDeployment":    cluster.Metadata.Name + "-data-plane",
		"persistentVolumeClaim":  cluster.Metadata.Name + "-data",
	}

	objects := []map[string]interface{}{
		serviceAccountObject(cluster, resourceNames["serviceAccount"], labels, ownerRef),
		configMapObject(cluster, resourceNames["configMap"], labels, ownerRef),
	}
	if len(cluster.Spec.Secrets) > 0 {
		objects = append(objects, secretObject(cluster, resourceNames["secret"], labels, ownerRef))
	}
	if cluster.Spec.Persistence.Enabled {
		objects = append(objects, pvcObject(cluster, resourceNames["persistentVolumeClaim"], labels, ownerRef))
	}
	objects = append(objects,
		controlPlaneServiceObject(cluster, resourceNames["controlPlaneService"], labels, ownerRef),
		dataPlaneServiceObject(cluster, resourceNames["dataPlaneService"], labels, ownerRef),
		controlPlaneDeploymentObject(cluster, resourceNames, labels, ownerRef),
		dataPlaneDeploymentObject(cluster, resourceNames, labels, ownerRef),
	)
	return RenderedResources{Objects: objects, ResourceNames: resourceNames}, nil
}

func clusterLabels(cluster SSHProxyCluster) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "ssh-proxy-core",
		"app.kubernetes.io/managed-by": "ssh-proxy-operator",
		"app.kubernetes.io/instance":   cluster.Metadata.Name,
	}
}

func objectMeta(name, namespace string, labels map[string]string, ownerRef map[string]interface{}) map[string]interface{} {
	meta := map[string]interface{}{
		"name":      name,
		"namespace": namespace,
		"labels":    labels,
	}
	if ownerRef["uid"] != "" {
		meta["ownerReferences"] = []map[string]interface{}{ownerRef}
	}
	return meta
}

func serviceAccountObject(cluster SSHProxyCluster, name string, labels map[string]string, ownerRef map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ServiceAccount",
		"metadata":   objectMeta(name, cluster.Namespace(), labels, ownerRef),
	}
}

func configMapObject(cluster SSHProxyCluster, name string, labels map[string]string, ownerRef map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata":   objectMeta(name, cluster.Namespace(), labels, ownerRef),
		"data": map[string]interface{}{
			"control-plane.json": cluster.Spec.Config.ControlPlaneJSON,
			"config.ini":         cluster.Spec.Config.DataPlaneINI,
		},
	}
}

func secretObject(cluster SSHProxyCluster, name string, labels map[string]string, ownerRef map[string]interface{}) map[string]interface{} {
	stringData := map[string]interface{}{}
	for key, value := range cluster.Spec.Secrets {
		stringData[key] = value
	}
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   objectMeta(name, cluster.Namespace(), labels, ownerRef),
		"type":       "Opaque",
		"stringData": stringData,
	}
}

func pvcObject(cluster SSHProxyCluster, name string, labels map[string]string, ownerRef map[string]interface{}) map[string]interface{} {
	spec := map[string]interface{}{
		"accessModes": []string{cluster.Spec.Persistence.AccessMode},
		"resources": map[string]interface{}{
			"requests": map[string]interface{}{
				"storage": cluster.Spec.Persistence.Size,
			},
		},
	}
	if cluster.Spec.Persistence.StorageClassName != "" {
		spec["storageClassName"] = cluster.Spec.Persistence.StorageClassName
	}
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "PersistentVolumeClaim",
		"metadata":   objectMeta(name, cluster.Namespace(), labels, ownerRef),
		"spec":       spec,
	}
}

func controlPlaneServiceObject(cluster SSHProxyCluster, name string, labels map[string]string, ownerRef map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   objectMeta(name, cluster.Namespace(), labels, ownerRef),
		"spec": map[string]interface{}{
			"type": "ClusterIP",
			"selector": map[string]interface{}{
				"app.kubernetes.io/instance":  cluster.Metadata.Name,
				"app.kubernetes.io/component": "control-plane",
			},
			"ports": []map[string]interface{}{{
				"name":       "https",
				"port":       cluster.Spec.Service.HTTPPort,
				"targetPort": cluster.Spec.ControlPlane.Port,
				"protocol":   "TCP",
			}},
		},
	}
}

func dataPlaneServiceObject(cluster SSHProxyCluster, name string, labels map[string]string, ownerRef map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   objectMeta(name, cluster.Namespace(), labels, ownerRef),
		"spec": map[string]interface{}{
			"type": cluster.Spec.Service.Type,
			"selector": map[string]interface{}{
				"app.kubernetes.io/instance":  cluster.Metadata.Name,
				"app.kubernetes.io/component": "data-plane",
			},
			"ports": []map[string]interface{}{{
				"name":       "ssh",
				"port":       cluster.Spec.Service.SSHPort,
				"targetPort": cluster.Spec.DataPlane.Port,
				"protocol":   "TCP",
			}},
		},
	}
}

func controlPlaneDeploymentObject(cluster SSHProxyCluster, names map[string]string, labels map[string]string, ownerRef map[string]interface{}) map[string]interface{} {
	container := map[string]interface{}{
		"name":            "control-plane",
		"image":           controlPlaneImage(cluster),
		"imagePullPolicy": cluster.Spec.Image.PullPolicy,
		"args": []string{
			"-config", "/etc/ssh-proxy/control-plane.json",
			"-addr", fmt.Sprintf(":%d", cluster.Spec.ControlPlane.Port),
		},
		"ports": []map[string]interface{}{{
			"name":          "https",
			"containerPort": cluster.Spec.ControlPlane.Port,
			"protocol":      "TCP",
		}},
		"env":          controlPlaneSecretEnv(cluster),
		"volumeMounts": deploymentVolumeMounts(cluster, names),
	}
	return deploymentObject(cluster, names["controlPlaneDeployment"], "control-plane", cluster.Spec.ControlPlane.Replicas, container, labels, ownerRef)
}

func dataPlaneDeploymentObject(cluster SSHProxyCluster, names map[string]string, labels map[string]string, ownerRef map[string]interface{}) map[string]interface{} {
	container := map[string]interface{}{
		"name":            "data-plane",
		"image":           dataPlaneImage(cluster),
		"imagePullPolicy": cluster.Spec.Image.PullPolicy,
		"args": []string{
			"-c", "/etc/ssh-proxy/config.ini",
		},
		"ports": []map[string]interface{}{
			{
				"name":          "ssh",
				"containerPort": cluster.Spec.DataPlane.Port,
				"protocol":      "TCP",
			},
			{
				"name":          "metrics",
				"containerPort": 9090,
				"protocol":      "TCP",
			},
		},
		"volumeMounts": deploymentVolumeMounts(cluster, names),
	}
	return deploymentObject(cluster, names["dataPlaneDeployment"], "data-plane", cluster.Spec.DataPlane.Replicas, container, labels, ownerRef)
}

func deploymentObject(cluster SSHProxyCluster, name, component string, replicas int32, container map[string]interface{}, labels map[string]string, ownerRef map[string]interface{}) map[string]interface{} {
	podLabels := map[string]interface{}{
		"app.kubernetes.io/instance":  cluster.Metadata.Name,
		"app.kubernetes.io/component": component,
		"app.kubernetes.io/name":      "ssh-proxy-core",
	}
	return map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   objectMeta(name, cluster.Namespace(), labels, ownerRef),
		"spec": map[string]interface{}{
			"replicas": replicas,
			"selector": map[string]interface{}{
				"matchLabels": podLabels,
			},
			"template": map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": podLabels,
				},
				"spec": map[string]interface{}{
					"serviceAccountName": cluster.Metadata.Name + "-sa",
					"containers":         []map[string]interface{}{container},
					"volumes":            deploymentVolumes(cluster),
				},
			},
		},
	}
}

func deploymentVolumes(cluster SSHProxyCluster) []map[string]interface{} {
	volumes := []map[string]interface{}{
		{
			"name": "config",
			"configMap": map[string]interface{}{
				"name": cluster.Metadata.Name + "-config",
			},
		},
	}
	if len(cluster.Spec.Secrets) > 0 {
		volumes = append(volumes, map[string]interface{}{
			"name": "secrets",
			"secret": map[string]interface{}{
				"secretName": cluster.Metadata.Name + "-secret",
			},
		})
	}
	if cluster.Spec.Persistence.Enabled {
		volumes = append(volumes, map[string]interface{}{
			"name": "data",
			"persistentVolumeClaim": map[string]interface{}{
				"claimName": cluster.Metadata.Name + "-data",
			},
		})
	} else {
		volumes = append(volumes, map[string]interface{}{
			"name":     "data",
			"emptyDir": map[string]interface{}{},
		})
	}
	return volumes
}

func deploymentVolumeMounts(cluster SSHProxyCluster, names map[string]string) []map[string]interface{} {
	mounts := []map[string]interface{}{
		{
			"name":      "config",
			"mountPath": "/etc/ssh-proxy",
			"readOnly":  true,
		},
		{
			"name":      "data",
			"mountPath": "/data",
		},
	}
	if len(cluster.Spec.Secrets) > 0 {
		mounts = append(mounts, map[string]interface{}{
			"name":      "secrets",
			"mountPath": "/etc/ssh-proxy/secrets",
			"readOnly":  true,
		})
	}
	return mounts
}

func controlPlaneImage(cluster SSHProxyCluster) string {
	tag := cluster.Spec.Image.Tag
	suffix := "-control-plane"
	if tag == "" {
		return cluster.Spec.Image.Repository + suffix
	}
	return cluster.Spec.Image.Repository + suffix + ":" + tag
}

func dataPlaneImage(cluster SSHProxyCluster) string {
	if cluster.Spec.Image.Tag == "" {
		return cluster.Spec.Image.Repository
	}
	return cluster.Spec.Image.Repository + ":" + cluster.Spec.Image.Tag
}

func controlPlaneSecretEnv(cluster SSHProxyCluster) []map[string]interface{} {
	if len(cluster.Spec.Secrets) == 0 {
		return nil
	}
	keys := make([]string, 0, len(cluster.Spec.Secrets))
	for key := range cluster.Spec.Secrets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]map[string]interface{}, 0, len(cluster.Spec.Secrets))
	for _, key := range keys {
		env = append(env, map[string]interface{}{
			"name": "SSH_PROXY_CP_" + secretKeyToEnvSuffix(key),
			"valueFrom": map[string]interface{}{
				"secretKeyRef": map[string]interface{}{
					"name": cluster.Metadata.Name + "-secret",
					"key":  key,
				},
			},
		})
	}
	return env
}

func secretKeyToEnvSuffix(key string) string {
	key = strings.TrimSpace(key)
	key = strings.ReplaceAll(key, "-", "_")
	key = strings.ReplaceAll(key, ".", "_")
	return strings.ToUpper(key)
}
