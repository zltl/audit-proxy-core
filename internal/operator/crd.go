package operator

func CRDObject() map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata": map[string]interface{}{
			"name": FullCRDName,
		},
		"spec": map[string]interface{}{
			"group": Group,
			"scope": "Namespaced",
			"names": map[string]interface{}{
				"plural":   Plural,
				"singular": "sshproxycluster",
				"kind":     Kind,
				"shortNames": []string{
					"spc",
				},
			},
			"versions": []map[string]interface{}{{
				"name":    Version,
				"served":  true,
				"storage": true,
				"schema": map[string]interface{}{
					"openAPIV3Schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"spec": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"image": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"repository": map[string]interface{}{"type": "string"},
											"tag":        map[string]interface{}{"type": "string"},
											"pullPolicy": map[string]interface{}{"type": "string"},
										},
									},
									"controlPlane": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"replicas": map[string]interface{}{"type": "integer"},
											"port":     map[string]interface{}{"type": "integer"},
										},
									},
									"dataPlane": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"replicas": map[string]interface{}{"type": "integer"},
											"port":     map[string]interface{}{"type": "integer"},
										},
									},
									"service": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"type":     map[string]interface{}{"type": "string"},
											"sshPort":  map[string]interface{}{"type": "integer"},
											"httpPort": map[string]interface{}{"type": "integer"},
										},
									},
									"persistence": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"enabled":          map[string]interface{}{"type": "boolean"},
											"size":             map[string]interface{}{"type": "string"},
											"accessMode":       map[string]interface{}{"type": "string"},
											"storageClassName": map[string]interface{}{"type": "string"},
										},
									},
									"config": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"controlPlaneJSON": map[string]interface{}{"type": "string"},
											"dataPlaneINI":     map[string]interface{}{"type": "string"},
										},
										"required": []string{"controlPlaneJSON", "dataPlaneINI"},
									},
									"secrets": map[string]interface{}{
										"type":                 "object",
										"additionalProperties": map[string]interface{}{"type": "string"},
									},
								},
								"required": []string{"config"},
							},
							"status": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"observedGeneration": map[string]interface{}{"type": "integer"},
									"phase":              map[string]interface{}{"type": "string"},
									"message":            map[string]interface{}{"type": "string"},
									"lastReconciledAt":   map[string]interface{}{"type": "string", "format": "date-time"},
									"resourceNames": map[string]interface{}{
										"type":                 "object",
										"additionalProperties": map[string]interface{}{"type": "string"},
									},
								},
							},
						},
					},
				},
				"subresources": map[string]interface{}{
					"status": map[string]interface{}{},
				},
			}},
		},
	}
}
