package openapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Document is a minimal OpenAPI 3.0 document tailored to the control-plane API.
type Document struct {
	OpenAPI    string     `json:"openapi"`
	Info       Info       `json:"info"`
	Servers    []Server   `json:"servers,omitempty"`
	Tags       []Tag      `json:"tags,omitempty"`
	Paths      Paths      `json:"paths"`
	Components Components `json:"components,omitempty"`
}

// Info describes the API title and version metadata.
type Info struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Version     string `json:"version"`
}

// Server is an OpenAPI server entry.
type Server struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

// Tag groups operations in the rendered UI.
type Tag struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Components holds reusable OpenAPI components.
type Components struct {
	Schemas         map[string]*Schema         `json:"schemas,omitempty"`
	SecuritySchemes map[string]*SecurityScheme `json:"securitySchemes,omitempty"`
}

// SecurityScheme describes cookie-based session auth.
type SecurityScheme struct {
	Type string `json:"type"`
	In   string `json:"in,omitempty"`
	Name string `json:"name,omitempty"`
}

// Paths maps path templates to path items.
type Paths map[string]*PathItem

// PathItem groups operations on the same path.
type PathItem struct {
	Get    *Operation `json:"get,omitempty"`
	Post   *Operation `json:"post,omitempty"`
	Put    *Operation `json:"put,omitempty"`
	Delete *Operation `json:"delete,omitempty"`
}

// Operation is a single documented endpoint.
type Operation struct {
	Tags        []string              `json:"tags,omitempty"`
	Summary     string                `json:"summary,omitempty"`
	Description string                `json:"description,omitempty"`
	OperationID string                `json:"operationId,omitempty"`
	Parameters  []Parameter           `json:"parameters,omitempty"`
	RequestBody *RequestBody          `json:"requestBody,omitempty"`
	Responses   map[string]Response   `json:"responses"`
	Security    []map[string][]string `json:"security,omitempty"`
}

// Parameter describes path, query, or header inputs.
type Parameter struct {
	Name        string  `json:"name"`
	In          string  `json:"in"`
	Description string  `json:"description,omitempty"`
	Required    bool    `json:"required"`
	Schema      *Schema `json:"schema,omitempty"`
}

// RequestBody describes a JSON request body.
type RequestBody struct {
	Description string               `json:"description,omitempty"`
	Required    bool                 `json:"required,omitempty"`
	Content     map[string]MediaType `json:"content,omitempty"`
}

// Response describes a response payload.
type Response struct {
	Description string               `json:"description"`
	Content     map[string]MediaType `json:"content,omitempty"`
}

// MediaType defines the schema for a content type.
type MediaType struct {
	Schema  *Schema     `json:"schema,omitempty"`
	Example interface{} `json:"example,omitempty"`
}

// Schema is a minimal JSON Schema/OpenAPI schema subset.
type Schema struct {
	Ref         string             `json:"$ref,omitempty"`
	Type        string             `json:"type,omitempty"`
	Format      string             `json:"format,omitempty"`
	Description string             `json:"description,omitempty"`
	Properties  map[string]*Schema `json:"properties,omitempty"`
	Items       *Schema            `json:"items,omitempty"`
	Required    []string           `json:"required,omitempty"`
	Enum        []string           `json:"enum,omitempty"`
}

// Route documents one REST endpoint.
type Route struct {
	Method              string
	Path                string
	Tag                 string
	Summary             string
	Description         string
	OperationID         string
	RequiresAuth        bool
	RequiresCSRF        bool
	QueryParameters     []Parameter
	RequestBodyDesc     string
	RequestBodySchema   *Schema
	RequestBodyExample  interface{}
	SuccessStatus       int
	SuccessDescription  string
	SuccessContentType  string
	SuccessSchema       *Schema
	SuccessExample      interface{}
	AdditionalResponses map[string]Response
}

// Build returns the generated OpenAPI document for the currently served REST API.
func Build() Document {
	routes := Routes()
	paths := make(Paths, len(routes))
	for _, route := range routes {
		pathItem := paths[route.Path]
		if pathItem == nil {
			pathItem = &PathItem{}
			paths[route.Path] = pathItem
		}
		op := operationFromRoute(route)
		switch strings.ToUpper(route.Method) {
		case http.MethodGet:
			pathItem.Get = op
		case http.MethodPost:
			pathItem.Post = op
		case http.MethodPut:
			pathItem.Put = op
		case http.MethodDelete:
			pathItem.Delete = op
		}
	}

	return Document{
		OpenAPI: "3.0.3",
		Info: Info{
			Title:       "SSH Proxy Core Control Plane API",
			Description: "Generated OpenAPI description for the currently exposed REST management API. Authenticate in the web UI first; Swagger UI reuses the browser session cookie and injects the CSRF token automatically for state-changing requests.",
			Version:     "v2",
		},
		Servers: []Server{{
			URL:         "/",
			Description: "Current control-plane origin",
		}},
		Tags: []Tag{
			{Name: "Auth", Description: "Authentication and session-related endpoints"},
			{Name: "Dashboard", Description: "Dashboard and overview endpoints"},
			{Name: "Sessions", Description: "Active SSH session inspection and control"},
			{Name: "Users", Description: "User and MFA administration"},
			{Name: "Servers", Description: "Upstream server inventory"},
			{Name: "Audit", Description: "Audit log search, export, and statistics"},
			{Name: "Config", Description: "Control-plane and data-plane configuration management"},
			{Name: "System", Description: "Health, runtime info, and metrics"},
			{Name: "SSH CA", Description: "SSH certificate authority operations"},
			{Name: "Threats", Description: "Threat detection alerts, rules, and runtime ingest"},
			{Name: "Discovery", Description: "Asset discovery and registration"},
			{Name: "Command Control", Description: "Command policy and approval workflows"},
			{Name: "Collaboration", Description: "Shared session collaboration APIs"},
		},
		Paths: paths,
		Components: Components{
			Schemas: map[string]*Schema{
				"HealthStatus": healthStatusSchema(),
				"Session":      sessionSchema(),
				"Server":       serverSchema(),
				"User":         userSchema(),
				"AuditEvent":   auditEventSchema(),
				"ConfigVersionListItem": objectSchema(map[string]*Schema{
					"version":   stringSchema("Version identifier"),
					"size":      integerSchema("Snapshot file size in bytes"),
					"timestamp": dateTimeSchema("Snapshot modification timestamp"),
				}, "version"),
				"ConfigDiff": objectSchema(map[string]*Schema{
					"from_version": stringSchema("Base version identifier"),
					"to_version":   stringSchema("Target version identifier"),
					"changed":      boolSchema("Whether the compared configs differ"),
					"diff":         stringSchema("Unified diff output"),
				}, "from_version", "to_version", "changed", "diff"),
			},
			SecuritySchemes: map[string]*SecurityScheme{
				"cookieAuth": {
					Type: "apiKey",
					In:   "cookie",
					Name: "session",
				},
			},
		},
	}
}

// JSON returns the generated OpenAPI document encoded as formatted JSON.
func JSON() ([]byte, error) {
	doc := Build()
	return json.MarshalIndent(doc, "", "  ")
}

func operationFromRoute(route Route) *Operation {
	parameters := append(pathParameters(route.Path), route.QueryParameters...)
	if route.RequiresCSRF {
		parameters = append(parameters, csrfHeaderParameter())
	}

	op := &Operation{
		Tags:        []string{route.Tag},
		Summary:     route.Summary,
		Description: route.Description,
		OperationID: route.OperationID,
		Parameters:  parameters,
		Responses:   defaultResponses(route),
	}
	if route.RequiresAuth {
		op.Security = []map[string][]string{{"cookieAuth": {}}}
	}
	if route.RequestBodySchema != nil {
		op.RequestBody = &RequestBody{
			Description: route.RequestBodyDesc,
			Required:    true,
			Content: map[string]MediaType{
				"application/json": {
					Schema:  route.RequestBodySchema,
					Example: route.RequestBodyExample,
				},
			},
		}
	}
	return op
}

func defaultResponses(route Route) map[string]Response {
	responses := map[string]Response{}
	successCode := route.SuccessStatus
	if successCode == 0 {
		successCode = http.StatusOK
	}
	contentType := route.SuccessContentType
	if contentType == "" {
		contentType = "application/json"
	}

	success := Response{Description: route.SuccessDescription}
	if success.Description == "" {
		success.Description = http.StatusText(successCode)
	}
	if route.SuccessSchema != nil {
		success.Content = map[string]MediaType{
			contentType: {
				Schema:  route.SuccessSchema,
				Example: route.SuccessExample,
			},
		}
	}
	responses[strconv.Itoa(successCode)] = success

	if route.RequiresAuth {
		responses["401"] = jsonErrorResponse("Unauthenticated request")
	}
	if route.RequiresCSRF {
		responses["403"] = jsonErrorResponse("Missing or invalid CSRF token")
	}
	for code, response := range route.AdditionalResponses {
		responses[code] = response
	}
	return responses
}

func pathParameters(path string) []Parameter {
	var params []Parameter
	for {
		start := strings.Index(path, "{")
		if start == -1 {
			break
		}
		rest := path[start+1:]
		end := strings.Index(rest, "}")
		if end == -1 {
			break
		}
		name := rest[:end]
		params = append(params, Parameter{
			Name:        name,
			In:          "path",
			Required:    true,
			Description: strings.ReplaceAll(name, "_", " ") + " path parameter",
			Schema:      stringSchema(""),
		})
		path = rest[end+1:]
	}

	sort.Slice(params, func(i, j int) bool {
		return params[i].Name < params[j].Name
	})
	return params
}

func jsonErrorResponse(description string) Response {
	return Response{
		Description: description,
		Content: map[string]MediaType{
			"application/json": {
				Schema: envelopeSchema(nil, false),
			},
		},
	}
}

func csrfHeaderParameter() Parameter {
	return Parameter{
		Name:        "X-CSRF-Token",
		In:          "header",
		Required:    true,
		Description: "CSRF token copied from the csrf_token cookie for POST/PUT/DELETE requests",
		Schema:      stringSchema("CSRF protection token"),
	}
}

func listParameters(extra ...Parameter) []Parameter {
	params := []Parameter{
		{
			Name:        "page",
			In:          "query",
			Description: "Page number (1-based)",
			Required:    false,
			Schema:      integerSchema("Page number"),
		},
		{
			Name:        "per_page",
			In:          "query",
			Description: "Page size (default 50, max 200)",
			Required:    false,
			Schema:      integerSchema("Page size"),
		},
	}
	return append(params, extra...)
}

func refSchema(name string) *Schema {
	return &Schema{Ref: "#/components/schemas/" + name}
}

func stringSchema(description string) *Schema {
	return &Schema{Type: "string", Description: description}
}

func boolSchema(description string) *Schema {
	return &Schema{Type: "boolean", Description: description}
}

func integerSchema(description string) *Schema {
	return &Schema{Type: "integer", Description: description}
}

func dateTimeSchema(description string) *Schema {
	return &Schema{Type: "string", Format: "date-time", Description: description}
}

func objectSchema(props map[string]*Schema, required ...string) *Schema {
	return &Schema{
		Type:       "object",
		Properties: props,
		Required:   required,
	}
}

func arraySchema(item *Schema) *Schema {
	return &Schema{
		Type:  "array",
		Items: item,
	}
}

func envelopeSchema(data *Schema, paginated bool) *Schema {
	props := map[string]*Schema{
		"success": boolSchema("Whether the request succeeded"),
		"error":   stringSchema("Error message when success=false"),
	}
	required := []string{"success"}
	if data != nil {
		props["data"] = data
	}
	if paginated {
		props["total"] = integerSchema("Total matching items")
		props["page"] = integerSchema("Current page")
		props["per_page"] = integerSchema("Requested page size")
	}
	return objectSchema(props, required...)
}

func messageEnvelope(message string) *Schema {
	return envelopeSchema(objectSchema(map[string]*Schema{
		"message": stringSchema(message),
	}, "message"), false)
}

func healthStatusSchema() *Schema {
	return objectSchema(map[string]*Schema{
		"status":  stringSchema("Health state"),
		"version": stringSchema("Data-plane version"),
		"uptime":  stringSchema("Human-readable uptime"),
	}, "status")
}

func sessionSchema() *Schema {
	return objectSchema(map[string]*Schema{
		"id":                 stringSchema("Session identifier"),
		"username":           stringSchema("SSH username"),
		"source_ip":          stringSchema("Client source IP"),
		"client_version":     stringSchema("Best-effort SSH client version derived from the identification banner"),
		"client_os":          stringSchema("Best-effort client operating system inferred from the SSH identification banner"),
		"device_fingerprint": stringSchema("Stable fingerprint derived from the SSH client banner metadata"),
		"instance_id":        stringSchema("Owning proxy instance identifier"),
		"target_host":        stringSchema("Target host"),
		"target_port":        integerSchema("Target SSH port"),
		"start_time":         dateTimeSchema("Session start time"),
		"duration":           stringSchema("Human-readable duration"),
		"bytes_in":           integerSchema("Bytes received from client"),
		"bytes_out":          integerSchema("Bytes sent to client"),
		"status":             stringSchema("Session status"),
		"recording_file":     stringSchema("Recording file path"),
	}, "id", "username", "source_ip", "target_host", "target_port", "start_time", "duration", "status")
}

func serverSchema() *Schema {
	return objectSchema(map[string]*Schema{
		"id":           stringSchema("Server identifier"),
		"host":         stringSchema("Server hostname or IP"),
		"port":         integerSchema("SSH port"),
		"name":         stringSchema("Display name"),
		"group":        stringSchema("Grouping label"),
		"status":       stringSchema("Server status"),
		"healthy":      boolSchema("Whether health checks currently pass"),
		"maintenance":  boolSchema("Maintenance mode flag"),
		"weight":       integerSchema("Load-balancing weight"),
		"max_sessions": integerSchema("Maximum concurrent sessions"),
		"sessions":     integerSchema("Current active sessions"),
		"checked_at":   dateTimeSchema("Last health-check timestamp"),
	}, "id", "host", "port", "status", "healthy")
}

func userSchema() *Schema {
	return objectSchema(map[string]*Schema{
		"username":     stringSchema("Login name"),
		"display_name": stringSchema("Display name"),
		"email":        stringSchema("Email address"),
		"role":         stringSchema("Assigned role"),
		"enabled":      boolSchema("Whether the user is enabled"),
		"mfa_enabled":  boolSchema("Whether MFA is enabled"),
		"created_at":   dateTimeSchema("User creation timestamp"),
		"updated_at":   dateTimeSchema("Last update timestamp"),
		"last_login":   dateTimeSchema("Last successful login"),
	}, "username", "role", "enabled", "mfa_enabled")
}

func auditEventSchema() *Schema {
	return objectSchema(map[string]*Schema{
		"id":          stringSchema("Event identifier"),
		"timestamp":   dateTimeSchema("Event timestamp"),
		"event_type":  stringSchema("Audit event type"),
		"username":    stringSchema("Initiating user"),
		"source_ip":   stringSchema("Source IP"),
		"target_host": stringSchema("Target host"),
		"details":     stringSchema("Additional event details"),
		"session_id":  stringSchema("Related session ID"),
	}, "id", "timestamp", "event_type")
}
