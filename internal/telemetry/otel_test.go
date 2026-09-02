package telemetry

import (
	"context"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestSetSessionIDRecordsAttribute(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "op")
	ctx = SetSessionID(ctx, "sess-123")
	span.End()

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans = %d", len(spans))
	}
	found := false
	for _, attr := range spans[0].Attributes {
		if string(attr.Key) == SessionIDKey && attr.Value.AsString() == "sess-123" {
			found = true
		}
	}
	if !found {
		t.Fatalf("session.id attribute missing: %#v", spans[0].Attributes)
	}
	_ = ctx
}
