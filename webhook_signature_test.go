// This file is emitted by scripts/generate-public-sdks.ts
package vortex

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

type webhookVectorSuite struct {
	Positive []struct {
		ID        string `json:"id"`
		Secret    string `json:"secret"`
		Timestamp int64  `json:"timestamp"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
		Header    string `json:"header"`
	} `json:"positive"`
	Negative []struct {
		ID      string  `json:"id"`
		Secret  string  `json:"secret"`
		Header  *string `json:"header"`
		Payload string  `json:"payload"`
		Now     int64   `json:"now"`
	} `json:"negative"`
}

func TestVortexWebhookCanonicalVectors(t *testing.T) {
	data, err := os.ReadFile("webhook_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var suite webhookVectorSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	for _, vec := range suite.Positive {
		header := GenerateVortexWebhookTestHeader([]byte(vec.Payload), vec.Secret, vec.Timestamp)
		want := fmt.Sprintf("t=%d,v1=%s", vec.Timestamp, vec.Signature)
		if header != want {
			t.Fatalf("%s: got %s, want %s", vec.ID, header, want)
		}
		evt, err := VerifyVortexWebhook([]byte(vec.Payload), vec.Header, vec.Secret, &VerifyWebhookOptions{
			Now: time.UnixMilli(vec.Timestamp),
		})
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", vec.ID, err)
		}
		if evt.Timestamp != vec.Timestamp {
			t.Fatalf("%s: timestamp %d != %d", vec.ID, evt.Timestamp, vec.Timestamp)
		}
	}
	for _, vec := range suite.Negative {
		hdr := ""
		if vec.Header != nil {
			hdr = *vec.Header
		}
		_, err := VerifyVortexWebhook([]byte(vec.Payload), hdr, vec.Secret, &VerifyWebhookOptions{
			Now: time.UnixMilli(vec.Now),
		})
		if err == nil {
			t.Fatalf("%s: expected error, got nil", vec.ID)
		}
	}
}
