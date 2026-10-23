// This file is emitted by scripts/generate-public-sdks.ts
// Webhook verification (VTX-601).
package vortex

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const DefaultWebhookTolerance = 300 * time.Second

var VortexEventTypes = []string{
	"billing_state.updated",
	"checkout_session.created",
	"customer.created",
	"customer.updated",
	"dispute.action_required",
	"dispute.adjustment",
	"dispute.lost",
	"dispute.opened",
	"dispute.reconciled",
	"dispute.won",
	"entitlement.granted",
	"entitlement.revoked",
	"invoice.created",
	"invoice.finalized",
	"invoice.marked_uncollectible",
	"invoice.paid",
	"invoice.payment_attempt_needs_resolution",
	"invoice.payment_failed",
	"invoice.payment_requested",
	"invoice.refunded",
	"invoice.voided",
	"merchant_account.action_required",
	"merchant_account.approved",
	"merchant_account.created",
	"merchant_account.rejected",
	"merchant_account.restricted",
	"merchant_account.submitted",
	"merchant_account.updated",
	"merchant_capability.updated",
	"merchant_requirement.refreshed",
	"merchant_requirement.submitted",
	"merchant_requirement_document.upload_link_created",
	"merchant_state.updated",
	"order.created",
	"order.executed",
	"order.failed",
	"order_form.created",
	"order_form.expired",
	"order_form.signature_requested",
	"order_form.signed",
	"order_form.voided",
	"payable_object.updated",
	"payment.authorized",
	"payment.canceled",
	"payment.captured",
	"payment.created",
	"payment.failed",
	"payment_method.created",
	"payment_method.updated",
	"payment_method_setup_session.authorization_locked",
	"payment_receipt.created",
	"payment_receipt.email_bounced",
	"payment_receipt.email_delivered",
	"payment_receipt.email_failed",
	"payment_receipt.email_opened",
	"payment_receipt.email_queued",
	"payment_receipt.generated",
	"payment_request.created",
	"payment_request.email_bounced",
	"payment_request.email_delivered",
	"payment_request.email_failed",
	"payment_request.email_opened",
	"payment_request.email_queued",
	"payment_request.updated",
	"payout.created",
	"payout.failed",
	"payout.reconciled",
	"payout.returned",
	"payout.succeeded",
	"platform_revenue.reversed",
	"platform_revenue.settlement_credit_succeeded",
	"price.created",
	"price.updated",
	"product.created",
	"product.updated",
	"quote.approved",
	"quote.created",
	"quote.voided",
	"refund.created",
	"refund.failed",
	"refund.succeeded",
	"settlement.accruing_started",
	"settlement.awaiting_approval",
	"settlement.closed",
	"settlement.reconciled",
	"subscription.canceled",
	"subscription.created",
	"subscription.renewed",
	"subscription.updated",
	"usage.recorded",
	"usage.threshold_reached",
}

type VortexWebhookEvent struct {
	ID        string                 `json:"id,omitempty"`
	Type      string                 `json:"type"`
	Payload   any                    `json:"data"`
	Raw       map[string]any         `json:"-"`
	Timestamp int64                  `json:"-"`
}

type VerifyWebhookOptions struct {
	Tolerance time.Duration
	Now       time.Time
}

func GenerateVortexWebhookTestHeader(payload []byte, secret string, timestampMs int64) string {
	if timestampMs <= 0 {
		timestampMs = time.Now().UnixMilli()
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestampMs, 10)))
	mac.Write([]byte("."))
	mac.Write(payload)
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("t=%d,v1=%s", timestampMs, sig)
}

func VerifyVortexWebhook(payload []byte, signatureHeader string, secret string, opts *VerifyWebhookOptions) (*VortexWebhookEvent, error) {
	if secret == "" {
		return nil, errors.New("vortex webhook: secret must be non-empty")
	}
	if strings.TrimSpace(signatureHeader) == "" {
		return nil, errors.New("vortex webhook: missing Vortex-Signature header")
	}
	var timestampMs int64
	var v1Sigs [][]byte
	for _, part := range strings.Split(signatureHeader, ",") {
		trimmed := strings.TrimSpace(part)
		eq := strings.IndexByte(trimmed, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:eq])
		val := strings.TrimSpace(trimmed[eq+1:])
		if key == "t" {
			if parsed, err := strconv.ParseInt(val, 10, 64); err == nil && parsed > 0 {
				timestampMs = parsed
			}
		} else if key == "v1" && val != "" {
			if decoded, err := hex.DecodeString(val); err == nil {
				v1Sigs = append(v1Sigs, decoded)
			}
		}
	}
	if timestampMs <= 0 || len(v1Sigs) == 0 {
		return nil, errors.New("vortex webhook: malformed Vortex-Signature header")
	}
	tolerance := DefaultWebhookTolerance
	nowMs := time.Now().UnixMilli()
	if opts != nil {
		if opts.Tolerance > 0 {
			tolerance = opts.Tolerance
		}
		if !opts.Now.IsZero() {
			nowMs = opts.Now.UnixMilli()
		}
	}
	diffMs := nowMs - timestampMs
	if diffMs < 0 {
		diffMs = -diffMs
	}
	if diffMs > tolerance.Milliseconds() {
		return nil, errors.New("vortex webhook: timestamp out of tolerance")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestampMs, 10)))
	mac.Write([]byte("."))
	mac.Write(payload)
	expected := mac.Sum(nil)
	matched := false
	for _, cand := range v1Sigs {
		if subtle.ConstantTimeCompare(expected, cand) == 1 {
			matched = true
			break
		}
	}
	if !matched {
		return nil, errors.New("vortex webhook: signature mismatch")
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("vortex webhook: invalid json: %w", err)
	}
	evtType, _ := raw["type"].(string)
	if evtType == "" {
		evtType = "unknown"
	}
	evtID, _ := raw["id"].(string)
	data, hasData := raw["data"]
	if !hasData {
		data = raw
	}
	return &VortexWebhookEvent{
		ID:        evtID,
		Type:      evtType,
		Payload:   data,
		Raw:       raw,
		Timestamp: timestampMs,
	}, nil
}
