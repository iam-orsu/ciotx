package llm

import (
	"math"
	"testing"
)

func TestCostUSD_Discovery(t *testing.T) {
	u := Usage{
		PromptTokens:     1_000_000,
		CompletionTokens: 500_000,
		CacheHitTokens:   200_000,
		CacheMissTokens:  800_000,
	}
	got := CostUSD(u, modelDiscovery)
	// (800k * 0.55 + 200k * 0.14) / 1M + 500k * 2.19 / 1M
	// = (440 + 28) / 1000 + 1095 / 1000
	// = 0.468 + 1.095 = 1.563
	want := (800_000*priceReasonerCacheMiss+200_000*priceReasonerCacheHit)/1_000_000 +
		500_000*priceReasonerOutput/1_000_000
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("CostUSD(discovery) = %f, want %f", got, want)
	}
}

func TestCostUSD_Audit(t *testing.T) {
	u := Usage{
		PromptTokens:     500_000,
		CompletionTokens: 100_000,
		CacheHitTokens:   100_000,
		CacheMissTokens:  400_000,
	}
	got := CostUSD(u, modelAudit)
	want := (400_000*priceChatCacheMiss+100_000*priceChatCacheHit)/1_000_000 +
		100_000*priceChatOutput/1_000_000
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("CostUSD(audit) = %f, want %f", got, want)
	}
}

func TestCostUSD_ZeroUsage(t *testing.T) {
	u := Usage{}
	if got := CostUSD(u, modelDiscovery); got != 0 {
		t.Errorf("CostUSD(zero usage) = %f, want 0", got)
	}
	if got := CostUSD(u, modelAudit); got != 0 {
		t.Errorf("CostUSD(zero usage, audit) = %f, want 0", got)
	}
}
