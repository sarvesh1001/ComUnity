package telemetry

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/segmentio/kafka-go"
	cfg "github.com/ComUnity/auth-service/internal/config"
)

// KafkaToES consumes Kafka topics and forwards events to ESAuditShipper.
// Keep it simple; one reader per topic in the same consumer group.
type KafkaToES struct {
	kcfg cfg.KafkaAuditRootConfig
	es   *ESAuditShipper
	logf func(format string, args ...any)
}

func NewKafkaToES(kcfg cfg.KafkaAuditRootConfig, esCfg cfg.ESAuditConfig) *KafkaToES {
	return &KafkaToES{
		kcfg: kcfg,
		es:   NewESAuditShipper(esCfg),
		logf: log.Printf,
	}
}

func (k *KafkaToES) Start(ctx context.Context) {
	if !k.kcfg.Enabled || !k.es.cfg.Enabled {
		return
	}
	k.es.Start()

	if k.kcfg.TopicDevice != "" {
		go k.consume(ctx, k.kcfg.TopicDevice)
	}
	if k.kcfg.TopicOTP != "" {
		go k.consume(ctx, k.kcfg.TopicOTP)
	}
}

func (k *KafkaToES) Stop(ctx context.Context) {
	// Only need to stop ES shipper; kafka-go readers will exit on ctx cancel from Start caller.
	k.es.Stop(ctx)
}

func (k *KafkaToES) consume(ctx context.Context, topic string) {
	reader := kafka.NewReader(k.readerConfig(topic))
	defer func() { _ = reader.Close() }()

	for {
		m, err := reader.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return // context canceled; shutdown
			}
			k.logf("kafka: read error topic=%s err=%v", topic, err)
			select {
			case <-time.After(500 * time.Millisecond):
			case <-ctx.Done():
				return
			}
			continue
		}

		var ev map[string]any
		if err := json.Unmarshal(m.Value, &ev); err != nil {
			k.logf("kafka: bad json topic=%s offset=%d err=%v", topic, m.Offset, err)
			continue
		}
		// ESAuditShipper adds @timestamp if missing as well, but we do it early for consistency.
		if _, ok := ev["@timestamp"]; !ok {
			ev["@timestamp"] = time.Now().UTC()
		}
		k.es.Publish(ev)
	}
}

func (k *KafkaToES) readerConfig(topic string) kafka.ReaderConfig {
	minBytes := k.kcfg.MinBytes
	if minBytes <= 0 {
		minBytes = 10_000
	}
	maxBytes := k.kcfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 10_000_000
	}
	maxWait := k.kcfg.FlushEvery
	if maxWait <= 0 {
		maxWait = time.Second
	}
	group := k.kcfg.GroupID
	if group == "" {
		group = "audit-sink-es"
	}
	return kafka.ReaderConfig{
		Brokers:  k.kcfg.Brokers,
		GroupID:  group,
		Topic:    topic,
		MinBytes: minBytes,
		MaxBytes: maxBytes,
		MaxWait:  maxWait,
		// If you need TLS/SASL, add Dialer here according to your cluster requirements.
	}
}
