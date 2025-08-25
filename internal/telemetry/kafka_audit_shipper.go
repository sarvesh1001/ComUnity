package telemetry

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"time"

	"github.com/segmentio/kafka-go"
	cfg "github.com/ComUnity/auth-service/internal/config"
)

type KafkaAuditShipper struct {
	cfg     cfg.KafkaAuditRootConfig
	wDevice *kafka.Writer
	wOTP    *kafka.Writer
	ch      chan any
	stop    chan struct{}
}

func NewKafkaAuditShipper(cfgIn cfg.KafkaAuditRootConfig) (*KafkaAuditShipper, error) {
	cfg := cfgIn
	if !cfg.Enabled {
		return &KafkaAuditShipper{cfg: cfg, ch: make(chan any), stop: make(chan struct{})}, nil
	}
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("kafka: no brokers configured")
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 2 * time.Second
	}
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = cfg.BatchSize * 4
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 5 * time.Second
	}

	tr := &kafka.Transport{
		DialTimeout: cfg.DialTimeout,
	}
	if cfg.TLS {
		tr.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	// NOTE: SASL examples omitted for brevity; add if your cluster requires it.

	var wDevice, wOTP *kafka.Writer
	if cfg.TopicDevice != "" {
		wDevice = &kafka.Writer{
			Addr:                   kafka.TCP(cfg.Brokers...),
			Topic:                  cfg.TopicDevice,
			Balancer:               &kafka.Hash{},
			RequiredAcks:           kafka.RequireAll,
			Transport:              tr,
			AllowAutoTopicCreation: false,
			Async:                  true,
			BatchTimeout:           cfg.FlushEvery,
			BatchSize:              cfg.BatchSize,
			WriteTimeout:           cfg.WriteTimeout,
		}
	}
	if cfg.TopicOTP != "" {
		wOTP = &kafka.Writer{
			Addr:                   kafka.TCP(cfg.Brokers...),
			Topic:                  cfg.TopicOTP,
			Balancer:               &kafka.Hash{},
			RequiredAcks:           kafka.RequireAll,
			Transport:              tr,
			AllowAutoTopicCreation: false,
			Async:                  true,
			BatchTimeout:           cfg.FlushEvery,
			BatchSize:              cfg.BatchSize,
			WriteTimeout:           cfg.WriteTimeout,
		}
	}

	return &KafkaAuditShipper{
		cfg:     cfg,
		wDevice: wDevice,
		wOTP:    wOTP,
		ch:      make(chan any, cfg.QueueCapacity),
		stop:    make(chan struct{}),
	}, nil
}

func (s *KafkaAuditShipper) Start() {
	if !s.cfg.Enabled {
		return
	}
	go s.loop()
}

func (s *KafkaAuditShipper) Stop(ctx context.Context) {
	if !s.cfg.Enabled {
		return
	}
	close(s.stop)
	// drain briefly
	drain := time.After(500 * time.Millisecond)
	for {
		select {
		case ev := <-s.ch:
			_ = s.dispatch(ev)
		case <-drain:
			if s.wDevice != nil {
				_ = s.wDevice.Close()
			}
			if s.wOTP != nil {
				_ = s.wOTP.Close()
			}
			return
		}
	}
}

func (s *KafkaAuditShipper) Publish(ev any) {
	if !s.cfg.Enabled {
		return
	}
	select {
	case s.ch <- ev:
	default:
		// drop on backpressure
	}
}

func (s *KafkaAuditShipper) loop() {
	for {
		select {
		case ev := <-s.ch:
			_ = s.dispatch(ev)
		case <-s.stop:
			// drain remaining quickly
			for {
				select {
				case ev := <-s.ch:
					_ = s.dispatch(ev)
				default:
					return
				}
			}
		}
	}
}

func (s *KafkaAuditShipper) dispatch(ev any) error {
	now := time.Now().UTC()
	m := map[string]any{}
	b, _ := json.Marshal(ev)
	_ = json.Unmarshal(b, &m)
	if _, ok := m["@timestamp"]; !ok {
		m["@timestamp"] = now
	}
	payload, _ := json.Marshal(m)

	key := func(field string) []byte {
		if v, ok := m[field]; ok && v != nil {
			if str, ok := v.(string); ok && str != "" {
				return []byte(str)
			}
		}
		return nil
	}

	switch ev.(type) {
	case DeviceAuditEvent:
		if s.wDevice == nil {
			return nil
		}
		return s.wDevice.WriteMessages(context.Background(), kafka.Message{
			Key:   key("device_key"),
			Value: payload,
			Time:  now,
		})
	case OTPAuditEvent:
		if s.wOTP == nil {
			return nil
		}
		return s.wOTP.WriteMessages(context.Background(), kafka.Message{
			Key:   key("device_key"),
			Value: payload,
			Time:  now,
		})
	default:
		// route unknown to device topic if configured
		if s.wDevice != nil {
			return s.wDevice.WriteMessages(context.Background(), kafka.Message{
				Key:   key("device_key"),
				Value: payload,
				Time:  now,
			})
		}
	}
	return nil
}
