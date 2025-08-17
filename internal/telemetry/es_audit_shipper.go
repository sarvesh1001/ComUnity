package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type ESAuditConfig struct {
	Endpoint   string        `yaml:"endpoint"`
	APIKey     string        `yaml:"api_key"`
	Username   string        `yaml:"username"`
	Password   string        `yaml:"password"`
	IndexPref  string        `yaml:"index_prefix"`
	FlushSize  int           `yaml:"flush_size"`
	FlushEvery time.Duration `yaml:"flush_every"`
	Timeout    time.Duration `yaml:"timeout"`
	Enabled    bool          `yaml:"enabled"`
}

type ESAuditShipper struct {
	cfg   ESAuditConfig
	http  *http.Client
	ch    chan any
	wg    sync.WaitGroup
	stop  chan struct{}
	index func(time.Time) string
}

func NewESAuditShipper(cfg ESAuditConfig) *ESAuditShipper {
	if cfg.FlushSize <= 0 {
		cfg.FlushSize = 500
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 2 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &ESAuditShipper{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout},
		ch:   make(chan any, cfg.FlushSize*4),
		stop: make(chan struct{}),
		index: func(t time.Time) string {
			return fmt.Sprintf("%s-%04d.%02d.%02d", cfg.IndexPref, t.Year(), int(t.Month()), t.Day())
		},
	}
}

func (s *ESAuditShipper) Start() {
	if !s.cfg.Enabled {
		return
	}
	s.wg.Add(1)
	go s.loop()
}

func (s *ESAuditShipper) Stop(ctx context.Context) {
	if !s.cfg.Enabled {
		return
	}
	close(s.stop)
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (s *ESAuditShipper) Publish(ev any) {
	if !s.cfg.Enabled {
		return
	}
	select {
	case s.ch <- ev:
	default:
		// drop on backpressure to protect latency
	}
}

func (s *ESAuditShipper) loop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.cfg.FlushEvery)
	defer ticker.Stop()

	batch := make([]any, 0, s.cfg.FlushSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		_ = s.bulkIndex(batch)
		batch = batch[:0]
	}

	for {
		select {
		case ev := <-s.ch:
			batch = append(batch, ev)
			if len(batch) >= s.cfg.FlushSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.stop:
			flush()
			return
		}
	}
}

func (s *ESAuditShipper) bulkIndex(batch []any) error {
	var buf bytes.Buffer
	now := time.Now().UTC()
	for _, ev := range batch {
		evMap := map[string]any{}
		b, _ := json.Marshal(ev)
		_ = json.Unmarshal(b, &evMap)
		if _, ok := evMap["@timestamp"]; !ok {
			evMap["@timestamp"] = now
		}
		idx := s.index(now)

		meta := map[string]any{"index": map[string]any{"_index": idx}}
		mb, _ := json.Marshal(meta)
		buf.Write(mb)
		buf.WriteByte('\n')

		db, _ := json.Marshal(evMap)
		buf.Write(db)
		buf.WriteByte('\n')
	}

	req, err := http.NewRequest("POST", s.cfg.Endpoint+"/_bulk", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if s.cfg.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+s.cfg.APIKey)
	} else if s.cfg.Username != "" || s.cfg.Password != "" {
		req.SetBasicAuth(s.cfg.Username, s.cfg.Password)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return nil
}
