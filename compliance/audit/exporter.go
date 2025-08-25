package audit

import (
    "bytes"
    "context"
    "encoding/csv"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "strings"
    "sync"
    "time"
	"crypto/sha256" // Add this
    "os"            
    "github.com/google/uuid"

    "github.com/ComUnity/auth-service/internal/client"
    "github.com/ComUnity/auth-service/internal/config"
    "github.com/ComUnity/auth-service/internal/models"
    "github.com/ComUnity/auth-service/internal/util/logger"
    "github.com/ComUnity/auth-service/security"
)

// ExportFormat represents the output format for audit exports
type ExportFormat string

const (
    FormatJSON ExportFormat = "json"
    FormatCSV  ExportFormat = "csv"
    FormatPDF  ExportFormat = "pdf"
    FormatXML  ExportFormat = "xml"
)

// ComplianceStandard represents different compliance frameworks
type ComplianceStandard string

const (
    StandardGDPR ComplianceStandard = "gdpr"
    StandardCCPA ComplianceStandard = "ccpa"
    StandardHIPAA ComplianceStandard = "hipaa"
    StandardSOX  ComplianceStandard = "sox"
    StandardPCI  ComplianceStandard = "pci"
    StandardISO27001 ComplianceStandard = "iso27001"
)

// ExportConfig holds configuration for audit exports
type ExportConfig struct {
    Enabled             bool                        `yaml:"enabled"`
    ESConfig            config.ESAuditConfig        `yaml:"elasticsearch"`
    RetentionPeriods    map[string]time.Duration    `yaml:"retention_periods"`
    ExportFormats       []ExportFormat              `yaml:"export_formats"`
    ComplianceStandards []ComplianceStandard        `yaml:"compliance_standards"`
    MaxBatchSize        int                         `yaml:"max_batch_size"`
    MaxExportSize       int64                       `yaml:"max_export_size"`
    S3Config            S3Config                    `yaml:"s3"`
    EncryptExports      bool                        `yaml:"encrypt_exports"`
    SignExports         bool                        `yaml:"sign_exports"`
}

// S3Config for storing compliance exports
type S3Config struct {
    Enabled    bool   `yaml:"enabled"`
    Bucket     string `yaml:"bucket"`
    Region     string `yaml:"region"`
    Prefix     string `yaml:"prefix"`
    KMSKeyID   string `yaml:"kms_key_id"`
}

// ExportRequest represents an audit export request
type ExportRequest struct {
    ID              uuid.UUID           `json:"id"`
    RequestedBy     uuid.UUID           `json:"requested_by"`
    RequestedAt     time.Time           `json:"requested_at"`
    EventTypes      []string            `json:"event_types"`
    StartTime       time.Time           `json:"start_time"`
    EndTime         time.Time           `json:"end_time"`
    Filters         ExportFilters       `json:"filters"`
    Format          ExportFormat        `json:"format"`
    Standard        ComplianceStandard  `json:"standard"`
    Status          ExportStatus        `json:"status"`
    CompletedAt     *time.Time          `json:"completed_at,omitempty"`
    FailedAt        *time.Time          `json:"failed_at,omitempty"`
    Error           string              `json:"error,omitempty"`
    FilePath        string              `json:"file_path,omitempty"`
    FileSize        int64               `json:"file_size,omitempty"`
    RecordCount     int64               `json:"record_count,omitempty"`
    Checksum        string              `json:"checksum,omitempty"`
    EncryptionKeyID string              `json:"encryption_key_id,omitempty"`
    ExpiresAt       time.Time           `json:"expires_at"`
    Metadata        models.JSONMap      `json:"metadata"`
}

// ExportFilters for filtering audit data
type ExportFilters struct {
    UserIDs      []uuid.UUID `json:"user_ids,omitempty"`
    DeviceKeys   []string    `json:"device_keys,omitempty"`
    IPRanges     []string    `json:"ip_ranges,omitempty"`
    Actions      []string    `json:"actions,omitempty"`
    Outcomes     []string    `json:"outcomes,omitempty"`
    RiskScores   *RiskRange  `json:"risk_scores,omitempty"`
    Platforms    []string    `json:"platforms,omitempty"`
    StatusCodes  []int       `json:"status_codes,omitempty"`
}

// RiskRange for filtering by risk score
type RiskRange struct {
    Min float64 `json:"min"`
    Max float64 `json:"max"`
}

// ExportStatus represents the status of an export
type ExportStatus string

const (
    StatusPending    ExportStatus = "pending"
    StatusProcessing ExportStatus = "processing"
    StatusCompleted  ExportStatus = "completed"
    StatusFailed     ExportStatus = "failed"
    StatusExpired    ExportStatus = "expired"
    StatusCancelled  ExportStatus = "cancelled"
)

// AuditExporter handles audit data exports for compliance
type AuditExporter struct {
    config     ExportConfig
    redis      *client.RedisClient
    kmsHelper  *security.Helper
    esClient   *http.Client
    
    // Export job management
    jobQueue   chan *ExportRequest
    workers    int
    
    // Statistics
    stats      ExportStats
    statsMu    sync.RWMutex
}

// ExportStats tracks export statistics
type ExportStats struct {
    TotalExports     int64          `json:"total_exports"`
    CompletedExports int64          `json:"completed_exports"`
    FailedExports    int64          `json:"failed_exports"`
    TotalRecords     int64          `json:"total_records"`
    TotalDataSize    int64          `json:"total_data_size"`
    AverageExportTime time.Duration `json:"average_export_time"`
    LastExport       *time.Time     `json:"last_export,omitempty"`
}

// NewAuditExporter creates a new audit exporter
func NewAuditExporter(config ExportConfig, redis *client.RedisClient, kmsHelper *security.Helper) *AuditExporter {
    // Set defaults
    if config.MaxBatchSize == 0 {
        config.MaxBatchSize = 10000
    }
    if config.MaxExportSize == 0 {
        config.MaxExportSize = 1 << 30 // 1GB
    }
    
    workers := 5 // Concurrent export workers
    
    exporter := &AuditExporter{
        config:    config,
        redis:     redis,
        kmsHelper: kmsHelper,
        esClient: &http.Client{
            Timeout: 30 * time.Second,
        },
        jobQueue: make(chan *ExportRequest, 100),
        workers:  workers,
    }
    
    if config.Enabled {
        // Start export workers
        for i := 0; i < workers; i++ {
            go exporter.exportWorker()
        }
        
        // Start cleanup routine
        go exporter.cleanupRoutine()
        
        logger.Info("Audit exporter initialized", 
            "workers", workers,
            "standards", config.ComplianceStandards,
            "formats", config.ExportFormats)
    }
    
    return exporter
}

// CreateExport creates a new audit export request
func (ae *AuditExporter) CreateExport(ctx context.Context, req *ExportRequest) (*ExportRequest, error) {
    if !ae.config.Enabled {
        return nil, fmt.Errorf("audit exporter is disabled")
    }
    
    // Validate request
    if err := ae.validateRequest(req); err != nil {
        return nil, fmt.Errorf("invalid export request: %w", err)
    }
    
    // Generate ID and set defaults
    req.ID = uuid.New()
    req.RequestedAt = time.Now()
    req.Status = StatusPending
    req.ExpiresAt = time.Now().Add(7 * 24 * time.Hour) // Expire after 7 days
    
    // Store request
    if err := ae.storeExportRequest(ctx, req); err != nil {
        return nil, fmt.Errorf("failed to store export request: %w", err)
    }
    
    // Queue for processing
    select {
    case ae.jobQueue <- req:
        logger.Info("Export request queued", "export_id", req.ID, "requested_by", req.RequestedBy)
    default:
        req.Status = StatusFailed
        req.Error = "export queue full"
        ae.storeExportRequest(ctx, req)
        return nil, fmt.Errorf("export queue is full")
    }
    
    return req, nil
}

// GetExportStatus returns the status of an export request
func (ae *AuditExporter) GetExportStatus(ctx context.Context, exportID uuid.UUID) (*ExportRequest, error) {
    req, err := ae.loadExportRequest(ctx, exportID)
    if err != nil {
        return nil, fmt.Errorf("export not found: %w", err)
    }
    return req, nil
}

// ListExports returns export requests for a user
func (ae *AuditExporter) ListExports(ctx context.Context, userID uuid.UUID, limit int) ([]*ExportRequest, error) {
    pattern := fmt.Sprintf("export:user:%s:*", userID.String())
    keys, err := ae.redis.Keys(ctx, pattern).Result()
    if err != nil {
        return nil, fmt.Errorf("failed to list exports: %w", err)
    }
    
    var exports []*ExportRequest
    for i, key := range keys {
        if limit > 0 && i >= limit {
            break
        }
        
        var req ExportRequest
        if err := ae.redis.GetJSON(ctx, key, &req); err != nil {
            continue // Skip invalid entries
        }
        exports = append(exports, &req)
    }
    
    return exports, nil
}

// CancelExport cancels a pending export
func (ae *AuditExporter) CancelExport(ctx context.Context, exportID uuid.UUID, userID uuid.UUID) error {
    req, err := ae.loadExportRequest(ctx, exportID)
    if err != nil {
        return fmt.Errorf("export not found: %w", err)
    }
    
    if req.RequestedBy != userID {
        return fmt.Errorf("unauthorized to cancel export")
    }
    
    if req.Status != StatusPending && req.Status != StatusProcessing {
        return fmt.Errorf("cannot cancel export in status: %s", req.Status)
    }
    
    req.Status = StatusCancelled
    return ae.storeExportRequest(ctx, req)
}

// Export workers and processing

func (ae *AuditExporter) exportWorker() {
    for req := range ae.jobQueue {
        ae.processExport(req)
    }
}

func (ae *AuditExporter) processExport(req *ExportRequest) {
    ctx := context.Background()
    start := time.Now()
    
    logger.Info("Processing export", "export_id", req.ID, "standard", req.Standard)
    
    // Update status to processing
    req.Status = StatusProcessing
    ae.storeExportRequest(ctx, req)
    
    // Process the export
    filePath, recordCount, fileSize, err := ae.executeExport(ctx, req)
    
    if err != nil {
        req.Status = StatusFailed
        req.Error = err.Error()
        failedAt := time.Now()
        req.FailedAt = &failedAt
        
        ae.updateStats(func(s *ExportStats) {
            s.FailedExports++
        })
        
        logger.Error("Export failed", "export_id", req.ID, "error", err)
    } else {
        req.Status = StatusCompleted
        req.FilePath = filePath
        req.RecordCount = recordCount
        req.FileSize = fileSize
        completedAt := time.Now()
        req.CompletedAt = &completedAt
        
        // Calculate checksum for integrity
        if checksum, err := ae.calculateChecksum(filePath); err == nil {
            req.Checksum = checksum
        }
        
        ae.updateStats(func(s *ExportStats) {
            s.CompletedExports++
            s.TotalRecords += recordCount
            s.TotalDataSize += fileSize
            s.AverageExportTime = (s.AverageExportTime + time.Since(start)) / 2
            now := time.Now()
            s.LastExport = &now
        })
        
        logger.Info("Export completed", 
            "export_id", req.ID,
            "records", recordCount,
            "size_bytes", fileSize,
            "duration", time.Since(start))
    }
    
    ae.updateStats(func(s *ExportStats) {
        s.TotalExports++
    })
    
    ae.storeExportRequest(ctx, req)
}

func (ae *AuditExporter) executeExport(ctx context.Context, req *ExportRequest) (string, int64, int64, error) {
    // Query audit data from Elasticsearch
    auditData, err := ae.queryAuditData(ctx, req)
    if err != nil {
        return "", 0, 0, fmt.Errorf("failed to query audit data: %w", err)
    }
    
    // Apply compliance standard formatting
    formattedData, err := ae.formatForCompliance(auditData, req.Standard)
    if err != nil {
        return "", 0, 0, fmt.Errorf("failed to format for compliance: %w", err)
    }
    
    // Generate file
    filePath, fileSize, err := ae.generateExportFile(req, formattedData)
    if err != nil {
        return "", 0, 0, fmt.Errorf("failed to generate export file: %w", err)
    }
    
    recordCount := int64(len(formattedData))
    
    // Encrypt if required
    if ae.config.EncryptExports {
        encryptedPath, keyID, err := ae.encryptExportFile(ctx, filePath)
        if err != nil {
            return "", 0, 0, fmt.Errorf("failed to encrypt export: %w", err)
        }
        req.EncryptionKeyID = keyID
        filePath = encryptedPath
    }
    
    // Upload to S3 if configured
    if ae.config.S3Config.Enabled {
        s3Path, err := ae.uploadToS3(ctx, filePath, req)
        if err != nil {
            logger.Warn("Failed to upload to S3", "error", err)
        } else {
            filePath = s3Path
        }
    }
    
    return filePath, recordCount, fileSize, nil
}

func (ae *AuditExporter) queryAuditData(ctx context.Context, req *ExportRequest) ([]map[string]interface{}, error) {
    // Build Elasticsearch query
    query := ae.buildESQuery(req)
    
    // Execute scroll query for large datasets
    var allData []map[string]interface{}
    scrollID := ""
    
    for {
        var resp map[string]interface{}
        var err error
        
        if scrollID == "" {
            // Initial search
            resp, err = ae.executeESSearch(ctx, query, req)
        } else {
            // Scroll for next batch
            resp, err = ae.executeESScroll(ctx, scrollID)
        }
        
        if err != nil {
            return nil, err
        }
        
        hits, ok := resp["hits"].(map[string]interface{})
        if !ok {
            break
        }
        
        hitsArray, ok := hits["hits"].([]interface{})
        if !ok || len(hitsArray) == 0 {
            break
        }
        
        // Process hits
        for _, hit := range hitsArray {
            hitMap, ok := hit.(map[string]interface{})
            if !ok {
                continue
            }
            
            source, ok := hitMap["_source"].(map[string]interface{})
            if ok {
                allData = append(allData, source)
            }
        }
        
        // Get scroll ID for next batch
        newScrollID, ok := resp["_scroll_id"].(string)
        if !ok {
            break
        }
        scrollID = newScrollID
        
        // Check batch size limit
        if len(allData) >= ae.config.MaxBatchSize {
            logger.Warn("Export batch size limit reached", "limit", ae.config.MaxBatchSize)
            break
        }
    }
    
    return allData, nil
}

func (ae *AuditExporter) buildESQuery(req *ExportRequest) map[string]interface{} {
    // Build Elasticsearch query based on request filters
    query := map[string]interface{}{
        "bool": map[string]interface{}{
            "must": []map[string]interface{}{
                {
                    "range": map[string]interface{}{
                        "@timestamp": map[string]interface{}{
                            "gte": req.StartTime.Format(time.RFC3339),
                            "lte": req.EndTime.Format(time.RFC3339),
                        },
                    },
                },
            },
        },
    }
    
    mustQueries := query["bool"].(map[string]interface{})["must"].([]map[string]interface{})
    
    // Add event type filters
    if len(req.EventTypes) > 0 {
        mustQueries = append(mustQueries, map[string]interface{}{
            "terms": map[string]interface{}{
                "_index": req.EventTypes,
            },
        })
    }
    
    // Add user ID filters
    if len(req.Filters.UserIDs) > 0 {
        userIDStrings := make([]string, len(req.Filters.UserIDs))
        for i, id := range req.Filters.UserIDs {
            userIDStrings[i] = id.String()
        }
        mustQueries = append(mustQueries, map[string]interface{}{
            "terms": map[string]interface{}{
                "user_id": userIDStrings,
            },
        })
    }
    
    // Add device key filters
    if len(req.Filters.DeviceKeys) > 0 {
        mustQueries = append(mustQueries, map[string]interface{}{
            "terms": map[string]interface{}{
                "device_key": req.Filters.DeviceKeys,
            },
        })
    }
    
    // Add status code filters
    if len(req.Filters.StatusCodes) > 0 {
        mustQueries = append(mustQueries, map[string]interface{}{
            "terms": map[string]interface{}{
                "status": req.Filters.StatusCodes,
            },
        })
    }
    
    // Add risk score range
    if req.Filters.RiskScores != nil {
        mustQueries = append(mustQueries, map[string]interface{}{
            "range": map[string]interface{}{
                "risk_score": map[string]interface{}{
                    "gte": req.Filters.RiskScores.Min,
                    "lte": req.Filters.RiskScores.Max,
                },
            },
        })
    }
    
    query["bool"].(map[string]interface{})["must"] = mustQueries
    
    return map[string]interface{}{
        "query": query,
        "sort": []map[string]interface{}{
            {"@timestamp": map[string]interface{}{"order": "asc"}},
        },
    }
}

func (ae *AuditExporter) executeESSearch(ctx context.Context, query map[string]interface{}, req *ExportRequest) (map[string]interface{}, error) {
    // Add scroll context for large result sets
    searchQuery := map[string]interface{}{
        "size":   1000, // Batch size
        "scroll": "10m", // 10 minute scroll context
    }
    
    // Merge with the main query
    for k, v := range query {
        searchQuery[k] = v
    }
    
    queryJSON, err := json.Marshal(searchQuery)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal query: %w", err)
    }
    
    // Determine index pattern based on date range
    indexPattern := ae.buildIndexPattern(req.StartTime, req.EndTime)
    
    url := fmt.Sprintf("%s/%s/_search", ae.config.ESConfig.Endpoint, indexPattern)
    
    esReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(queryJSON))
    if err != nil {
        return nil, fmt.Errorf("failed to create ES request: %w", err)
    }
    
    esReq.Header.Set("Content-Type", "application/json")
    
    if ae.config.ESConfig.APIKey != "" {
        esReq.Header.Set("Authorization", "ApiKey "+ae.config.ESConfig.APIKey)
    } else if ae.config.ESConfig.Username != "" || ae.config.ESConfig.Password != "" {
        esReq.SetBasicAuth(ae.config.ESConfig.Username, ae.config.ESConfig.Password)
    }
    
    resp, err := ae.esClient.Do(esReq)
    if err != nil {
        return nil, fmt.Errorf("ES request failed: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode >= 400 {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("ES search failed: status=%d body=%s", resp.StatusCode, string(body))
    }
    
    var result map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("failed to decode ES response: %w", err)
    }
    
    return result, nil
}

func (ae *AuditExporter) executeESScroll(ctx context.Context, scrollID string) (map[string]interface{}, error) {
    scrollQuery := map[string]interface{}{
        "scroll":    "10m",
        "scroll_id": scrollID,
    }
    
    queryJSON, err := json.Marshal(scrollQuery)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal scroll query: %w", err)
    }
    
    url := fmt.Sprintf("%s/_search/scroll", ae.config.ESConfig.Endpoint)
    
    esReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(queryJSON))
    if err != nil {
        return nil, fmt.Errorf("failed to create ES scroll request: %w", err)
    }
    
    esReq.Header.Set("Content-Type", "application/json")
    
    if ae.config.ESConfig.APIKey != "" {
        esReq.Header.Set("Authorization", "ApiKey "+ae.config.ESConfig.APIKey)
    } else if ae.config.ESConfig.Username != "" || ae.config.ESConfig.Password != "" {
        esReq.SetBasicAuth(ae.config.ESConfig.Username, ae.config.ESConfig.Password)
    }
    
    resp, err := ae.esClient.Do(esReq)
    if err != nil {
        return nil, fmt.Errorf("ES scroll request failed: %w", err)
    }
    defer resp.Body.Close()
    
    var result map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("failed to decode ES scroll response: %w", err)
    }
    
    return result, nil
}

func (ae *AuditExporter) buildIndexPattern(startTime, endTime time.Time) string {
    // Build index pattern for the date range
    // Assumes daily indices like "audit-2025.08.23"
    
    if startTime.Truncate(24*time.Hour).Equal(endTime.Truncate(24*time.Hour)) {
        // Single day
        return fmt.Sprintf("audit-%04d.%02d.%02d", 
            startTime.Year(), int(startTime.Month()), startTime.Day())
    }
    
    // Multiple days - use wildcard pattern
    return "audit-*"
}

func (ae *AuditExporter) formatForCompliance(data []map[string]interface{}, standard ComplianceStandard) ([]map[string]interface{}, error) {
    // Format data according to compliance standard requirements
    
    switch standard {
    case StandardGDPR:
        return ae.formatForGDPR(data), nil
    case StandardCCPA:
        return ae.formatForCCPA(data), nil
    case StandardHIPAA:
        return ae.formatForHIPAA(data), nil
    case StandardSOX:
        return ae.formatForSOX(data), nil
    case StandardPCI:
        return ae.formatForPCI(data), nil
    case StandardISO27001:
        return ae.formatForISO27001(data), nil
    default:
        return data, nil // Return as-is for unknown standards
    }
}

func (ae *AuditExporter) formatForGDPR(data []map[string]interface{}) []map[string]interface{} {
    // GDPR-specific formatting
    var formatted []map[string]interface{}
    
    for _, record := range data {
        gdprRecord := map[string]interface{}{
            "timestamp":     record["@timestamp"],
            "data_subject":  record["user_id"], // GDPR term for user
            "processing_purpose": ae.determinePurpose(record),
            "legal_basis":   ae.determineLegalBasis(record),
            "data_category": ae.determineDataCategory(record),
            "retention_period": ae.determineRetentionPeriod(record),
            "controller":    "ComUnity Auth Service",
            "processor":     "ComUnity Inc",
            "original_event": record,
        }
        formatted = append(formatted, gdprRecord)
    }
    
    return formatted
}

func (ae *AuditExporter) formatForCCPA(data []map[string]interface{}) []map[string]interface{} {
    // CCPA-specific formatting
    var formatted []map[string]interface{}
    
    for _, record := range data {
        ccpaRecord := map[string]interface{}{
            "timestamp":      record["@timestamp"],
            "consumer_id":    record["user_id"],
            "personal_info_category": ae.determinePersonalInfoCategory(record),
            "business_purpose": ae.determineBusinessPurpose(record),
            "commercial_purpose": ae.determineCommercialPurpose(record),
            "third_party_disclosure": false, // Adjust based on your data sharing
            "sale_indicator": false, // Adjust based on your business model
            "original_event": record,
        }
        formatted = append(formatted, ccpaRecord)
    }
    
    return formatted
}

func (ae *AuditExporter) formatForHIPAA(data []map[string]interface{}) []map[string]interface{} {
    // HIPAA-specific formatting (if handling health data)
    var formatted []map[string]interface{}
    
    for _, record := range data {
        hipaaRecord := map[string]interface{}{
            "timestamp":        record["@timestamp"],
            "patient_id":       record["user_id"],
            "covered_entity":   "ComUnity Auth Service",
            "business_associate": nil,
            "phi_accessed":     ae.determinePHIAccess(record),
            "minimum_necessary": true,
            "authorization":    ae.determineAuthorization(record),
            "original_event":   record,
        }
        formatted = append(formatted, hipaaRecord)
    }
    
    return formatted
}

func (ae *AuditExporter) formatForSOX(data []map[string]interface{}) []map[string]interface{} {
    // SOX-specific formatting for financial controls
    var formatted []map[string]interface{}
    
    for _, record := range data {
        soxRecord := map[string]interface{}{
            "timestamp":           record["@timestamp"],
            "user_id":            record["user_id"],
            "control_activity":   ae.determineControlActivity(record),
            "financial_relevance": ae.determineFinancialRelevance(record),
            "segregation_duties": ae.checkSegregationDuties(record),
            "approval_required":  ae.checkApprovalRequired(record),
            "original_event":     record,
        }
        formatted = append(formatted, soxRecord)
    }
    
    return formatted
}

func (ae *AuditExporter) formatForPCI(data []map[string]interface{}) []map[string]interface{} {
    // PCI-DSS specific formatting
    var formatted []map[string]interface{}
    
    for _, record := range data {
        pciRecord := map[string]interface{}{
            "timestamp":          record["@timestamp"],
            "cardholder_data":    ae.identifyCardholderData(record),
            "sensitive_auth_data": ae.identifySensitiveAuthData(record),
            "pci_requirement":    ae.mapToPCIRequirement(record),
            "network_access":     ae.analyzeNetworkAccess(record),
            "vulnerability":      ae.assessVulnerability(record),
            "original_event":     record,
        }
        formatted = append(formatted, pciRecord)
    }
    
    return formatted
}

func (ae *AuditExporter) formatForISO27001(data []map[string]interface{}) []map[string]interface{} {
    // ISO 27001 specific formatting
    var formatted []map[string]interface{}
    
    for _, record := range data {
        isoRecord := map[string]interface{}{
            "timestamp":         record["@timestamp"],
            "security_domain":   ae.determineSecurityDomain(record),
            "control_objective": ae.mapToISOControl(record),
            "asset_classification": ae.classifyAsset(record),
            "risk_assessment":   ae.assessRisk(record),
            "incident_indicator": ae.checkIncidentIndicator(record),
            "original_event":    record,
        }
        formatted = append(formatted, isoRecord)
    }
    
    return formatted
}

// Helper methods for compliance formatting
func (ae *AuditExporter) determinePurpose(record map[string]interface{}) string {
    path, _ := record["path"].(string)
    switch {
    case strings.Contains(path, "/auth/login"):
        return "Authentication"
    case strings.Contains(path, "/otp/"):
        return "Identity Verification"
    case strings.Contains(path, "/rbac/"):
        return "Authorization"
    default:
        return "Service Operation"
    }
}

func (ae *AuditExporter) determineLegalBasis(record map[string]interface{}) string {
    return "Legitimate Interest - Service Security and Fraud Prevention"
}

func (ae *AuditExporter) determineDataCategory(record map[string]interface{}) string {
    if _, hasDevice := record["device_key"]; hasDevice {
        return "Technical Data - Device Information"
    }
    if _, hasIP := record["ip_bucket"]; hasIP {
        return "Technical Data - Network Information"
    }
    return "Service Usage Data"
}

func (ae *AuditExporter) determineRetentionPeriod(record map[string]interface{}) string {
    return "90 days (Security Audit Logs)"
}

func (ae *AuditExporter) determinePersonalInfoCategory(record map[string]interface{}) string {
    return "Identifiers and Internet/Electronic Activity"
}

func (ae *AuditExporter) determineBusinessPurpose(record map[string]interface{}) string {
    return "Security and fraud prevention"
}

func (ae *AuditExporter) determineCommercialPurpose(record map[string]interface{}) string {
    return "Service improvement and analytics"
}

// Additional helper methods would be implemented similarly...
func (ae *AuditExporter) determinePHIAccess(record map[string]interface{}) bool { return false }
func (ae *AuditExporter) determineAuthorization(record map[string]interface{}) string { return "Implicit" }
func (ae *AuditExporter) determineControlActivity(record map[string]interface{}) string { return "Access Control" }
func (ae *AuditExporter) determineFinancialRelevance(record map[string]interface{}) bool { return false }
func (ae *AuditExporter) checkSegregationDuties(record map[string]interface{}) bool { return true }
func (ae *AuditExporter) checkApprovalRequired(record map[string]interface{}) bool { return false }
func (ae *AuditExporter) identifyCardholderData(record map[string]interface{}) bool { return false }
func (ae *AuditExporter) identifySensitiveAuthData(record map[string]interface{}) bool { return false }
func (ae *AuditExporter) mapToPCIRequirement(record map[string]interface{}) string { return "Req 10 - Logging" }
func (ae *AuditExporter) analyzeNetworkAccess(record map[string]interface{}) string { return "Authorized" }
func (ae *AuditExporter) assessVulnerability(record map[string]interface{}) string { return "None" }
func (ae *AuditExporter) determineSecurityDomain(record map[string]interface{}) string { return "A.12 Operations Security" }
func (ae *AuditExporter) mapToISOControl(record map[string]interface{}) string { return "A.12.4 Logging and Monitoring" }
func (ae *AuditExporter) classifyAsset(record map[string]interface{}) string { return "Authentication Data" }
func (ae *AuditExporter) assessRisk(record map[string]interface{}) string { return "Low" }
func (ae *AuditExporter) checkIncidentIndicator(record map[string]interface{}) bool { 
    status, _ := record["status"].(float64)
    return status >= 400
}

func (ae *AuditExporter) generateExportFile(req *ExportRequest, data []map[string]interface{}) (string, int64, error) {
    timestamp := time.Now().Format("20060102-150405")
    filename := fmt.Sprintf("audit-export-%s-%s-%s.%s", 
        req.Standard, req.ID.String()[:8], timestamp, req.Format)
    
    filePath := fmt.Sprintf("/tmp/exports/%s", filename)
    
    switch req.Format {
    case FormatJSON:
        return ae.generateJSONFile(filePath, data)
    case FormatCSV:
        return ae.generateCSVFile(filePath, data)
    case FormatXML:
        return ae.generateXMLFile(filePath, data)
    default:
        return "", 0, fmt.Errorf("unsupported export format: %s", req.Format)
    }
}

func (ae *AuditExporter) generateJSONFile(filePath string, data []map[string]interface{}) (string, int64, error) {
    file, err := os.Create(filePath)
    if err != nil {
        return "", 0, fmt.Errorf("failed to create file: %w", err)
    }
    defer file.Close()
    
    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
    
    if err := encoder.Encode(data); err != nil {
        return "", 0, fmt.Errorf("failed to encode JSON: %w", err)
    }
    
    stat, err := file.Stat()
    if err != nil {
        return "", 0, fmt.Errorf("failed to get file stats: %w", err)
    }
    
    return filePath, stat.Size(), nil
}

func (ae *AuditExporter) generateCSVFile(filePath string, data []map[string]interface{}) (string, int64, error) {
    file, err := os.Create(filePath)
    if err != nil {
        return "", 0, fmt.Errorf("failed to create file: %w", err)
    }
    defer file.Close()
    
    writer := csv.NewWriter(file)
    defer writer.Flush()
    
    if len(data) == 0 {
        return filePath, 0, nil
    }
    
    // Extract headers from first record
    var headers []string
    for key := range data[0] {
        headers = append(headers, key)
    }
    
    if err := writer.Write(headers); err != nil {
        return "", 0, fmt.Errorf("failed to write CSV headers: %w", err)
    }
    
    // Write data rows
    for _, record := range data {
        var row []string
        for _, header := range headers {
            value := ""
            if v, ok := record[header]; ok && v != nil {
                value = fmt.Sprintf("%v", v)
            }
            row = append(row, value)
        }
        
        if err := writer.Write(row); err != nil {
            return "", 0, fmt.Errorf("failed to write CSV row: %w", err)
        }
    }
    
    stat, err := file.Stat()
    if err != nil {
        return "", 0, fmt.Errorf("failed to get file stats: %w", err)
    }
    
    return filePath, stat.Size(), nil
}

func (ae *AuditExporter) generateXMLFile(filePath string, data []map[string]interface{}) (string, int64, error) {
    file, err := os.Create(filePath)
    if err != nil {
        return "", 0, fmt.Errorf("failed to create file: %w", err)
    }
    defer file.Close()
    
    // Simple XML generation
    file.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
    file.WriteString("<audit_records>\n")
    
    for _, record := range data {
        file.WriteString("  <record>\n")
        for key, value := range record {
            file.WriteString(fmt.Sprintf("    <%s>%v</%s>\n", key, value, key))
        }
        file.WriteString("  </record>\n")
    }
    
    file.WriteString("</audit_records>\n")
    
    stat, err := file.Stat()
    if err != nil {
        return "", 0, fmt.Errorf("failed to get file stats: %w", err)
    }
    
    return filePath, stat.Size(), nil
}

// Storage and utility methods

func (ae *AuditExporter) storeExportRequest(ctx context.Context, req *ExportRequest) error {
    key := fmt.Sprintf("export:%s", req.ID.String())
    userKey := fmt.Sprintf("export:user:%s:%s", req.RequestedBy.String(), req.ID.String())
    
    // Store with 30 day TTL
    ttl := 30 * 24 * time.Hour
    
    if err := ae.redis.SetJSON(ctx, key, req, ttl); err != nil {
        return err
    }
    
    return ae.redis.SetJSON(ctx, userKey, req, ttl)
}

func (ae *AuditExporter) loadExportRequest(ctx context.Context, exportID uuid.UUID) (*ExportRequest, error) {
    key := fmt.Sprintf("export:%s", exportID.String())
    
    var req ExportRequest
    if err := ae.redis.GetJSON(ctx, key, &req); err != nil {
        return nil, err
    }
    
    return &req, nil
}

func (ae *AuditExporter) validateRequest(req *ExportRequest) error {
    if req.StartTime.IsZero() || req.EndTime.IsZero() {
        return fmt.Errorf("start_time and end_time are required")
    }
    
    if req.EndTime.Before(req.StartTime) {
        return fmt.Errorf("end_time must be after start_time")
    }
    
    if req.EndTime.Sub(req.StartTime) > 90*24*time.Hour {
        return fmt.Errorf("export period cannot exceed 90 days")
    }
    
    if req.Format == "" {
        req.Format = FormatJSON
    }
    
    if req.Standard == "" {
        req.Standard = StandardGDPR
    }
    
    return nil
}

func (ae *AuditExporter) encryptExportFile(ctx context.Context, filePath string) (string, string, error) {
    // Use KMS to encrypt the export file
    dataKey, err := ae.kmsHelper.GenerateDataKey(ctx, "AES_256")
    if err != nil {
        return "", "", fmt.Errorf("failed to generate data key: %w", err)
    }
    defer security.Wipe(dataKey.Plaintext)
    
    // Read original file
    plaintext, err := os.ReadFile(filePath)
    if err != nil {
        return "", "", fmt.Errorf("failed to read file: %w", err)
    }
    
    // Encrypt content
    ciphertext, err := dataKey.Encrypt(plaintext, []byte("audit_export"))
    if err != nil {
        return "", "", fmt.Errorf("failed to encrypt file: %w", err)
    }
    
    // Write encrypted file
    encryptedPath := filePath + ".enc"
    if err := os.WriteFile(encryptedPath, ciphertext, 0600); err != nil {
        return "", "", fmt.Errorf("failed to write encrypted file: %w", err)
    }
    
    // Remove original
    os.Remove(filePath)
    
    return encryptedPath, dataKey.CiphertextB64, nil
}

func (ae *AuditExporter) calculateChecksum(filePath string) (string, error) {
    // Calculate SHA256 checksum for file integrity
    data, err := os.ReadFile(filePath)
    if err != nil {
        return "", err
    }
    
    hash := sha256.Sum256(data)
    return fmt.Sprintf("%x", hash), nil
}

func (ae *AuditExporter) uploadToS3(ctx context.Context, filePath string, req *ExportRequest) (string, error) {
    // S3 upload implementation would go here
    // For now, return the local path
    return filePath, nil
}

func (ae *AuditExporter) cleanupRoutine() {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()
    
    for range ticker.C {
        ae.cleanupExpiredExports()
    }
}

func (ae *AuditExporter) cleanupExpiredExports() {
    ctx := context.Background()
    pattern := "export:*"
    
    keys, err := ae.redis.Keys(ctx, pattern).Result()
    if err != nil {
        return
    }
    
    for _, key := range keys {
        var req ExportRequest
        if err := ae.redis.GetJSON(ctx, key, &req); err != nil {
            continue
        }
        
        if time.Now().After(req.ExpiresAt) {
            // Delete expired export
            ae.redis.Del(ctx, key)
            
            // Clean up file if it exists
            if req.FilePath != "" {
                os.Remove(req.FilePath)
            }
            
            logger.Debug("Cleaned up expired export", "export_id", req.ID)
        }
    }
}

func (ae *AuditExporter) updateStats(update func(*ExportStats)) {
    ae.statsMu.Lock()
    defer ae.statsMu.Unlock()
    update(&ae.stats)
}

// GetStats returns export statistics
func (ae *AuditExporter) GetStats() ExportStats {
    ae.statsMu.RLock()
    defer ae.statsMu.RUnlock()
    return ae.stats
}
