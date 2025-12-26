/**
 * Core type definitions for Cloak Security Gateway
 */

/**
 * Extension configuration options
 */
export interface CloakExtensionConfig {
    ollamaEndpoint: string;
    threatSensitivity: 'low' | 'medium' | 'high';
    enableLogging: boolean;
    maxPromptLength: number;
    timeout: number;
}

/**
 * Intercepted prompt data structure
 */
export interface InterceptedPrompt {
    id: string;
    content: string;
    timestamp: Date;
    source: 'chat' | 'command';
    metadata: PromptMetadata;
}

/**
 * Metadata associated with an intercepted prompt
 */
export interface PromptMetadata {
    participantId?: string;
    commandId?: string;
    sessionId?: string;
}

/**
 * Security analysis result from the local SLM
 */
export interface SecurityAnalysis {
    threatLevel: 'safe' | 'suspicious' | 'dangerous';
    confidence: number;
    detectedPatterns: ThreatPattern[];
    reasoning: string;
    processingTime: number;
}

/**
 * Detected threat pattern details
 */
export interface ThreatPattern {
    type: 'rule_bypass' | 'secret_extraction' | 'command_injection' | 'role_manipulation';
    pattern: string;
    severity: 'low' | 'medium' | 'high';
    description: string;
}

/**
 * Security decision made by the Gatekeeper
 */
export interface SecurityDecision {
    action: 'allow' | 'block' | 'warn';
    reason: string;
    originalPrompt: InterceptedPrompt;
    analysis: SecurityAnalysis;
    userOverride?: boolean;
}

/**
 * Shield status for UI display
 */
export interface ShieldStatus {
    state: 'active' | 'scanning' | 'error' | 'disabled';
    message: string;
    lastAnalysis?: Date;
    serviceHealth: 'healthy' | 'degraded' | 'unavailable';
}

/**
 * Security event for audit logging
 */
export interface SecurityEvent {
    id: string;
    timestamp: Date;
    eventType: 'analysis' | 'block' | 'allow' | 'override' | 'error';
    promptHash: string;
    threatLevel: string;
    confidence: number;
    decision: string;
    userOverride?: boolean;
    processingTime: number;
}

/**
 * Full security configuration schema
 */
export interface SecurityConfig {
    ollama: {
        endpoint: string;
        model: string;
        timeout: number;
        retryAttempts: number;
    };
    security: {
        threatSensitivity: 'low' | 'medium' | 'high';
        blockThreshold: number;
        warnThreshold: number;
        enableUserOverride: boolean;
    };
    logging: {
        enableAuditLog: boolean;
        logLevel: 'error' | 'warn' | 'info' | 'debug';
        maxLogSize: number;
    };
}

/**
 * Intercepted prompt with integrity hash for data integrity verification
 */
export interface VerifiedPrompt extends InterceptedPrompt {
    integrityHash: string;
}

/**
 * Stored analysis result with metadata for local storage
 */
export interface StoredAnalysisResult {
    id: string;
    timestamp: Date;
    promptHash: string;
    analysis: SecurityAnalysis;
    decision: 'allow' | 'block' | 'warn';
}

/**
 * Local storage configuration options
 */
export interface LocalStorageConfig {
    maxAuditLogEntries: number;
    maxAnalysisResultEntries: number;
    enablePersistence: boolean;
    rotationThreshold: number;
}


/**
 * Performance metrics for a single operation
 */
export interface OperationMetrics {
    operationId: string;
    operationType: 'analysis' | 'interception' | 'decision' | 'storage';
    startTime: number;
    endTime?: number;
    duration?: number;
    success: boolean;
    memoryUsedBefore?: number;
    memoryUsedAfter?: number;
}

/**
 * Aggregated performance statistics
 */
export interface PerformanceStats {
    totalOperations: number;
    successfulOperations: number;
    failedOperations: number;
    averageDuration: number;
    minDuration: number;
    maxDuration: number;
    p95Duration: number;
    operationsPerMinute: number;
    currentQueueSize: number;
    peakQueueSize: number;
    memoryUsage: MemoryUsage;
    uptime: number;
}

/**
 * Memory usage information
 */
export interface MemoryUsage {
    heapUsed: number;
    heapTotal: number;
    external: number;
    rss: number;
    percentUsed: number;
}

/**
 * Queue statistics for monitoring
 */
export interface QueueStats {
    currentSize: number;
    peakSize: number;
    totalProcessed: number;
    averageWaitTime: number;
    droppedRequests: number;
}

/**
 * Resource monitoring configuration
 */
export interface ResourceMonitorConfig {
    idleCheckIntervalMs: number;
    memoryWarningThresholdPercent: number;
    maxQueueSize: number;
    metricsRetentionCount: number;
    enableDetailedLogging: boolean;
}
