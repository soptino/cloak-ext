import * as vscode from 'vscode';

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

/**
 * PerformanceMonitor provides performance monitoring and resource optimization
 * for the Cloak security extension.
 * 
 * Requirements:
 * - 6.4: Queue requests efficiently when multiple analyses are requested
 * - 6.5: Consume minimal system resources during idle periods
 */
export class PerformanceMonitor implements vscode.Disposable {
    private config: ResourceMonitorConfig;
    private metrics: OperationMetrics[] = [];
    private activeOperations: Map<string, OperationMetrics> = new Map();
    private queueStats: QueueStats;
    private startTime: number;
    private idleCheckTimer: NodeJS.Timeout | undefined;
    private lastActivityTime: number;
    private isIdle: boolean = true;
    private outputChannel: vscode.OutputChannel;
    private disposables: vscode.Disposable[] = [];
    private operationCounter: number = 0;

    constructor(config?: Partial<ResourceMonitorConfig>) {
        this.config = {
            idleCheckIntervalMs: config?.idleCheckIntervalMs ?? 30000, // 30 seconds
            memoryWarningThresholdPercent: config?.memoryWarningThresholdPercent ?? 80,
            maxQueueSize: config?.maxQueueSize ?? 100,
            metricsRetentionCount: config?.metricsRetentionCount ?? 1000,
            enableDetailedLogging: config?.enableDetailedLogging ?? false
        };

        this.queueStats = {
            currentSize: 0,
            peakSize: 0,
            totalProcessed: 0,
            averageWaitTime: 0,
            droppedRequests: 0
        };

        this.startTime = Date.now();
        this.lastActivityTime = Date.now();
        this.outputChannel = vscode.window.createOutputChannel('Cloak Performance');
        
        this.startIdleMonitoring();
    }


    /**
     * Starts idle monitoring to track resource usage during inactive periods.
     * Requirements: 6.5 - Minimal resources during idle
     */
    private startIdleMonitoring(): void {
        this.idleCheckTimer = setInterval(() => {
            this.checkIdleState();
        }, this.config.idleCheckIntervalMs);
    }

    /**
     * Checks if the system is idle and performs cleanup if needed.
     * Requirements: 6.5
     */
    private checkIdleState(): void {
        const timeSinceLastActivity = Date.now() - this.lastActivityTime;
        const wasIdle = this.isIdle;
        
        // Consider idle if no activity for 2x the check interval
        this.isIdle = timeSinceLastActivity > this.config.idleCheckIntervalMs * 2;

        if (this.isIdle && !wasIdle) {
            this.onEnterIdle();
        } else if (!this.isIdle && wasIdle) {
            this.onExitIdle();
        }

        // Check memory usage during idle
        if (this.isIdle) {
            this.performIdleCleanup();
        }
    }

    /**
     * Called when system enters idle state.
     */
    private onEnterIdle(): void {
        if (this.config.enableDetailedLogging) {
            this.log('System entered idle state');
        }
        
        // Trim metrics to reduce memory footprint
        this.trimMetrics();
    }

    /**
     * Called when system exits idle state.
     */
    private onExitIdle(): void {
        if (this.config.enableDetailedLogging) {
            this.log('System exited idle state');
        }
    }

    /**
     * Performs cleanup during idle periods.
     * Requirements: 6.5
     */
    private performIdleCleanup(): void {
        const memoryUsage = this.getMemoryUsage();
        
        // If memory usage is high, perform aggressive cleanup
        if (memoryUsage.percentUsed > this.config.memoryWarningThresholdPercent) {
            this.trimMetrics(Math.floor(this.config.metricsRetentionCount / 2));
            
            if (this.config.enableDetailedLogging) {
                this.log(`Memory cleanup performed. Usage: ${memoryUsage.percentUsed.toFixed(1)}%`);
            }
        }
    }

    /**
     * Starts tracking a new operation.
     * 
     * @param operationType Type of operation being tracked
     * @returns Operation ID for tracking
     */
    public startOperation(operationType: OperationMetrics['operationType']): string {
        this.lastActivityTime = Date.now();
        this.isIdle = false;
        
        const operationId = this.generateOperationId();
        const memoryBefore = this.getMemoryUsage();
        
        const metrics: OperationMetrics = {
            operationId,
            operationType,
            startTime: Date.now(),
            success: false,
            memoryUsedBefore: memoryBefore.heapUsed
        };

        this.activeOperations.set(operationId, metrics);
        
        if (this.config.enableDetailedLogging) {
            this.log(`Started operation: ${operationId} (${operationType})`);
        }

        return operationId;
    }

    /**
     * Completes tracking of an operation.
     * 
     * @param operationId The operation ID returned from startOperation
     * @param success Whether the operation succeeded
     */
    public endOperation(operationId: string, success: boolean): void {
        const metrics = this.activeOperations.get(operationId);
        
        if (!metrics) {
            return;
        }

        const memoryAfter = this.getMemoryUsage();
        
        metrics.endTime = Date.now();
        metrics.duration = metrics.endTime - metrics.startTime;
        metrics.success = success;
        metrics.memoryUsedAfter = memoryAfter.heapUsed;

        this.activeOperations.delete(operationId);
        this.metrics.push(metrics);

        // Trim metrics if exceeding retention limit
        if (this.metrics.length > this.config.metricsRetentionCount) {
            this.trimMetrics();
        }

        if (this.config.enableDetailedLogging) {
            this.log(`Completed operation: ${operationId} (${metrics.duration}ms, ${success ? 'success' : 'failed'})`);
        }
    }

    /**
     * Updates queue statistics.
     * Requirements: 6.4 - Efficient queue management
     * 
     * @param currentSize Current queue size
     */
    public updateQueueStats(currentSize: number): void {
        this.queueStats.currentSize = currentSize;
        
        if (currentSize > this.queueStats.peakSize) {
            this.queueStats.peakSize = currentSize;
        }

        // Check if queue is getting too large
        if (currentSize > this.config.maxQueueSize * 0.8) {
            this.log(`Warning: Queue size (${currentSize}) approaching limit (${this.config.maxQueueSize})`);
        }
    }

    /**
     * Records a processed queue item.
     * 
     * @param waitTime Time the item waited in queue (ms)
     */
    public recordQueueProcessed(waitTime: number): void {
        this.queueStats.totalProcessed++;
        
        // Update rolling average wait time
        const alpha = 0.1; // Smoothing factor
        this.queueStats.averageWaitTime = 
            alpha * waitTime + (1 - alpha) * this.queueStats.averageWaitTime;
    }

    /**
     * Records a dropped request due to queue overflow.
     */
    public recordDroppedRequest(): void {
        this.queueStats.droppedRequests++;
        this.log(`Request dropped due to queue overflow. Total dropped: ${this.queueStats.droppedRequests}`);
    }


    /**
     * Gets current memory usage statistics.
     * 
     * @returns Memory usage information
     */
    public getMemoryUsage(): MemoryUsage {
        const usage = process.memoryUsage();
        
        return {
            heapUsed: usage.heapUsed,
            heapTotal: usage.heapTotal,
            external: usage.external,
            rss: usage.rss,
            percentUsed: (usage.heapUsed / usage.heapTotal) * 100
        };
    }

    /**
     * Gets aggregated performance statistics.
     * 
     * @returns Performance statistics
     */
    public getPerformanceStats(): PerformanceStats {
        const completedMetrics = this.metrics.filter(m => m.duration !== undefined);
        const durations = completedMetrics.map(m => m.duration!).sort((a, b) => a - b);
        
        const totalOperations = completedMetrics.length;
        const successfulOperations = completedMetrics.filter(m => m.success).length;
        const failedOperations = totalOperations - successfulOperations;
        
        const averageDuration = totalOperations > 0 
            ? durations.reduce((a, b) => a + b, 0) / totalOperations 
            : 0;
        
        const minDuration = durations.length > 0 ? durations[0] : 0;
        const maxDuration = durations.length > 0 ? durations[durations.length - 1] : 0;
        
        // Calculate P95
        const p95Index = Math.floor(durations.length * 0.95);
        const p95Duration = durations.length > 0 ? durations[p95Index] || maxDuration : 0;
        
        // Calculate operations per minute
        const uptimeMinutes = (Date.now() - this.startTime) / 60000;
        const operationsPerMinute = uptimeMinutes > 0 ? totalOperations / uptimeMinutes : 0;

        return {
            totalOperations,
            successfulOperations,
            failedOperations,
            averageDuration,
            minDuration,
            maxDuration,
            p95Duration,
            operationsPerMinute,
            currentQueueSize: this.queueStats.currentSize,
            peakQueueSize: this.queueStats.peakSize,
            memoryUsage: this.getMemoryUsage(),
            uptime: Date.now() - this.startTime
        };
    }

    /**
     * Gets queue statistics.
     * 
     * @returns Queue statistics
     */
    public getQueueStats(): QueueStats {
        return { ...this.queueStats };
    }

    /**
     * Gets metrics for a specific operation type.
     * 
     * @param operationType The operation type to filter by
     * @returns Filtered metrics
     */
    public getMetricsByType(operationType: OperationMetrics['operationType']): OperationMetrics[] {
        return this.metrics.filter(m => m.operationType === operationType);
    }

    /**
     * Gets metrics within a time range.
     * 
     * @param startTime Start of time range
     * @param endTime End of time range
     * @returns Filtered metrics
     */
    public getMetricsByTimeRange(startTime: number, endTime: number): OperationMetrics[] {
        return this.metrics.filter(m => m.startTime >= startTime && m.startTime <= endTime);
    }

    /**
     * Checks if the system is currently idle.
     * 
     * @returns true if idle
     */
    public isSystemIdle(): boolean {
        return this.isIdle;
    }

    /**
     * Gets the time since last activity.
     * 
     * @returns Time in milliseconds
     */
    public getTimeSinceLastActivity(): number {
        return Date.now() - this.lastActivityTime;
    }

    /**
     * Gets the number of active operations.
     * 
     * @returns Number of active operations
     */
    public getActiveOperationCount(): number {
        return this.activeOperations.size;
    }

    /**
     * Checks if queue can accept more requests.
     * Requirements: 6.4
     * 
     * @returns true if queue has capacity
     */
    public canAcceptRequest(): boolean {
        return this.queueStats.currentSize < this.config.maxQueueSize;
    }

    /**
     * Gets the current queue capacity percentage.
     * 
     * @returns Percentage of queue capacity used (0-100)
     */
    public getQueueCapacityPercent(): number {
        return (this.queueStats.currentSize / this.config.maxQueueSize) * 100;
    }

    /**
     * Trims metrics to reduce memory usage.
     * 
     * @param keepCount Number of metrics to keep (defaults to retention count)
     */
    private trimMetrics(keepCount?: number): void {
        const count = keepCount ?? this.config.metricsRetentionCount;
        
        if (this.metrics.length > count) {
            this.metrics = this.metrics.slice(-count);
        }
    }

    /**
     * Generates a unique operation ID.
     */
    private generateOperationId(): string {
        this.operationCounter++;
        return `op_${Date.now()}_${this.operationCounter}`;
    }

    /**
     * Logs a message to the output channel.
     */
    private log(message: string): void {
        this.outputChannel.appendLine(`[${new Date().toISOString()}] ${message}`);
    }

    /**
     * Shows the performance output channel.
     */
    public showOutputChannel(): void {
        this.outputChannel.show();
    }

    /**
     * Exports performance report as JSON.
     * 
     * @returns JSON string of performance data
     */
    public exportReport(): string {
        return JSON.stringify({
            stats: this.getPerformanceStats(),
            queueStats: this.getQueueStats(),
            recentMetrics: this.metrics.slice(-100),
            config: this.config,
            exportTime: new Date().toISOString()
        }, null, 2);
    }

    /**
     * Resets all metrics and statistics.
     */
    public reset(): void {
        this.metrics = [];
        this.activeOperations.clear();
        this.queueStats = {
            currentSize: 0,
            peakSize: 0,
            totalProcessed: 0,
            averageWaitTime: 0,
            droppedRequests: 0
        };
        this.startTime = Date.now();
        this.operationCounter = 0;
        
        this.log('Performance metrics reset');
    }

    /**
     * Updates the configuration.
     * 
     * @param config Partial configuration to update
     */
    public updateConfig(config: Partial<ResourceMonitorConfig>): void {
        this.config = { ...this.config, ...config };
        
        // Restart idle monitoring with new interval if changed
        if (config.idleCheckIntervalMs !== undefined) {
            this.stopIdleMonitoring();
            this.startIdleMonitoring();
        }
    }

    /**
     * Gets the current configuration.
     */
    public getConfig(): ResourceMonitorConfig {
        return { ...this.config };
    }

    /**
     * Stops idle monitoring.
     */
    private stopIdleMonitoring(): void {
        if (this.idleCheckTimer) {
            clearInterval(this.idleCheckTimer);
            this.idleCheckTimer = undefined;
        }
    }

    /**
     * Performs cleanup during extension deactivation.
     * Requirements: 6.5 - Optimize memory usage during deactivation
     */
    public performDeactivationCleanup(): void {
        this.log('Performing deactivation cleanup...');
        
        // Clear all metrics
        this.metrics = [];
        this.activeOperations.clear();
        
        // Log final statistics before cleanup
        const finalStats = this.getPerformanceStats();
        this.log(`Final stats - Total operations: ${finalStats.totalOperations}, ` +
                 `Success rate: ${((finalStats.successfulOperations / finalStats.totalOperations) * 100 || 0).toFixed(1)}%, ` +
                 `Avg duration: ${finalStats.averageDuration.toFixed(1)}ms`);
        
        this.log('Deactivation cleanup complete');
    }

    /**
     * Disposes of all resources.
     */
    public dispose(): void {
        this.performDeactivationCleanup();
        this.stopIdleMonitoring();
        this.outputChannel.dispose();
        
        for (const disposable of this.disposables) {
            disposable.dispose();
        }
        this.disposables = [];
    }
}
