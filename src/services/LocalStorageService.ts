import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { SecurityEvent, SecurityAnalysis, InterceptedPrompt } from '../types';

/**
 * Configuration for local storage service
 */
export interface LocalStorageConfig {
    maxAuditLogEntries: number;
    maxAnalysisResultEntries: number;
    enablePersistence: boolean;
    rotationThreshold: number;
}

/**
 * Stored analysis result with metadata
 */
export interface StoredAnalysisResult {
    id: string;
    timestamp: Date;
    promptHash: string;
    analysis: SecurityAnalysis;
    decision: 'allow' | 'block' | 'warn';
}

/**
 * LocalStorageService handles secure local storage for analysis results and audit logs.
 * 
 * Responsibilities:
 * - Store analysis results locally
 * - Persist audit logs with rotation
 * - Ensure data integrity for safe prompt pass-through
 * - Never transmit data to external services
 * 
 * Requirements:
 * - 7.3: Store all analysis results locally
 * - 7.4: Pass safe prompts through unchanged
 */
export class LocalStorageService implements vscode.Disposable {
    private config: LocalStorageConfig;
    private auditLog: SecurityEvent[] = [];
    private analysisResults: StoredAnalysisResult[] = [];
    private globalState: vscode.Memento | undefined;
    private readonly AUDIT_LOG_KEY = 'cloak.auditLog';
    private readonly ANALYSIS_RESULTS_KEY = 'cloak.analysisResults';

    constructor(config?: Partial<LocalStorageConfig>) {
        this.config = {
            maxAuditLogEntries: config?.maxAuditLogEntries ?? 1000,
            maxAnalysisResultEntries: config?.maxAnalysisResultEntries ?? 500,
            enablePersistence: config?.enablePersistence ?? true,
            rotationThreshold: config?.rotationThreshold ?? 0.8
        };
    }

    /**
     * Initializes the storage service with VS Code global state.
     * Must be called during extension activation.
     * 
     * @param globalState VS Code extension global state for persistence
     */
    public async initialize(globalState: vscode.Memento): Promise<void> {
        this.globalState = globalState;
        
        if (this.config.enablePersistence) {
            await this.loadPersistedData();
        }
    }


    /**
     * Loads persisted data from VS Code global state.
     */
    private async loadPersistedData(): Promise<void> {
        if (!this.globalState) {
            return;
        }

        try {
            // Load audit log
            const storedAuditLog = this.globalState.get<SecurityEvent[]>(this.AUDIT_LOG_KEY);
            if (storedAuditLog && Array.isArray(storedAuditLog)) {
                this.auditLog = storedAuditLog.map(event => ({
                    ...event,
                    timestamp: new Date(event.timestamp)
                }));
            }

            // Load analysis results
            const storedResults = this.globalState.get<StoredAnalysisResult[]>(this.ANALYSIS_RESULTS_KEY);
            if (storedResults && Array.isArray(storedResults)) {
                this.analysisResults = storedResults.map(result => ({
                    ...result,
                    timestamp: new Date(result.timestamp)
                }));
            }
        } catch (error) {
            console.error('Failed to load persisted data:', error);
            // Reset to empty state on load failure
            this.auditLog = [];
            this.analysisResults = [];
        }
    }

    /**
     * Persists current data to VS Code global state.
     */
    private async persistData(): Promise<void> {
        if (!this.globalState || !this.config.enablePersistence) {
            return;
        }

        try {
            await this.globalState.update(this.AUDIT_LOG_KEY, this.auditLog);
            await this.globalState.update(this.ANALYSIS_RESULTS_KEY, this.analysisResults);
        } catch (error) {
            console.error('Failed to persist data:', error);
        }
    }

    /**
     * Stores a security event in the audit log.
     * Implements rotation when threshold is reached.
     * 
     * Requirements: 7.3
     * 
     * @param event The security event to store
     */
    public async storeSecurityEvent(event: SecurityEvent): Promise<void> {
        this.auditLog.push(event);

        // Check if rotation is needed
        if (this.auditLog.length >= this.config.maxAuditLogEntries * this.config.rotationThreshold) {
            this.rotateAuditLog();
        }

        await this.persistData();
    }

    /**
     * Stores an analysis result locally.
     * 
     * Requirements: 7.3
     * 
     * @param prompt The original intercepted prompt
     * @param analysis The security analysis result
     * @param decision The security decision made
     */
    public async storeAnalysisResult(
        prompt: InterceptedPrompt,
        analysis: SecurityAnalysis,
        decision: 'allow' | 'block' | 'warn'
    ): Promise<StoredAnalysisResult> {
        const result: StoredAnalysisResult = {
            id: this.generateId(),
            timestamp: new Date(),
            promptHash: this.hashContent(prompt.content),
            analysis,
            decision
        };

        this.analysisResults.push(result);

        // Check if rotation is needed
        if (this.analysisResults.length >= this.config.maxAnalysisResultEntries * this.config.rotationThreshold) {
            this.rotateAnalysisResults();
        }

        await this.persistData();
        return result;
    }

    /**
     * Rotates the audit log by removing oldest entries.
     * Keeps the most recent entries up to half the max size.
     */
    private rotateAuditLog(): void {
        const keepCount = Math.floor(this.config.maxAuditLogEntries / 2);
        this.auditLog = this.auditLog.slice(-keepCount);
    }

    /**
     * Rotates analysis results by removing oldest entries.
     * Keeps the most recent entries up to half the max size.
     */
    private rotateAnalysisResults(): void {
        const keepCount = Math.floor(this.config.maxAnalysisResultEntries / 2);
        this.analysisResults = this.analysisResults.slice(-keepCount);
    }


    /**
     * Validates that a prompt passes through unchanged for safe prompts.
     * This ensures data integrity by verifying the prompt content is not modified.
     * 
     * Requirements: 7.4
     * 
     * @param originalPrompt The original intercepted prompt
     * @param passedPrompt The prompt after processing
     * @returns true if the prompt content is unchanged
     */
    public validatePromptIntegrity(
        originalPrompt: InterceptedPrompt,
        passedPrompt: InterceptedPrompt
    ): boolean {
        // Verify content is exactly the same
        if (originalPrompt.content !== passedPrompt.content) {
            return false;
        }

        // Verify hash matches
        const originalHash = this.hashContent(originalPrompt.content);
        const passedHash = this.hashContent(passedPrompt.content);
        
        return originalHash === passedHash;
    }

    /**
     * Creates a verified copy of a prompt for safe pass-through.
     * Ensures the prompt content is preserved exactly.
     * 
     * Requirements: 7.4
     * 
     * @param prompt The prompt to create a verified copy of
     * @returns A new prompt object with verified content integrity
     */
    public createVerifiedPromptCopy(prompt: InterceptedPrompt): InterceptedPrompt & { integrityHash: string } {
        const hash = this.hashContent(prompt.content);
        
        return {
            id: prompt.id,
            content: prompt.content,
            timestamp: prompt.timestamp,
            source: prompt.source,
            metadata: { ...prompt.metadata },
            integrityHash: hash
        };
    }

    /**
     * Verifies the integrity of a prompt using its hash.
     * 
     * Requirements: 7.4
     * 
     * @param prompt The prompt with integrity hash
     * @returns true if the prompt content matches its hash
     */
    public verifyPromptIntegrity(prompt: InterceptedPrompt & { integrityHash: string }): boolean {
        const currentHash = this.hashContent(prompt.content);
        return currentHash === prompt.integrityHash;
    }

    /**
     * Gets all stored audit log entries.
     * 
     * @returns Array of security events
     */
    public getAuditLog(): SecurityEvent[] {
        return [...this.auditLog];
    }

    /**
     * Gets audit log entries filtered by event type.
     * 
     * @param eventType The event type to filter by
     * @returns Filtered array of security events
     */
    public getAuditLogByType(eventType: SecurityEvent['eventType']): SecurityEvent[] {
        return this.auditLog.filter(event => event.eventType === eventType);
    }

    /**
     * Gets audit log entries within a time range.
     * 
     * @param startTime Start of time range
     * @param endTime End of time range
     * @returns Filtered array of security events
     */
    public getAuditLogByTimeRange(startTime: Date, endTime: Date): SecurityEvent[] {
        return this.auditLog.filter(
            event => event.timestamp >= startTime && event.timestamp <= endTime
        );
    }

    /**
     * Gets all stored analysis results.
     * 
     * @returns Array of stored analysis results
     */
    public getAnalysisResults(): StoredAnalysisResult[] {
        return [...this.analysisResults];
    }

    /**
     * Gets analysis results by decision type.
     * 
     * @param decision The decision type to filter by
     * @returns Filtered array of analysis results
     */
    public getAnalysisResultsByDecision(decision: 'allow' | 'block' | 'warn'): StoredAnalysisResult[] {
        return this.analysisResults.filter(result => result.decision === decision);
    }

    /**
     * Gets analysis result by prompt hash.
     * 
     * @param promptHash The hash of the prompt content
     * @returns The matching analysis result or undefined
     */
    public getAnalysisResultByHash(promptHash: string): StoredAnalysisResult | undefined {
        return this.analysisResults.find(result => result.promptHash === promptHash);
    }


    /**
     * Gets statistics from the stored data.
     */
    public getStatistics(): {
        totalAuditEvents: number;
        totalAnalysisResults: number;
        blockedCount: number;
        allowedCount: number;
        warnCount: number;
        oldestAuditEvent: Date | null;
        newestAuditEvent: Date | null;
    } {
        const blockedCount = this.analysisResults.filter(r => r.decision === 'block').length;
        const allowedCount = this.analysisResults.filter(r => r.decision === 'allow').length;
        const warnCount = this.analysisResults.filter(r => r.decision === 'warn').length;

        return {
            totalAuditEvents: this.auditLog.length,
            totalAnalysisResults: this.analysisResults.length,
            blockedCount,
            allowedCount,
            warnCount,
            oldestAuditEvent: this.auditLog.length > 0 ? this.auditLog[0].timestamp : null,
            newestAuditEvent: this.auditLog.length > 0 ? this.auditLog[this.auditLog.length - 1].timestamp : null
        };
    }

    /**
     * Clears all stored audit log entries.
     */
    public async clearAuditLog(): Promise<void> {
        this.auditLog = [];
        await this.persistData();
    }

    /**
     * Clears all stored analysis results.
     */
    public async clearAnalysisResults(): Promise<void> {
        this.analysisResults = [];
        await this.persistData();
    }

    /**
     * Clears all stored data.
     */
    public async clearAll(): Promise<void> {
        this.auditLog = [];
        this.analysisResults = [];
        await this.persistData();
    }

    /**
     * Exports audit log to JSON format.
     * 
     * @returns JSON string of audit log
     */
    public exportAuditLog(): string {
        return JSON.stringify(this.auditLog, null, 2);
    }

    /**
     * Exports analysis results to JSON format.
     * 
     * @returns JSON string of analysis results
     */
    public exportAnalysisResults(): string {
        return JSON.stringify(this.analysisResults, null, 2);
    }

    /**
     * Updates the storage configuration.
     * 
     * @param config Partial configuration to update
     */
    public updateConfig(config: Partial<LocalStorageConfig>): void {
        this.config = { ...this.config, ...config };
    }

    /**
     * Gets the current configuration.
     */
    public getConfig(): LocalStorageConfig {
        return { ...this.config };
    }

    /**
     * Generates a unique ID for stored items.
     */
    private generateId(): string {
        return `store_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    }

    /**
     * Hashes content using SHA-256 for privacy-preserving storage.
     * 
     * @param content The content to hash
     * @returns SHA-256 hash of the content
     */
    private hashContent(content: string): string {
        return crypto.createHash('sha256').update(content).digest('hex');
    }

    /**
     * Disposes of resources and persists final state.
     */
    public dispose(): void {
        // Persist data one final time before disposal
        if (this.config.enablePersistence && this.globalState) {
            this.persistData().catch(error => {
                console.error('Failed to persist data during disposal:', error);
            });
        }
    }
}
