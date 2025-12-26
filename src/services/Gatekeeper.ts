import * as vscode from 'vscode';
import * as crypto from 'crypto';
import {
    SecurityAnalysis,
    InterceptedPrompt,
    SecurityDecision,
    SecurityEvent
} from '../types';
import { LocalStorageService } from './LocalStorageService';

/**
 * Configuration for the Gatekeeper component
 */
export interface GatekeeperConfig {
    blockThreshold: number;
    warnThreshold: number;
    enableUserOverride: boolean;
    enableAuditLog: boolean;
}

/**
 * Gatekeeper component for security decision enforcement.
 * 
 * Responsibilities:
 * - Make security decisions based on analysis results
 * - Block dangerous requests with user notifications
 * - Allow safe requests to proceed unchanged
 * - Maintain audit logs for security decisions
 * 
 * Requirements:
 * - 4.1: Block dangerous prompts from proceeding to external services
 * - 4.2: Display VS Code Warning Notification for blocked requests
 * - 4.3: Allow safe prompts to proceed to intended destination
 * - 4.4: Log all security decisions for audit purposes
 * - 4.5: Provide user override mechanism with explicit confirmation
 */
export class Gatekeeper implements vscode.Disposable {
    private config: GatekeeperConfig;
    private auditLog: SecurityEvent[] = [];
    private readonly maxAuditLogSize: number = 1000;
    private outputChannel: vscode.OutputChannel;
    private localStorageService: LocalStorageService | undefined;

    constructor(config?: Partial<GatekeeperConfig>) {
        const vsConfig = vscode.workspace.getConfiguration('cloak');
        
        this.config = {
            blockThreshold: config?.blockThreshold ?? 0.7,
            warnThreshold: config?.warnThreshold ?? 0.5,
            enableUserOverride: config?.enableUserOverride ?? true,
            enableAuditLog: config?.enableAuditLog ?? vsConfig.get<boolean>('enableLogging', true)
        };

        this.outputChannel = vscode.window.createOutputChannel('Cloak Security');
    }

    /**
     * Sets the local storage service for persistent audit logging.
     * 
     * Requirements: 7.3
     * 
     * @param storageService The local storage service instance
     */
    public setLocalStorageService(storageService: LocalStorageService): void {
        this.localStorageService = storageService;
    }

    /**
     * Enforces security policy based on analysis results.
     * Makes a decision to allow, block, or warn based on threat level.
     * 
     * Requirements: 4.1, 4.3
     * 
     * @param analysis Security analysis result from SecurityService
     * @param prompt The original intercepted prompt
     * @returns Security decision with action and reason
     */
    public async enforceSecurityPolicy(
        analysis: SecurityAnalysis,
        prompt: InterceptedPrompt
    ): Promise<SecurityDecision> {
        const decision = this.makeDecision(analysis, prompt);
        
        // Log the security event
        this.logSecurityEvent({
            id: this.generateEventId(),
            timestamp: new Date(),
            eventType: this.mapDecisionToEventType(decision.action),
            promptHash: this.hashPrompt(prompt.content),
            threatLevel: analysis.threatLevel,
            confidence: analysis.confidence,
            decision: decision.action,
            processingTime: analysis.processingTime
        });

        // Notify user based on decision
        await this.notifyUser(decision);

        return decision;
    }


    /**
     * Makes a security decision based on threat level and confidence.
     * 
     * Requirements: 4.1, 4.3
     * 
     * @param analysis Security analysis result
     * @param prompt Original intercepted prompt
     * @returns Security decision
     */
    private makeDecision(
        analysis: SecurityAnalysis,
        prompt: InterceptedPrompt
    ): SecurityDecision {
        const { threatLevel, confidence, reasoning, detectedPatterns } = analysis;

        // Dangerous threats with high confidence should be blocked
        if (threatLevel === 'dangerous' && confidence >= this.config.blockThreshold) {
            return {
                action: 'block',
                reason: this.buildBlockReason(reasoning, detectedPatterns),
                originalPrompt: prompt,
                analysis
            };
        }

        // Dangerous threats with lower confidence or suspicious threats should warn
        if (threatLevel === 'dangerous' || 
            (threatLevel === 'suspicious' && confidence >= this.config.warnThreshold)) {
            return {
                action: 'warn',
                reason: this.buildWarnReason(reasoning, detectedPatterns),
                originalPrompt: prompt,
                analysis
            };
        }

        // Safe prompts are allowed
        return {
            action: 'allow',
            reason: 'Prompt passed security analysis',
            originalPrompt: prompt,
            analysis
        };
    }

    /**
     * Builds a detailed reason message for blocked requests.
     */
    private buildBlockReason(reasoning: string, patterns: SecurityAnalysis['detectedPatterns']): string {
        const patternTypes = [...new Set(patterns.map(p => p.type))];
        const patternSummary = patternTypes.length > 0 
            ? `Detected patterns: ${patternTypes.join(', ')}. ` 
            : '';
        return `${patternSummary}${reasoning}`;
    }

    /**
     * Builds a detailed reason message for warned requests.
     */
    private buildWarnReason(reasoning: string, patterns: SecurityAnalysis['detectedPatterns']): string {
        const patternTypes = [...new Set(patterns.map(p => p.type))];
        const patternSummary = patternTypes.length > 0 
            ? `Suspicious patterns: ${patternTypes.join(', ')}. ` 
            : '';
        return `${patternSummary}${reasoning}`;
    }

    /**
     * Notifies the user about security decisions via VS Code notifications.
     * 
     * Requirements: 4.2
     * 
     * @param decision The security decision to notify about
     */
    public async notifyUser(decision: SecurityDecision): Promise<void> {
        switch (decision.action) {
            case 'block':
                await this.showBlockNotification(decision);
                break;
            case 'warn':
                await this.showWarnNotification(decision);
                break;
            case 'allow':
                // No notification for allowed prompts
                break;
        }
    }

    /**
     * Shows a warning notification for blocked requests.
     * Includes option for user override if enabled.
     * 
     * Requirements: 4.2, 4.5
     */
    private async showBlockNotification(decision: SecurityDecision): Promise<void> {
        const message = `🛡️ Cloak: Request blocked - ${decision.reason}`;
        
        if (this.config.enableUserOverride) {
            const selection = await vscode.window.showWarningMessage(
                message,
                { modal: false },
                'View Details',
                'Override (Proceed Anyway)'
            );

            if (selection === 'View Details') {
                this.showDecisionDetails(decision);
            } else if (selection === 'Override (Proceed Anyway)') {
                await this.handleUserOverride(decision);
            }
        } else {
            await vscode.window.showWarningMessage(message, 'View Details')
                .then(selection => {
                    if (selection === 'View Details') {
                        this.showDecisionDetails(decision);
                    }
                });
        }
    }

    /**
     * Shows an information notification for warned requests.
     * 
     * Requirements: 4.2
     */
    private async showWarnNotification(decision: SecurityDecision): Promise<void> {
        const message = `🛡️ Cloak: Suspicious activity detected - ${decision.reason}`;
        
        const selection = await vscode.window.showInformationMessage(
            message,
            'View Details',
            'Dismiss'
        );

        if (selection === 'View Details') {
            this.showDecisionDetails(decision);
        }
    }

    /**
     * Shows detailed information about a security decision in the output channel.
     */
    private showDecisionDetails(decision: SecurityDecision): void {
        this.outputChannel.clear();
        this.outputChannel.appendLine('═══════════════════════════════════════════════════════════');
        this.outputChannel.appendLine('                    SECURITY DECISION DETAILS');
        this.outputChannel.appendLine('═══════════════════════════════════════════════════════════');
        this.outputChannel.appendLine('');
        this.outputChannel.appendLine(`Action: ${decision.action.toUpperCase()}`);
        this.outputChannel.appendLine(`Reason: ${decision.reason}`);
        this.outputChannel.appendLine('');
        this.outputChannel.appendLine('─── Analysis Results ───');
        this.outputChannel.appendLine(`Threat Level: ${decision.analysis.threatLevel}`);
        this.outputChannel.appendLine(`Confidence: ${(decision.analysis.confidence * 100).toFixed(1)}%`);
        this.outputChannel.appendLine(`Processing Time: ${decision.analysis.processingTime}ms`);
        this.outputChannel.appendLine('');
        
        if (decision.analysis.detectedPatterns.length > 0) {
            this.outputChannel.appendLine('─── Detected Patterns ───');
            for (const pattern of decision.analysis.detectedPatterns) {
                this.outputChannel.appendLine(`  • Type: ${pattern.type}`);
                this.outputChannel.appendLine(`    Severity: ${pattern.severity}`);
                this.outputChannel.appendLine(`    Pattern: ${pattern.pattern}`);
                this.outputChannel.appendLine(`    Description: ${pattern.description}`);
                this.outputChannel.appendLine('');
            }
        }

        this.outputChannel.appendLine('─── Reasoning ───');
        this.outputChannel.appendLine(decision.analysis.reasoning);
        this.outputChannel.appendLine('');
        this.outputChannel.appendLine('═══════════════════════════════════════════════════════════');
        this.outputChannel.show();
    }


    /**
     * Handles user override for blocked requests.
     * Requires explicit confirmation before proceeding.
     * 
     * Requirements: 4.5
     * 
     * @param decision The original security decision
     * @returns Updated decision with override flag if confirmed
     */
    public async handleUserOverride(decision: SecurityDecision): Promise<SecurityDecision | null> {
        // Show explicit confirmation dialog
        const confirmation = await vscode.window.showWarningMessage(
            '⚠️ Security Override Confirmation\n\n' +
            'You are about to override a security block. This prompt was flagged as potentially dangerous.\n\n' +
            `Threat Level: ${decision.analysis.threatLevel}\n` +
            `Reason: ${decision.reason}\n\n` +
            'Are you sure you want to proceed?',
            { modal: true },
            'Yes, I understand the risks',
            'Cancel'
        );

        if (confirmation === 'Yes, I understand the risks') {
            // Log the override event
            this.logSecurityEvent({
                id: this.generateEventId(),
                timestamp: new Date(),
                eventType: 'override',
                promptHash: this.hashPrompt(decision.originalPrompt.content),
                threatLevel: decision.analysis.threatLevel,
                confidence: decision.analysis.confidence,
                decision: 'allow',
                userOverride: true,
                processingTime: decision.analysis.processingTime
            });

            // Return updated decision with override flag
            const overriddenDecision: SecurityDecision = {
                ...decision,
                action: 'allow',
                userOverride: true,
                reason: `User override: ${decision.reason}`
            };

            vscode.window.showInformationMessage(
                '🛡️ Cloak: Security override applied. Proceeding with caution.'
            );

            return overriddenDecision;
        }

        return null;
    }

    /**
     * Logs a security event for audit purposes.
     * Persists to both in-memory log and local storage.
     * 
     * Requirements: 4.4, 7.3
     * 
     * @param event The security event to log
     */
    public logSecurityEvent(event: SecurityEvent): void {
        if (!this.config.enableAuditLog) {
            return;
        }

        // Add to in-memory audit log
        this.auditLog.push(event);

        // Rotate log if it exceeds max size
        if (this.auditLog.length > this.maxAuditLogSize) {
            this.auditLog = this.auditLog.slice(-this.maxAuditLogSize);
        }

        // Persist to local storage if available
        if (this.localStorageService) {
            this.localStorageService.storeSecurityEvent(event).catch(error => {
                console.error('Failed to persist security event:', error);
            });
        }

        // Log to output channel for debugging
        this.outputChannel.appendLine(
            `[${event.timestamp.toISOString()}] ${event.eventType.toUpperCase()}: ` +
            `${event.threatLevel} (${(event.confidence * 100).toFixed(1)}% confidence) - ` +
            `Decision: ${event.decision}${event.userOverride ? ' (USER OVERRIDE)' : ''}`
        );
    }

    /**
     * Gets the audit log for review.
     * 
     * @returns Array of security events
     */
    public getAuditLog(): SecurityEvent[] {
        return [...this.auditLog];
    }

    /**
     * Clears the audit log.
     */
    public clearAuditLog(): void {
        this.auditLog = [];
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
     * Gets statistics from the audit log.
     */
    public getAuditStatistics(): {
        totalEvents: number;
        blockedCount: number;
        allowedCount: number;
        overrideCount: number;
        warnCount: number;
        errorCount: number;
    } {
        return {
            totalEvents: this.auditLog.length,
            blockedCount: this.auditLog.filter(e => e.eventType === 'block').length,
            allowedCount: this.auditLog.filter(e => e.eventType === 'allow').length,
            overrideCount: this.auditLog.filter(e => e.eventType === 'override').length,
            warnCount: this.auditLog.filter(e => e.decision === 'warn').length,
            errorCount: this.auditLog.filter(e => e.eventType === 'error').length
        };
    }

    /**
     * Maps a decision action to an event type.
     */
    private mapDecisionToEventType(action: SecurityDecision['action']): SecurityEvent['eventType'] {
        switch (action) {
            case 'block':
                return 'block';
            case 'allow':
                return 'allow';
            case 'warn':
                return 'analysis'; // Warn is logged as analysis since it doesn't block
            default:
                return 'analysis';
        }
    }

    /**
     * Generates a unique event ID.
     */
    private generateEventId(): string {
        return `evt_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    }

    /**
     * Hashes prompt content for privacy-preserving logging.
     * 
     * @param content The prompt content to hash
     * @returns SHA-256 hash of the content
     */
    private hashPrompt(content: string): string {
        return crypto.createHash('sha256').update(content).digest('hex');
    }

    /**
     * Updates the Gatekeeper configuration.
     * 
     * @param config Partial configuration to update
     */
    public updateConfig(config: Partial<GatekeeperConfig>): void {
        this.config = { ...this.config, ...config };
    }

    /**
     * Gets the current configuration.
     */
    public getConfig(): GatekeeperConfig {
        return { ...this.config };
    }

    /**
     * Disposes of resources.
     */
    public dispose(): void {
        this.outputChannel.dispose();
        this.auditLog = [];
    }
}
