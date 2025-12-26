import * as vscode from 'vscode';
import { ShieldStatusUI } from './ui/ShieldStatusUI';
import { Interceptor } from './services/Interceptor';
import { SecurityService } from './services/SecurityService';
import { LocalStorageService } from './services/LocalStorageService';
import { Gatekeeper } from './services/Gatekeeper';
import { ConfigurationService } from './services/ConfigurationService';
import { PerformanceMonitor } from './services/PerformanceMonitor';
import { InterceptedPrompt } from './types';

/**
 * Global references for cleanup during deactivation
 */
let shieldStatusUI: ShieldStatusUI | undefined;
let interceptor: Interceptor | undefined;
let securityService: SecurityService | undefined;
let localStorageService: LocalStorageService | undefined;
let gatekeeper: Gatekeeper | undefined;
let configurationService: ConfigurationService | undefined;
let performanceMonitor: PerformanceMonitor | undefined;

/**
 * Output channel for comprehensive logging
 */
let outputChannel: vscode.OutputChannel | undefined;

/**
 * Flag to track if the extension is in degraded mode
 */
let isDegradedMode: boolean = false;

/**
 * Logs a message to the output channel with timestamp
 * @param message The message to log
 * @param level The log level (info, warn, error)
 */
function log(message: string, level: 'info' | 'warn' | 'error' = 'info'): void {
    if (!outputChannel) {
        return;
    }
    const timestamp = new Date().toISOString();
    const prefix = level === 'error' ? '❌' : level === 'warn' ? '⚠️' : 'ℹ️';
    outputChannel.appendLine(`[${timestamp}] ${prefix} ${message}`);
}

/**
 * Extension activation entry point.
 * Called when the extension is activated.
 * 
 * Requirements: 6.3 - Extension shall initialize quickly and not delay VS Code startup
 */
export async function activate(context: vscode.ExtensionContext): Promise<void> {
    // Create output channel for logging first
    outputChannel = vscode.window.createOutputChannel('Cloak Security Gateway');
    context.subscriptions.push(outputChannel);
    
    log('Cloak Security Gateway activation started');
    console.log('Cloak Security Gateway is now active');
    
    try {
        // Initialize the Configuration Service first
        // Requirements: 8.1, 8.2, 8.3, 8.4, 8.5
        configurationService = new ConfigurationService();
        context.subscriptions.push(configurationService);
        log('ConfigurationService initialized');
        
        // Initialize the Performance Monitor
        // Requirements: 6.4, 6.5
        performanceMonitor = new PerformanceMonitor({
            enableDetailedLogging: configurationService.isLoggingEnabled()
        });
        context.subscriptions.push(performanceMonitor);
        log('PerformanceMonitor initialized');
        
        // Initialize the Shield Status UI component
        shieldStatusUI = new ShieldStatusUI();
        context.subscriptions.push(shieldStatusUI);
        log('ShieldStatusUI initialized');
        
        // Set initial status to initializing
        shieldStatusUI.updateStatus({
            state: 'active',
            message: 'Initializing security services...',
            serviceHealth: 'healthy'
        });
        
        // Initialize the Local Storage Service
        // Requirements: 7.3 - Store all analysis results locally
        localStorageService = new LocalStorageService();
        await localStorageService.initialize(context.globalState);
        context.subscriptions.push(localStorageService);
        log('LocalStorageService initialized');
        
        // Initialize the Security Service with configuration
        securityService = new SecurityService(configurationService);
        log('SecurityService initialized');
        
        // Initialize the Gatekeeper with local storage and configuration
        // Requirements: 4.4, 7.3 - Log all security decisions and store locally
        gatekeeper = new Gatekeeper();
        gatekeeper.setLocalStorageService(localStorageService);
        
        // Apply configuration to Gatekeeper
        const thresholds = configurationService.getSensitivityThresholds();
        gatekeeper.updateConfig({
            blockThreshold: thresholds.blockThreshold,
            warnThreshold: thresholds.warnThreshold,
            enableAuditLog: configurationService.isLoggingEnabled()
        });
        context.subscriptions.push(gatekeeper);
        log('Gatekeeper initialized');
        
        // Initialize the Interceptor component
        interceptor = new Interceptor();
        interceptor.setPerformanceMonitor(performanceMonitor);
        context.subscriptions.push(interceptor);
        log('Interceptor initialized');
        
        // Register ChatParticipant for prompt interception
        // Requirements: 1.1, 1.4 - Capture prompts via ChatParticipant API
        interceptor.registerChatParticipant(context);
        log('ChatParticipant registered');
        
        // Register command wrapper for broader compatibility
        // Requirements: 1.4 - Support command wrapper approach
        interceptor.registerCommandWrapper(context);
        log('Command wrapper registered');
        
        // Set up prompt handler to route to SecurityService
        // Requirements: 1.2 - Route captured prompts to Security_Service
        interceptor.setPromptHandler(async (prompt: InterceptedPrompt) => {
            await handlePromptAnalysis(prompt);
        });
        log('Prompt handler configured');
        
        // Register commands
        registerCommands(context);
        log('Commands registered');
        
        // Register configuration change listener for hot reloading
        // Requirements: 8.4 - Apply changes without VS Code restart
        const configChangeDisposable = configurationService.onConfigurationChange((event) => {
            handleConfigurationChange(event.affectedKeys);
        });
        context.subscriptions.push(configChangeDisposable);
        log('Configuration change listener registered');
        
        // Check service health and set initial status
        await checkServiceHealthAndUpdateStatus();
        
        log('Cloak Security Gateway activation completed successfully');
        
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        log(`Activation failed: ${errorMessage}`, 'error');
        
        // Enter degraded mode
        enterDegradedMode(`Activation error: ${errorMessage}`);
        
        // Re-throw to let VS Code know activation failed
        throw error;
    }
}

/**
 * Handles prompt analysis by routing to SecurityService.
 * Updates UI status during analysis and stores results locally.
 * 
 * Requirements: 1.2 - Route prompts to Security_Service for analysis
 * Requirements: 7.3 - Store all analysis results locally
 * Requirements: 7.4 - Pass safe prompts through unchanged
 * Requirements: 6.4 - Efficient queue management with performance tracking
 * 
 * @param prompt The intercepted prompt to analyze
 */
async function handlePromptAnalysis(prompt: InterceptedPrompt): Promise<void> {
    if (!securityService || !shieldStatusUI || !gatekeeper || !localStorageService) {
        log('Cannot analyze prompt: services not initialized', 'error');
        return;
    }
    
    // Check if in degraded mode
    if (isDegradedMode) {
        log('Prompt analysis skipped: system in degraded mode', 'warn');
        await handleDegradedModeAnalysis(prompt);
        return;
    }
    
    log(`Starting analysis for prompt: ${prompt.id}`);
    
    // Start performance tracking
    const operationId = performanceMonitor?.startOperation('analysis');
    
    // Update status to scanning
    shieldStatusUI.updateStatus({
        state: 'scanning',
        message: 'Analyzing prompt...',
        serviceHealth: 'healthy'
    });
    
    try {
        // Analyze the prompt
        const analysis = await securityService.analyzePrompt(prompt);
        log(`Analysis complete for ${prompt.id}: ${analysis.threatLevel} (${(analysis.confidence * 100).toFixed(1)}% confidence)`);
        
        // Track decision operation
        const decisionOpId = performanceMonitor?.startOperation('decision');
        
        // Enforce security policy through Gatekeeper
        const decision = await gatekeeper.enforceSecurityPolicy(analysis, prompt);
        log(`Security decision for ${prompt.id}: ${decision.action}`);
        
        // End decision tracking
        if (decisionOpId) {
            performanceMonitor?.endOperation(decisionOpId, true);
        }
        
        // Track storage operation
        const storageOpId = performanceMonitor?.startOperation('storage');
        
        // Store analysis result locally
        // Requirements: 7.3 - Store all analysis results locally
        await localStorageService.storeAnalysisResult(prompt, analysis, decision.action);
        
        // End storage tracking
        if (storageOpId) {
            performanceMonitor?.endOperation(storageOpId, true);
        }
        
        // Update status based on analysis result
        updateStatusFromAnalysis(analysis);
        
        // End analysis tracking (success)
        if (operationId) {
            performanceMonitor?.endOperation(operationId, true);
        }
    } catch (error) {
        // End analysis tracking (failure)
        if (operationId) {
            performanceMonitor?.endOperation(operationId, false);
        }
        
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        log(`Analysis failed for ${prompt.id}: ${errorMessage}`, 'error');
        
        // Handle analysis errors with graceful degradation
        await handleAnalysisError(error, prompt);
    }
}

/**
 * Updates the shield status based on analysis results.
 * 
 * @param analysis The security analysis result
 */
function updateStatusFromAnalysis(analysis: import('./types').SecurityAnalysis): void {
    if (!shieldStatusUI) {
        return;
    }
    
    if (analysis.threatLevel === 'dangerous') {
        shieldStatusUI.updateStatus({
            state: 'error',
            message: `Threat detected: ${analysis.reasoning}`,
            lastAnalysis: new Date(),
            serviceHealth: 'healthy'
        });
    } else if (analysis.threatLevel === 'suspicious') {
        shieldStatusUI.updateStatus({
            state: 'active',
            message: `Suspicious activity: ${analysis.reasoning}`,
            lastAnalysis: new Date(),
            serviceHealth: 'healthy'
        });
    } else {
        shieldStatusUI.updateStatus({
            state: 'active',
            message: 'Security monitoring active',
            lastAnalysis: new Date(),
            serviceHealth: 'healthy'
        });
    }
}

/**
 * Handles analysis errors with graceful degradation.
 * 
 * @param error The error that occurred
 * @param prompt The prompt that was being analyzed
 */
async function handleAnalysisError(error: unknown, prompt: InterceptedPrompt): Promise<void> {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    
    // Check if this is a service connectivity issue
    const isServiceError = errorMessage.includes('ECONNREFUSED') || 
                          errorMessage.includes('ETIMEDOUT') ||
                          errorMessage.includes('unavailable');
    
    if (isServiceError) {
        // Enter degraded mode for service failures
        enterDegradedMode(errorMessage);
        
        // Handle the prompt in degraded mode
        await handleDegradedModeAnalysis(prompt);
    } else {
        // For other errors, just update status
        shieldStatusUI?.updateStatus({
            state: 'error',
            message: errorMessage,
            serviceHealth: 'degraded'
        });
    }
}

/**
 * Handles prompt analysis when in degraded mode.
 * Uses local pattern detection only.
 * 
 * @param prompt The prompt to analyze
 */
async function handleDegradedModeAnalysis(prompt: InterceptedPrompt): Promise<void> {
    if (!securityService || !gatekeeper || !localStorageService || !shieldStatusUI) {
        return;
    }
    
    log(`Degraded mode analysis for ${prompt.id}`, 'warn');
    
    // Use local pattern detection only
    const localDetection = securityService.detectThreatPatterns(prompt.content);
    
    // Create a minimal analysis result
    const analysis: import('./types').SecurityAnalysis = {
        threatLevel: localDetection.suggestedThreatLevel,
        confidence: localDetection.hasThreats ? 0.6 : 0.3, // Lower confidence in degraded mode
        detectedPatterns: localDetection.detectedPatterns,
        reasoning: 'Local pattern detection only (SLM unavailable)',
        processingTime: 0
    };
    
    // Enforce security policy
    const decision = await gatekeeper.enforceSecurityPolicy(analysis, prompt);
    
    // Store result
    await localStorageService.storeAnalysisResult(prompt, analysis, decision.action);
    
    // Update status
    shieldStatusUI.updateStatus({
        state: 'active',
        message: 'Degraded mode: local detection only',
        lastAnalysis: new Date(),
        serviceHealth: 'degraded'
    });
}

/**
 * Enters degraded mode when the security service is unavailable.
 * 
 * @param reason The reason for entering degraded mode
 */
function enterDegradedMode(reason: string): void {
    if (isDegradedMode) {
        return; // Already in degraded mode
    }
    
    isDegradedMode = true;
    log(`Entering degraded mode: ${reason}`, 'warn');
    
    shieldStatusUI?.updateStatus({
        state: 'error',
        message: `Service unavailable: ${reason}`,
        serviceHealth: 'unavailable'
    });
    
    // Show notification to user
    vscode.window.showWarningMessage(
        `🛡️ Cloak: Security service unavailable. Operating in degraded mode with local pattern detection only.`,
        'Retry Connection',
        'View Details'
    ).then(selection => {
        if (selection === 'Retry Connection') {
            checkServiceHealthAndUpdateStatus();
        } else if (selection === 'View Details') {
            outputChannel?.show();
        }
    });
}

/**
 * Exits degraded mode when the service becomes available.
 */
function exitDegradedMode(): void {
    if (!isDegradedMode) {
        return;
    }
    
    isDegradedMode = false;
    log('Exiting degraded mode: service restored');
    
    shieldStatusUI?.updateStatus({
        state: 'active',
        message: 'Security monitoring active',
        serviceHealth: 'healthy'
    });
    
    vscode.window.showInformationMessage('🛡️ Cloak: Security service restored. Full protection active.');
}

/**
 * Checks service health and updates status accordingly.
 */
async function checkServiceHealthAndUpdateStatus(): Promise<void> {
    if (!securityService || !shieldStatusUI) {
        return;
    }
    
    log('Checking security service health...');
    
    try {
        const isAvailable = await securityService.isServiceAvailable();
        
        if (isAvailable) {
            log('Security service is healthy');
            
            if (isDegradedMode) {
                exitDegradedMode();
            } else {
                shieldStatusUI.updateStatus({
                    state: 'active',
                    message: 'Security monitoring active',
                    serviceHealth: 'healthy'
                });
            }
        } else {
            log('Security service is unavailable', 'warn');
            enterDegradedMode('Ollama service not responding');
        }
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        log(`Health check failed: ${errorMessage}`, 'error');
        enterDegradedMode(errorMessage);
    }
}

/**
 * Registers all extension commands.
 * 
 * @param context Extension context for subscription management
 */
function registerCommands(context: vscode.ExtensionContext): void {
    // Register the show status command
    const showStatusCommand = vscode.commands.registerCommand('cloak.showStatus', () => {
        shieldStatusUI?.showStatusDetails();
    });
    context.subscriptions.push(showStatusCommand);
    
    // Register the show performance stats command
    const showPerformanceCommand = vscode.commands.registerCommand('cloak.showPerformance', () => {
        if (performanceMonitor) {
            performanceMonitor.showOutputChannel();
            const stats = performanceMonitor.getPerformanceStats();
            vscode.window.showInformationMessage(
                `🛡️ Cloak Performance: ${stats.totalOperations} ops, ` +
                `${stats.averageDuration.toFixed(0)}ms avg, ` +
                `${stats.memoryUsage.percentUsed.toFixed(1)}% memory`
            );
        }
    });
    context.subscriptions.push(showPerformanceCommand);
    
    // Register the check service health command
    const checkHealthCommand = vscode.commands.registerCommand('cloak.checkServiceHealth', async () => {
        await checkServiceHealthAndUpdateStatus();
    });
    context.subscriptions.push(checkHealthCommand);
    
    // Register the show logs command
    const showLogsCommand = vscode.commands.registerCommand('cloak.showLogs', () => {
        outputChannel?.show();
    });
    context.subscriptions.push(showLogsCommand);
    
    // Register the show audit log command
    const showAuditCommand = vscode.commands.registerCommand('cloak.showAuditLog', () => {
        if (localStorageService) {
            const stats = localStorageService.getStatistics();
            const auditLog = localStorageService.exportAuditLog();
            
            // Create a new document with the audit log
            vscode.workspace.openTextDocument({
                content: `Cloak Security Audit Log\n` +
                        `========================\n\n` +
                        `Statistics:\n` +
                        `- Total Events: ${stats.totalAuditEvents}\n` +
                        `- Analysis Results: ${stats.totalAnalysisResults}\n` +
                        `- Blocked: ${stats.blockedCount}\n` +
                        `- Allowed: ${stats.allowedCount}\n` +
                        `- Warned: ${stats.warnCount}\n\n` +
                        `Audit Log:\n${auditLog}`,
                language: 'json'
            }).then(doc => {
                vscode.window.showTextDocument(doc);
            });
        }
    });
    context.subscriptions.push(showAuditCommand);
    
    // Register the test endpoint connectivity command
    const testConnectivityCommand = vscode.commands.registerCommand('cloak.testConnectivity', async () => {
        if (configurationService) {
            const result = await configurationService.testEndpointConnectivity();
            if (result.success) {
                vscode.window.showInformationMessage(`🛡️ Cloak: ${result.message}`);
                if (isDegradedMode) {
                    exitDegradedMode();
                }
            } else {
                vscode.window.showErrorMessage(`🛡️ Cloak: ${result.message}`);
            }
        }
    });
    context.subscriptions.push(testConnectivityCommand);

    // Register the open settings command
    const openSettingsCommand = vscode.commands.registerCommand('cloak.openSettings', () => {
        vscode.commands.executeCommand('workbench.action.openSettings', '@ext:cloak-security.cloak-security-gateway');
    });
    context.subscriptions.push(openSettingsCommand);
}

/**
 * Handles configuration changes and updates services accordingly.
 * Requirements: 8.4 - Apply changes without VS Code restart
 * 
 * @param affectedKeys The configuration keys that changed
 */
function handleConfigurationChange(affectedKeys: string[]): void {
    if (!configurationService) {
        return;
    }
    
    // Update SecurityService if endpoint, timeout, or system prompt changed
    if (affectedKeys.includes('ollamaEndpoint') || 
        affectedKeys.includes('timeout') || 
        affectedKeys.includes('systemPrompt')) {
        if (securityService) {
            securityService.updateEndpoint(configurationService.getOllamaEndpoint());
            securityService.updateSystemPrompt(configurationService.getSystemPrompt());
            securityService.updateTimeout(configurationService.getTimeout());
        }
    }
    
    // Update Gatekeeper if threat sensitivity or logging changed
    if (affectedKeys.includes('threatSensitivity') || affectedKeys.includes('enableLogging')) {
        if (gatekeeper) {
            const thresholds = configurationService.getSensitivityThresholds();
            gatekeeper.updateConfig({
                blockThreshold: thresholds.blockThreshold,
                warnThreshold: thresholds.warnThreshold,
                enableAuditLog: configurationService.isLoggingEnabled()
            });
        }
    }
    
    // Update status UI to reflect configuration state
    if (shieldStatusUI) {
        shieldStatusUI.updateStatus({
            state: 'active',
            message: 'Configuration updated',
            serviceHealth: 'healthy'
        });
    }
}

/**
 * Extension deactivation entry point.
 * Called when the extension is deactivated.
 * Performs cleanup of all resources.
 * 
 * Requirements: 6.5 - Optimize memory usage and cleanup during deactivation
 */
export function deactivate(): void {
    log('Cloak Security Gateway deactivation started');
    console.log('Cloak Security Gateway has been deactivated');
    
    // Perform performance monitor cleanup first to log final stats
    if (performanceMonitor) {
        const finalStats = performanceMonitor.getPerformanceStats();
        log(`Final performance stats: ${finalStats.totalOperations} total operations, ` +
            `${finalStats.successfulOperations} successful, ` +
            `${finalStats.averageDuration.toFixed(1)}ms avg duration`);
        performanceMonitor.performDeactivationCleanup();
    }
    
    // Log storage statistics before cleanup
    if (localStorageService) {
        const storageStats = localStorageService.getStatistics();
        log(`Storage stats: ${storageStats.totalAuditEvents} audit events, ` +
            `${storageStats.totalAnalysisResults} analysis results`);
    }
    
    // Log gatekeeper statistics before cleanup
    if (gatekeeper) {
        const auditStats = gatekeeper.getAuditStatistics();
        log(`Gatekeeper stats: ${auditStats.blockedCount} blocked, ` +
            `${auditStats.allowedCount} allowed, ` +
            `${auditStats.overrideCount} overrides`);
    }
    
    log('Cloak Security Gateway deactivation completed');
    
    // Cleanup is handled by VS Code's subscription disposal mechanism
    // The ShieldStatusUI, Interceptor, Gatekeeper, LocalStorageService,
    // ConfigurationService, and PerformanceMonitor dispose() methods will be called automatically
    shieldStatusUI = undefined;
    interceptor = undefined;
    securityService = undefined;
    localStorageService = undefined;
    gatekeeper = undefined;
    configurationService = undefined;
    performanceMonitor = undefined;
    outputChannel = undefined;
    isDegradedMode = false;
}
