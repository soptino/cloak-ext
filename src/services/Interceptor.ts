import * as vscode from 'vscode';
import { InterceptedPrompt, PromptMetadata } from '../types';
import { PerformanceMonitor } from './PerformanceMonitor';

/**
 * Queued prompt request for async processing
 */
interface QueuedRequest {
    prompt: InterceptedPrompt;
    resolve: (value: InterceptedPrompt) => void;
    reject: (reason: Error) => void;
    queuedAt: number;
}

/**
 * Callback function type for handling intercepted prompts
 */
export type PromptHandler = (prompt: InterceptedPrompt) => Promise<void>;

/**
 * Interceptor component for capturing user prompts via VS Code Chat API.
 * 
 * Requirements:
 * - 1.1: Capture prompts before they reach external services
 * - 1.2: Route captured prompts to Security_Service for analysis
 * - 1.3: Handle multiple prompts asynchronously without blocking UI
 * - 1.4: Support both ChatParticipant API and command wrapper approaches
 * - 6.4: Queue requests efficiently when multiple analyses are requested
 */
export class Interceptor implements vscode.Disposable {
    private disposables: vscode.Disposable[] = [];
    private requestQueue: QueuedRequest[] = [];
    private isProcessing: boolean = false;
    private promptHandler: PromptHandler | undefined;
    private requestCounter: number = 0;
    private sessionId: string;
    private performanceMonitor: PerformanceMonitor | undefined;
    private maxQueueSize: number = 100;

    constructor() {
        this.sessionId = this.generateSessionId();
    }

    /**
     * Sets the performance monitor for queue tracking.
     * Requirements: 6.4 - Efficient queue management
     * 
     * @param monitor The performance monitor instance
     */
    public setPerformanceMonitor(monitor: PerformanceMonitor): void {
        this.performanceMonitor = monitor;
    }

    /**
     * Registers the ChatParticipant with VS Code.
     * Requirements: 1.4 - Support ChatParticipant API
     * 
     * @param context Extension context for subscription management
     * @returns The registered ChatParticipant
     */
    public registerChatParticipant(context: vscode.ExtensionContext): vscode.ChatParticipant {
        const participant = vscode.chat.createChatParticipant(
            'cloak.securityGateway',
            this.handleChatRequest.bind(this)
        );

        participant.iconPath = new vscode.ThemeIcon('shield');
        
        this.disposables.push(participant);
        context.subscriptions.push(participant);

        return participant;
    }

    /**
     * Registers command wrapper for broader compatibility.
     * Requirements: 1.4 - Support command wrapper approach
     * 
     * @param context Extension context for subscription management
     */
    public registerCommandWrapper(context: vscode.ExtensionContext): void {
        const analyzeCommand = vscode.commands.registerCommand(
            'cloak.analyzePrompt',
            this.handleCommandRequest.bind(this)
        );

        this.disposables.push(analyzeCommand);
        context.subscriptions.push(analyzeCommand);
    }

    /**
     * Sets the handler function for intercepted prompts.
     * This handler is called for each intercepted prompt after queuing.
     * 
     * @param handler Function to handle intercepted prompts
     */
    public setPromptHandler(handler: PromptHandler): void {
        this.promptHandler = handler;
    }


    /**
     * Handles incoming chat requests from the ChatParticipant API.
     * Requirements: 1.1, 1.2 - Capture and route prompts
     * 
     * @param request The chat request from VS Code
     * @param context Chat context
     * @param stream Response stream for providing feedback
     * @param token Cancellation token
     */
    private async handleChatRequest(
        request: vscode.ChatRequest,
        _context: vscode.ChatContext,
        stream: vscode.ChatResponseStream,
        token: vscode.CancellationToken
    ): Promise<vscode.ChatResult> {
        // Create intercepted prompt from chat request
        const interceptedPrompt = this.createInterceptedPrompt(
            request.prompt,
            'chat',
            {
                participantId: 'cloak.securityGateway',
                sessionId: this.sessionId
            }
        );

        // Queue the prompt for async processing
        try {
            await this.queuePrompt(interceptedPrompt, token);
            
            // Provide feedback to user
            stream.markdown('🛡️ Prompt analyzed by Cloak Security Gateway');
            
            return { metadata: { intercepted: true, promptId: interceptedPrompt.id } };
        } catch (error) {
            if (error instanceof Error && error.message === 'Cancelled') {
                stream.markdown('⚠️ Security analysis was cancelled');
                return { metadata: { intercepted: false, cancelled: true } };
            }
            
            stream.markdown('❌ Security analysis failed');
            return { 
                metadata: { intercepted: false, error: error instanceof Error ? error.message : 'Unknown error' },
                errorDetails: { message: error instanceof Error ? error.message : 'Unknown error' }
            };
        }
    }

    /**
     * Handles command-based prompt analysis requests.
     * Requirements: 1.4 - Command wrapper for broader compatibility
     * 
     * @param promptText Optional prompt text to analyze
     */
    private async handleCommandRequest(promptText?: string): Promise<InterceptedPrompt | undefined> {
        // If no prompt provided, get from user input
        let content = promptText;
        if (!content) {
            content = await vscode.window.showInputBox({
                prompt: 'Enter the prompt to analyze for security threats',
                placeHolder: 'Type your prompt here...',
                ignoreFocusOut: true
            });
        }

        if (!content) {
            return undefined;
        }

        const interceptedPrompt = this.createInterceptedPrompt(
            content,
            'command',
            {
                commandId: 'cloak.analyzePrompt',
                sessionId: this.sessionId
            }
        );

        // Queue and process the prompt
        try {
            await this.queuePrompt(interceptedPrompt);
            vscode.window.showInformationMessage('🛡️ Prompt analyzed by Cloak Security Gateway');
            return interceptedPrompt;
        } catch (error) {
            vscode.window.showErrorMessage(
                `Security analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`
            );
            return undefined;
        }
    }

    /**
     * Intercepts a chat request and creates an InterceptedPrompt.
     * This is the main entry point for external callers.
     * Requirements: 1.1 - Capture prompts before external service
     * 
     * @param request The chat request to intercept
     * @returns The intercepted prompt
     */
    public async interceptChatRequest(request: { prompt: string; participantId?: string }): Promise<InterceptedPrompt> {
        const interceptedPrompt = this.createInterceptedPrompt(
            request.prompt,
            'chat',
            {
                participantId: request.participantId || 'unknown',
                sessionId: this.sessionId
            }
        );

        return interceptedPrompt;
    }


    /**
     * Creates an InterceptedPrompt from raw content.
     * 
     * @param content The prompt content
     * @param source The source of the prompt (chat or command)
     * @param metadata Additional metadata
     * @returns The created InterceptedPrompt
     */
    private createInterceptedPrompt(
        content: string,
        source: 'chat' | 'command',
        metadata: PromptMetadata
    ): InterceptedPrompt {
        return {
            id: this.generatePromptId(),
            content,
            timestamp: new Date(),
            source,
            metadata
        };
    }

    /**
     * Queues a prompt for async processing.
     * Requirements: 1.3 - Handle multiple prompts asynchronously
     * Requirements: 6.4 - Queue requests efficiently
     * 
     * @param prompt The prompt to queue
     * @param token Optional cancellation token
     * @returns Promise that resolves when the prompt is processed
     */
    private async queuePrompt(
        prompt: InterceptedPrompt,
        token?: vscode.CancellationToken
    ): Promise<InterceptedPrompt> {
        return new Promise((resolve, reject) => {
            // Check for cancellation before queuing
            if (token?.isCancellationRequested) {
                reject(new Error('Cancelled'));
                return;
            }

            // Check queue capacity
            if (this.performanceMonitor && !this.performanceMonitor.canAcceptRequest()) {
                this.performanceMonitor.recordDroppedRequest();
                reject(new Error('Queue capacity exceeded'));
                return;
            }

            if (this.requestQueue.length >= this.maxQueueSize) {
                reject(new Error('Queue capacity exceeded'));
                return;
            }

            // Add to queue with timestamp
            const queuedRequest: QueuedRequest = { 
                prompt, 
                resolve, 
                reject,
                queuedAt: Date.now()
            };
            this.requestQueue.push(queuedRequest);

            // Update performance monitor
            if (this.performanceMonitor) {
                this.performanceMonitor.updateQueueStats(this.requestQueue.length);
            }

            // Set up cancellation listener
            if (token) {
                const cancellationListener = token.onCancellationRequested(() => {
                    const index = this.requestQueue.indexOf(queuedRequest);
                    if (index !== -1) {
                        this.requestQueue.splice(index, 1);
                        if (this.performanceMonitor) {
                            this.performanceMonitor.updateQueueStats(this.requestQueue.length);
                        }
                        reject(new Error('Cancelled'));
                    }
                    cancellationListener.dispose();
                });
            }

            // Start processing if not already running
            this.processQueue();
        });
    }

    /**
     * Processes the request queue asynchronously.
     * Requirements: 1.3 - Handle multiple prompts without blocking UI
     * Requirements: 6.4 - Efficient queue management
     */
    private async processQueue(): Promise<void> {
        // Prevent concurrent queue processing
        if (this.isProcessing) {
            return;
        }

        this.isProcessing = true;

        try {
            while (this.requestQueue.length > 0) {
                const request = this.requestQueue.shift();
                if (!request) {
                    continue;
                }

                // Calculate wait time for metrics
                const waitTime = Date.now() - request.queuedAt;
                
                // Update queue stats
                if (this.performanceMonitor) {
                    this.performanceMonitor.updateQueueStats(this.requestQueue.length);
                    this.performanceMonitor.recordQueueProcessed(waitTime);
                }

                try {
                    // Call the prompt handler if set
                    if (this.promptHandler) {
                        await this.promptHandler(request.prompt);
                    }
                    request.resolve(request.prompt);
                } catch (error) {
                    request.reject(error instanceof Error ? error : new Error(String(error)));
                }
            }
        } finally {
            this.isProcessing = false;
            
            // Final queue stats update
            if (this.performanceMonitor) {
                this.performanceMonitor.updateQueueStats(0);
            }
        }
    }

    /**
     * Gets the current queue length.
     * Useful for monitoring and testing.
     * 
     * @returns Number of prompts in the queue
     */
    public getQueueLength(): number {
        return this.requestQueue.length;
    }

    /**
     * Checks if the interceptor is currently processing requests.
     * 
     * @returns true if processing, false otherwise
     */
    public isCurrentlyProcessing(): boolean {
        return this.isProcessing;
    }

    /**
     * Gets the current session ID.
     * 
     * @returns The session ID
     */
    public getSessionId(): string {
        return this.sessionId;
    }

    /**
     * Generates a unique prompt ID.
     * 
     * @returns Unique prompt ID
     */
    private generatePromptId(): string {
        this.requestCounter++;
        return `prompt-${Date.now()}-${this.requestCounter}`;
    }

    /**
     * Generates a unique session ID.
     * 
     * @returns Unique session ID
     */
    private generateSessionId(): string {
        return `session-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
    }

    /**
     * Disposes of all resources.
     */
    public dispose(): void {
        // Reject any pending requests
        for (const request of this.requestQueue) {
            request.reject(new Error('Interceptor disposed'));
        }
        this.requestQueue = [];

        // Dispose all subscriptions
        for (const disposable of this.disposables) {
            disposable.dispose();
        }
        this.disposables = [];
    }
}
