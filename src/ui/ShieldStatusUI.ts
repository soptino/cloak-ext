import * as vscode from 'vscode';
import { ShieldStatus } from '../types';

/**
 * ShieldStatusUI manages the StatusBar item that displays the current security status.
 * 
 * Requirements:
 * - 5.1: Display a StatusBar item showing the current Shield_Status
 * - 5.2: Display "Active" when actively monitoring
 * - 5.3: Display "Scanning" when analyzing a prompt
 * - 5.4: Display error state when Ollama service is unavailable
 * - 5.5: Provide additional information when clicked
 */
export class ShieldStatusUI implements vscode.Disposable {
    private statusBarItem: vscode.StatusBarItem;
    private currentStatus: ShieldStatus;

    constructor() {
        // Create StatusBar item on the left side with high priority
        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Left,
            100
        );
        
        // Set command to execute when clicked
        this.statusBarItem.command = 'cloak.showStatus';
        
        // Initialize with default status
        this.currentStatus = {
            state: 'active',
            message: 'Initializing...',
            serviceHealth: 'healthy'
        };
        
        this.render();
        this.statusBarItem.show();
    }

    /**
     * Updates the shield status and refreshes the UI.
     * @param status The new shield status to display
     */
    public updateStatus(status: ShieldStatus): void {
        this.currentStatus = status;
        this.render();
    }

    /**
     * Gets the current shield status.
     */
    public getStatus(): ShieldStatus {
        return this.currentStatus;
    }

    /**
     * Shows a quick pick menu with Cloak commands.
     * Requirement 5.5: Provide additional information when clicked
     */
    public showStatusDetails(): void {
        const statusLine = this.buildStatusDetails();
        
        const items: vscode.QuickPickItem[] = [
            {
                label: '$(info) Status',
                description: statusLine,
                detail: 'Current security gateway status'
            },
            {
                label: '$(search) Analyze Prompt',
                description: 'Manually analyze a prompt for threats',
                detail: 'cloak.analyzePrompt'
            },
            {
                label: '$(pulse) Performance',
                description: 'View performance statistics',
                detail: 'cloak.showPerformance'
            },
            {
                label: '$(list-unordered) Audit Log',
                description: 'View security audit log',
                detail: 'cloak.showAuditLog'
            },
            {
                label: '$(plug) Test Connectivity',
                description: 'Test Ollama endpoint connection',
                detail: 'cloak.testConnectivity'
            },
            {
                label: '$(gear) Settings',
                description: 'Open Cloak settings',
                detail: 'cloak.openSettings'
            }
        ];

        vscode.window.showQuickPick(items, {
            placeHolder: 'Select a Cloak action',
            title: '🛡️ Cloak Security Gateway'
        }).then(selected => {
            if (selected && selected.detail && selected.detail.startsWith('cloak.')) {
                vscode.commands.executeCommand(selected.detail);
            }
        });
    }

    /**
     * Renders the StatusBar item based on current status.
     */
    private render(): void {
        const { icon, text, tooltip, backgroundColor } = this.getDisplayProperties();
        
        this.statusBarItem.text = `${icon} ${text}`;
        this.statusBarItem.tooltip = tooltip;
        this.statusBarItem.backgroundColor = backgroundColor;
    }

    /**
     * Gets display properties based on current status state.
     */
    private getDisplayProperties(): {
        icon: string;
        text: string;
        tooltip: string;
        backgroundColor: vscode.ThemeColor | undefined;
    } {
        switch (this.currentStatus.state) {
            case 'active':
                return {
                    icon: '$(shield)',
                    text: 'Cloak: Active',
                    tooltip: 'Cloak Security Gateway - Monitoring AI interactions',
                    backgroundColor: undefined
                };
            
            case 'scanning':
                return {
                    icon: '$(sync~spin)',
                    text: 'Cloak: Scanning',
                    tooltip: 'Cloak Security Gateway - Analyzing prompt for threats...',
                    backgroundColor: undefined
                };
            
            case 'error':
                return {
                    icon: '$(shield)',
                    text: 'Cloak: Error',
                    tooltip: `Cloak Security Gateway - ${this.currentStatus.message}`,
                    backgroundColor: new vscode.ThemeColor('statusBarItem.errorBackground')
                };
            
            case 'disabled':
                return {
                    icon: '$(shield)',
                    text: 'Cloak: Disabled',
                    tooltip: 'Cloak Security Gateway - Security monitoring disabled',
                    backgroundColor: new vscode.ThemeColor('statusBarItem.warningBackground')
                };
            
            default:
                return {
                    icon: '$(shield)',
                    text: 'Cloak',
                    tooltip: 'Cloak Security Gateway',
                    backgroundColor: undefined
                };
        }
    }

    /**
     * Builds a detailed status message for the information dialog.
     */
    private buildStatusDetails(): string {
        const lines: string[] = [
            `Status: ${this.currentStatus.state.charAt(0).toUpperCase() + this.currentStatus.state.slice(1)}`,
            `Service Health: ${this.currentStatus.serviceHealth}`,
        ];

        if (this.currentStatus.message) {
            lines.push(`Message: ${this.currentStatus.message}`);
        }

        if (this.currentStatus.lastAnalysis) {
            const timeAgo = this.getTimeAgo(this.currentStatus.lastAnalysis);
            lines.push(`Last Analysis: ${timeAgo}`);
        }

        return lines.join(' | ');
    }

    /**
     * Formats a date as a relative time string.
     */
    private getTimeAgo(date: Date): string {
        const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
        
        if (seconds < 60) {
            return 'Just now';
        } else if (seconds < 3600) {
            const minutes = Math.floor(seconds / 60);
            return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
        } else {
            const hours = Math.floor(seconds / 3600);
            return `${hours} hour${hours > 1 ? 's' : ''} ago`;
        }
    }

    /**
     * Disposes of the StatusBar item and cleans up resources.
     */
    public dispose(): void {
        this.statusBarItem.dispose();
    }
}
