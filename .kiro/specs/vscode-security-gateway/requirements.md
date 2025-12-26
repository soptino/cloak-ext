# Requirements Document

## Introduction

Cloak is a local-first security layer for VS Code that acts as a security gateway for AI interactions. The system intercepts user prompts before they reach external LLMs and uses a local Small Language Model (SLM) to detect and neutralize prompt injection attacks, ensuring no sensitive data leaves the local machine without proper validation.

## Glossary

- **Cloak_Extension**: The VS Code extension that provides the security gateway functionality
- **Security_Service**: The core service responsible for analyzing prompts using the local SLM
- **Interceptor**: The component that captures user prompts via VS Code Extension API
- **Local_Engine**: The component that routes prompts to the local Ollama endpoint
- **Gatekeeper**: The component that makes security decisions based on analysis results
- **Shield_Status**: The visual indicator showing the current security state (Active/Scanning)
- **Prompt_Injection**: Adversarial patterns attempting to manipulate AI behavior or extract sensitive information
- **Security_Classifier**: The local SLM configured with a specific system prompt for threat detection
- **Ollama_Endpoint**: The local API endpoint (http://localhost:1234) running Qwen2.5-Coder-1.5B

## Requirements

### Requirement 1: Prompt Interception

**User Story:** As a developer using AI assistance in VS Code, I want my prompts to be intercepted and analyzed for security threats, so that I can prevent prompt injection attacks before they reach external LLMs.

#### Acceptance Criteria

1. WHEN a user submits a prompt through VS Code AI features, THE Interceptor SHALL capture the prompt before it reaches any external service
2. WHEN the prompt is captured, THE Cloak_Extension SHALL route it to the Security_Service for analysis
3. WHEN multiple prompts are submitted simultaneously, THE Interceptor SHALL handle them asynchronously without blocking the UI
4. THE Interceptor SHALL support both ChatParticipant API and command wrapper approaches for maximum compatibility

### Requirement 2: Local Security Analysis

**User Story:** As a security-conscious developer, I want prompts analyzed by a local SLM, so that no data leaves my machine during the security assessment process.

#### Acceptance Criteria

1. WHEN a prompt requires analysis, THE Security_Service SHALL send it to the local Ollama endpoint at http://localhost:1234
2. THE Local_Engine SHALL use Qwen2.5-Coder-1.5B model for all security classifications
3. WHEN communicating with the local SLM, THE Security_Service SHALL use a specific system prompt designed for security classification
4. THE Security_Service SHALL operate asynchronously to prevent blocking the VS Code interface
5. IF the Ollama endpoint is unavailable, THEN THE Security_Service SHALL handle the error gracefully and notify the user

### Requirement 3: Threat Detection and Classification

**User Story:** As a developer, I want the system to detect various types of prompt injection attacks, so that I can be protected from adversarial patterns that could compromise my AI interactions.

#### Acceptance Criteria

1. WHEN analyzing a prompt, THE Security_Classifier SHALL detect instructions attempting to ignore previous rules
2. WHEN analyzing a prompt, THE Security_Classifier SHALL identify attempts to leak system secrets or sensitive information
3. WHEN analyzing a prompt, THE Security_Classifier SHALL recognize requests for unauthorized bash command execution
4. WHEN analyzing a prompt, THE Security_Classifier SHALL classify the overall threat level as safe or dangerous
5. THE Security_Classifier SHALL provide reasoning for its classification decisions

### Requirement 4: Security Decision Enforcement

**User Story:** As a developer, I want dangerous prompts to be blocked with clear notifications, so that I understand when and why my requests are being filtered for security reasons.

#### Acceptance Criteria

1. WHEN a prompt is classified as dangerous, THE Gatekeeper SHALL block the request from proceeding to external services
2. WHEN a request is blocked, THE Cloak_Extension SHALL display a VS Code Warning Notification explaining the security concern
3. WHEN a prompt is classified as safe, THE Gatekeeper SHALL allow it to proceed to its intended destination
4. THE Gatekeeper SHALL log all security decisions for audit purposes
5. WHEN a false positive occurs, THE system SHALL provide a mechanism for user override with explicit confirmation

### Requirement 5: Visual Security Status

**User Story:** As a developer, I want to see the current security status in my VS Code interface, so that I know when the security layer is active and monitoring my AI interactions.

#### Acceptance Criteria

1. THE Cloak_Extension SHALL display a StatusBar item showing the current Shield_Status
2. WHEN the system is actively monitoring, THE Shield_Status SHALL display "Active"
3. WHEN the system is analyzing a prompt, THE Shield_Status SHALL display "Scanning"
4. WHEN the Ollama service is unavailable, THE Shield_Status SHALL display an error state
5. WHEN clicked, THE StatusBar item SHALL provide additional information about the security service status

### Requirement 6: Extension Architecture and Performance

**User Story:** As a VS Code user, I want the security extension to operate efficiently without impacting my development workflow, so that security doesn't come at the cost of productivity.

#### Acceptance Criteria

1. THE Cloak_Extension SHALL be implemented in TypeScript for VS Code compatibility
2. WHEN processing prompts, THE Security_Service SHALL use async/await patterns to prevent UI blocking
3. THE extension SHALL initialize quickly and not delay VS Code startup
4. WHEN multiple security analyses are requested, THE system SHALL queue them efficiently
5. THE extension SHALL consume minimal system resources during idle periods

### Requirement 7: Local-First Security Guarantee

**User Story:** As a privacy-conscious developer, I want assurance that my prompts and sensitive data never leave my local machine during security analysis, so that I maintain complete control over my information.

#### Acceptance Criteria

1. THE Security_Service SHALL only communicate with the local Ollama endpoint
2. WHEN analyzing prompts, THE system SHALL not transmit any data to external services
3. THE system SHALL store all analysis results locally
4. WHEN a prompt is deemed safe, THE original prompt SHALL be passed through unchanged
5. THE system SHALL provide clear documentation about its local-first architecture

### Requirement 8: Configuration and Extensibility

**User Story:** As a developer, I want to configure the security service settings, so that I can customize the security behavior to match my specific needs and threat model.

#### Acceptance Criteria

1. THE Cloak_Extension SHALL provide configuration options for the Ollama endpoint URL
2. THE Security_Service SHALL allow customization of the security classification system prompt
3. THE system SHALL support different threat sensitivity levels
4. WHEN configuration changes are made, THE system SHALL apply them without requiring VS Code restart
5. THE extension SHALL validate configuration settings and provide helpful error messages for invalid configurations