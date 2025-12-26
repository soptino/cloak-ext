# Cloak - AI Security Gateway

VS Code extension that provides a local-first security layer for AI interactions. It detects and neutralizes prompt injection attacks before they reach AI assistants like GitHub Copilot.

## Core Functionality

- Intercepts prompts sent to VS Code chat participants
- Analyzes prompts using a local SLM (Small Language Model) via Ollama
- Detects threat patterns: rule bypass, secret extraction, command injection, role manipulation
- Makes security decisions: allow, block, or warn with user override option
- Provides visual shield status indicator and audit logging

## Key Design Principles

- Local-first: All analysis happens locally via Ollama, no cloud dependencies
- Non-blocking: Security analysis should not significantly impact user experience
- Transparent: Users can see why prompts were flagged and override decisions
- Privacy-focused: Prompts are hashed for logging, not stored in plaintext
