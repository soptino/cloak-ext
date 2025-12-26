# Tech Stack

## Core Technologies

- TypeScript (ES2022, strict mode)
- VS Code Extension API (^1.85.0)
- Node.js runtime
- Axios for HTTP requests to Ollama

## Build System

- TypeScript compiler (`tsc`)
- Output directory: `out/`
- Source directory: `src/`
- Module system: CommonJS

## Testing

- Vitest for unit testing
- fast-check for property-based testing
- Test files: `src/**/*.test.ts`

## Linting

- ESLint with TypeScript parser
- @typescript-eslint plugin

## Common Commands

```bash
# Compile TypeScript
npm run compile

# Watch mode (development)
npm run watch

# Run tests (single run)
npm run test

# Run tests (watch mode)
npm run test:watch

# Lint source files
npm run lint

# Prepare for publishing
npm run vscode:prepublish
```

## External Dependencies

- Ollama API (local LLM server, default: http://localhost:1234)
- VS Code Chat Participant API for intercepting AI interactions
