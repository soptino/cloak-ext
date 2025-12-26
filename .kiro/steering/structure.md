# Project Structure

```
├── src/                    # Source code
│   ├── extension.ts        # Extension entry point (activate/deactivate)
│   └── types/
│       └── index.ts        # Core type definitions
├── out/                    # Compiled JavaScript output
├── .kiro/
│   ├── steering/           # AI assistant guidance files
│   └── specs/              # Feature specifications
├── package.json            # Extension manifest and dependencies
├── tsconfig.json           # TypeScript configuration
├── vitest.config.ts        # Test configuration
└── .eslintrc.json          # Linting rules
```

## Key Files

- `src/extension.ts`: Main entry point, exports `activate()` and `deactivate()`
- `src/types/index.ts`: All TypeScript interfaces for the extension
- `package.json`: Defines VS Code contribution points (commands, configuration, chat participants)

## Conventions

- Type definitions go in `src/types/`
- Test files are co-located with source: `*.test.ts`
- Extension contributes a chat participant with id `cloak.securityGateway`
- Commands are prefixed with `cloak.`
- Configuration settings are under `cloak.*` namespace
