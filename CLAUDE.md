# DOMINUS — Claude CLI Rules

## RTK Mandatory Layer

RTK must always be used before any model invocation.

Goals:
- Reduce token usage
- Reuse semantic context
- Avoid sending full files
- Minimize context window bloat
- Cache and diff aggressively

## Rules

- Never call Claude directly without RTK.
- Always prioritize cached semantic retrieval.
- Use diff/context slicing instead of full file uploads.
- Compress context whenever possible.
- Preserve token budget aggressively.
- Reuse previous embeddings and cached summaries.

## Workflow

1. RTK preprocess
2. Context reduction
3. Semantic cache lookup
4. Minimal prompt generation
5. Claude execution

## Forbidden

- Full repository dumps
- Repeated identical context uploads
- Uncompressed long prompts
- Duplicate file injections
