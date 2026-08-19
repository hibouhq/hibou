// Token-tree syntax highlighting for MarkdownText's fenced code blocks.
//
// THREAT MODEL (inherited from MarkdownText): the code is attacker-influenced
// advisory text, so nothing here may produce HTML. Prism is used ONLY through
// `Prism.tokenize`, which returns a tree of strings and Token objects — never
// markup — and the renderer maps that tree to Vue vnodes whose single
// attribute is a class from the fixed vocabulary below. Guardrails:
//   - languages are allowlisted (unknown tag → no highlighting),
//   - input is size-capped (grammars are regex-based; bounding input bounds
//     the worst-case cost),
//   - any tokenizer error falls back to plain text.
import Prism from 'prismjs'
import 'prismjs/components/prism-bash'
import 'prismjs/components/prism-c'
import 'prismjs/components/prism-cpp'
import 'prismjs/components/prism-csharp'
import 'prismjs/components/prism-docker'
import 'prismjs/components/prism-go'
import 'prismjs/components/prism-java'
import 'prismjs/components/prism-json'
import 'prismjs/components/prism-kotlin'
import 'prismjs/components/prism-markup-templating'
import 'prismjs/components/prism-php'
import 'prismjs/components/prism-python'
import 'prismjs/components/prism-ruby'
import 'prismjs/components/prism-rust'
import 'prismjs/components/prism-sql'
import 'prismjs/components/prism-typescript'
import 'prismjs/components/prism-yaml'

// The bundle import auto-highlights `code[class*="language-"]` elements on
// DOMContentLoaded; nothing rendered here uses those classes, and this flag
// (set during initial module evaluation, before DOMContentLoaded) makes the
// pass a no-op anyway.
Prism.manual = true

/** Above this, highlighting is skipped — a bound on regex-grammar cost. */
const MAX_HIGHLIGHT_CHARS = 20_000

const LANGUAGE_ALIASES: Record<string, string> = {
  'js': 'javascript',
  'jsx': 'javascript',
  'node': 'javascript',
  'ts': 'typescript',
  'tsx': 'typescript',
  'py': 'python',
  'rb': 'ruby',
  'golang': 'go',
  'sh': 'bash',
  'shell': 'bash',
  'zsh': 'bash',
  'console': 'bash',
  'shell-session': 'bash',
  'yml': 'yaml',
  'c++': 'cpp',
  'c#': 'csharp',
  'cs': 'csharp',
  'dotnet': 'csharp',
  'kt': 'kotlin',
  'html': 'markup',
  'xml': 'markup',
  'dockerfile': 'docker',
}

// GitHub-dark-adjacent syntax palette, matching the hex family the rest of
// the UI already uses (#8b949e, #58a6ff, …). Unmapped token types render as
// plain text — the vocabulary of emitted classes is exactly this map.
const TOKEN_CLASS: Record<string, string> = {
  'comment': 'text-[#8b949e] italic',
  'prolog': 'text-[#8b949e] italic',
  'doctype': 'text-[#8b949e] italic',
  'cdata': 'text-[#8b949e] italic',
  'keyword': 'text-[#ff7b72]',
  'boolean': 'text-[#ff7b72]',
  'important': 'text-[#ff7b72]',
  'atrule': 'text-[#ff7b72]',
  'string': 'text-[#a5d6ff]',
  'char': 'text-[#a5d6ff]',
  'attr-value': 'text-[#a5d6ff]',
  'regex': 'text-[#a5d6ff]',
  'url': 'text-[#a5d6ff]',
  'number': 'text-[#79c0ff]',
  'constant': 'text-[#79c0ff]',
  'symbol': 'text-[#79c0ff]',
  'attr-name': 'text-[#79c0ff]',
  'property': 'text-[#79c0ff]',
  'variable': 'text-[#79c0ff]',
  'function': 'text-[#d2a8ff]',
  'class-name': 'text-[#d2a8ff]',
  'selector': 'text-[#d2a8ff]',
  'tag': 'text-[#7ee787]',
  'builtin': 'text-[#7ee787]',
  'namespace': 'text-[#7ee787]',
}

export interface HighlightSpan {
  text: string
  /** Empty string means "plain text, no span". */
  className: string
}

/** A bound on token-tree depth; grammars never nest anywhere near this. */
const MAX_TOKEN_DEPTH = 32

function flattenToken(token: string | Prism.Token, inherited: string, depth: number, out: HighlightSpan[]): void {
  if (typeof token === 'string') {
    out.push({ text: token, className: inherited })
    return
  }
  const className = TOKEN_CLASS[token.type] ?? inherited
  if (depth >= MAX_TOKEN_DEPTH) {
    out.push({ text: tokenText(token), className })
    return
  }
  const content = token.content
  if (typeof content === 'string') {
    out.push({ text: content, className })
    return
  }
  const children = Array.isArray(content) ? content : [content]
  for (const child of children) {
    flattenToken(child, className, depth + 1, out)
  }
}

function tokenText(token: string | Prism.Token): string {
  if (typeof token === 'string') return token
  const content = token.content
  if (typeof content === 'string') return content
  const children = Array.isArray(content) ? content : [content]
  return children.map(tokenText).join('')
}

/**
 * highlightCode tokenizes the block for the given fence tag. Returns null
 * when highlighting does not apply (unknown language, oversized input, or a
 * tokenizer failure) — the caller renders the code as plain text.
 */
export function highlightCode(code: string, languageTag: string): HighlightSpan[] | null {
  const normalized = languageTag.trim().toLowerCase()
  const language = LANGUAGE_ALIASES[normalized] ?? normalized
  const grammar = Prism.languages[language]
  if (!grammar || code.length > MAX_HIGHLIGHT_CHARS) {
    return null
  }
  try {
    const spans: HighlightSpan[] = []
    for (const token of Prism.tokenize(code, grammar)) {
      flattenToken(token, '', 0, spans)
    }
    return spans
  } catch {
    // A grammar edge case must never cost the reader the code itself.
    return null
  }
}
