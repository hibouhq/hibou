<script lang="ts">
import { defineComponent, h, type VNode } from 'vue'

// Renders the markdown subset that advisory text actually uses — headings,
// lists, fenced and inline code, emphasis, links, blockquotes, rules.
//
// THREAT MODEL. This text is third-party and attacker-influenceable: an
// advisory description, a scanner message, a VEX statement. Three properties
// keep it safe, and each has a test in MarkdownText.test.ts:
//
//  1. No HTML is ever parsed. Everything reaches the DOM as a Vue text node
//     (no `v-html`, no innerHTML, no dangerouslySetInnerHTML equivalent), so
//     `<script>` and `<img onerror>` in the source render as visible text.
//     There is no sanitiser to keep up to date because nothing is sanitised.
//  2. The only attribute ever taken from the input is an `href`, and only when
//     the value matched `https?://…` — `javascript:`, `data:`, `vbscript:` and
//     protocol-relative `//host` cannot become links. Every link carries
//     rel="noopener noreferrer" so a target="_blank" tab cannot reach back.
//  3. Parsing is linear and bounded. Input is truncated, block and inline
//     counts are capped, the inline scanner is a single global regex with no
//     nested quantifiers or backreferences, and nothing recurses — so no input
//     can hang the tab (ReDoS) or blow the stack.
//
// Not supported on purpose: raw HTML (rendered as text), tables, footnotes,
// reference links. Advisories using them stay readable, just unstyled.

/** Beyond this the text is not a description any more; the tail is dropped. */
const MAX_CHARS = 64_000
const MAX_LINES = 2_000
const MAX_BLOCKS = 500
const MAX_INLINE_NODES = 400
const MAX_LIST_ITEMS = 200

const FENCE = /^\s*```/
const HEADING = /^(#{1,6})\s+(.*)$/
const RULE = /^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/
const QUOTE = /^\s*>\s?(.*)$/
const BULLET = /^(\s*)[-*+]\s+(.*)$/
const ORDERED = /^(\s*)\d+[.)]\s+(.*)$/

// One pass, one regex. Alternatives are ordered by precedence (code wins over
// everything, so `` `**x**` `` stays literal) and every quantifier is over a
// negated class — no `.+?`, no backreference, so there is no backtracking blowup.
const INLINE = new RegExp([
  '(`[^`\\n]+`)', // 1 code span
  '(\\[[^\\]\\n]*\\]\\(https?://[^\\s)]+\\))', // 2 markdown link, http(s) only
  '(\\*\\*[^*\\n]+\\*\\*|__[^_\\n]+__)', // 3 bold
  '(\\*[^*\\n]+\\*|_[^_\\n]+_)', // 4 italic
  '(https?://[^\\s<>()\\[\\]]+)', // 5 bare URL
].join('|'), 'g')

const LINK_PARTS = /^\[([^\]\n]*)\]\((https?:\/\/[^\s)]+)\)$/

const HEADING_CLASS: Record<number, string> = {
  1: 'mt-4 mb-1.5 text-sm font-semibold text-white',
  2: 'mt-4 mb-1.5 text-sm font-semibold text-white',
  3: 'mt-3.5 mb-1 text-[13px] font-semibold uppercase tracking-wide text-gray-300',
  4: 'mt-3 mb-1 text-[13px] font-semibold text-gray-300',
  5: 'mt-3 mb-1 text-xs font-semibold text-gray-400',
  6: 'mt-3 mb-1 text-xs font-semibold text-gray-400',
}

const LINK_CLASS = 'text-accent underline decoration-accent/30 underline-offset-2 hover:decoration-accent'

/** The one place an input-derived attribute is emitted. */
function anchor(href: string, label: string, extraClass = ''): VNode {
  return h('a', {
    href,
    target: '_blank',
    rel: 'noopener noreferrer',
    class: extraClass ? `${LINK_CLASS} ${extraClass}` : LINK_CLASS,
  }, label)
}

function inlineNodes(source: string): (string | VNode)[] {
  if (!source) return []

  const nodes: (string | VNode)[] = []
  const scanner = new RegExp(INLINE.source, 'g')
  let last = 0
  let match: RegExpExecArray | null

  while ((match = scanner.exec(source)) !== null) {
    if (nodes.length >= MAX_INLINE_NODES) break
    if (match.index > last) nodes.push(source.slice(last, match.index))

    const [token, code, link, bold, italic, url] = match
    if (code) {
      nodes.push(h('code', { class: 'rounded bg-surface-overlay px-1 py-0.5 font-mono text-[0.9em] text-gray-200' }, code.slice(1, -1)))
    } else if (link) {
      const parts = LINK_PARTS.exec(link)
      // The scanner already proved the shape; parts is belt and braces.
      if (parts) nodes.push(anchor(parts[2], parts[1] || parts[2]))
      else nodes.push(token)
    } else if (bold) {
      nodes.push(h('strong', { class: 'font-semibold text-gray-100' }, bold.slice(2, -2)))
    } else if (italic) {
      nodes.push(h('em', { class: 'italic' }, italic.slice(1, -1)))
    } else if (url) {
      nodes.push(anchor(url, url, 'break-all'))
    }

    last = scanner.lastIndex
    // A zero-width match would spin forever; regex above cannot produce one,
    // but the guard costs nothing and removes the possibility entirely.
    if (scanner.lastIndex === match.index) scanner.lastIndex++
  }

  if (last < source.length && nodes.length < MAX_INLINE_NODES) nodes.push(source.slice(last))
  return nodes
}

function renderBlocks(source: string): VNode[] {
  const truncated = source.length > MAX_CHARS
  const text = (truncated ? source.slice(0, MAX_CHARS) : source).replace(/\r\n?/g, '\n')
  const lines = text.split('\n').slice(0, MAX_LINES)

  const blocks: VNode[] = []
  let index = 0

  const readList = (ordered: boolean) => {
    const items: VNode[] = []
    const matcher = ordered ? ORDERED : BULLET
    while (index < lines.length && items.length < MAX_LIST_ITEMS) {
      const match = matcher.exec(lines[index])
      if (!match) break
      let itemText = match[2]
      index++
      // An indented continuation line belongs to the item above it.
      while (index < lines.length && /^\s+\S/.test(lines[index]) && !BULLET.test(lines[index]) && !ORDERED.test(lines[index])) {
        itemText += ' ' + lines[index].trim()
        index++
      }
      items.push(h('li', { class: 'ml-4 list-outside pl-1' }, inlineNodes(itemText)))
    }
    blocks.push(h(ordered ? 'ol' : 'ul', {
      class: `my-1.5 space-y-0.5 ${ordered ? 'list-decimal' : 'list-disc'}`,
    }, items))
  }

  while (index < lines.length && blocks.length < MAX_BLOCKS) {
    const line = lines[index]

    if (!line.trim()) {
      index++
      continue
    }

    if (FENCE.test(line)) {
      index++
      const code: string[] = []
      while (index < lines.length && !FENCE.test(lines[index])) {
        code.push(lines[index])
        index++
      }
      index++ // closing fence
      blocks.push(h('pre', {
        class: 'my-2 overflow-x-auto rounded-lg border border-surface-border-subtle bg-surface px-3 py-2',
      }, h('code', { class: 'font-mono text-[12px] leading-relaxed text-gray-300' }, code.join('\n'))))
      continue
    }

    const heading = HEADING.exec(line)
    if (heading) {
      blocks.push(h('p', { class: HEADING_CLASS[heading[1].length] ?? HEADING_CLASS[6] }, inlineNodes(heading[2])))
      index++
      continue
    }

    if (RULE.test(line)) {
      blocks.push(h('hr', { class: 'my-3 border-surface-border-subtle' }))
      index++
      continue
    }

    if (QUOTE.test(line)) {
      const quoted: string[] = []
      while (index < lines.length) {
        const match = QUOTE.exec(lines[index])
        if (!match) break
        quoted.push(match[1])
        index++
      }
      blocks.push(h('blockquote', { class: 'my-2 border-l-2 border-surface-border pl-3 text-gray-400' }, inlineNodes(quoted.join(' '))))
      continue
    }

    if (ORDERED.test(line)) {
      readList(true)
      continue
    }

    if (BULLET.test(line)) {
      readList(false)
      continue
    }

    // Paragraph: soft line breaks join, a blank line ends it.
    const paragraph: string[] = []
    while (index < lines.length && lines[index].trim() && !HEADING.test(lines[index]) && !BULLET.test(lines[index]) && !ORDERED.test(lines[index]) && !FENCE.test(lines[index]) && !RULE.test(lines[index]) && !QUOTE.test(lines[index])) {
      paragraph.push(lines[index].trim())
      index++
    }
    blocks.push(h('p', { class: 'my-1.5' }, inlineNodes(paragraph.join(' '))))
  }

  if (truncated || index < lines.length || blocks.length >= MAX_BLOCKS) {
    blocks.push(h('p', { class: 'mt-2 text-xs text-gray-600' }, 'Description truncated — open the advisory for the full text.'))
  }

  return blocks
}

export default defineComponent({
  name: 'MarkdownText',
  props: {
    text: { type: String, default: '' },
  },
  setup(props) {
    return () => h('div', {
      class: 'text-sm leading-relaxed text-gray-300 [&>*:first-child]:mt-0 [&>*:last-child]:mb-0',
    }, renderBlocks(props.text ?? ''))
  },
})
</script>
