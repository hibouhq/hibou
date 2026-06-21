<script lang="ts">
import { defineComponent, h, type VNode } from 'vue'

// Matches markdown links [label](url), restricted to http(s) so only safe
// anchors are ever produced.
const MARKDOWN_LINK = /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g

// Renders plain text with markdown links turned into anchors. Uses a render
// function (not v-html) so all text is escaped by Vue and only validated
// http(s) hrefs are emitted — no XSS surface.
export default defineComponent({
  name: 'LinkedText',
  props: {
    text: { type: String, default: '' },
  },
  setup(props) {
    return () => {
      const source = props.text ?? ''
      const nodes: (string | VNode)[] = []
      const pattern = new RegExp(MARKDOWN_LINK)
      let lastIndex = 0
      let match: RegExpExecArray | null

      while ((match = pattern.exec(source)) !== null) {
        if (match.index > lastIndex) {
          nodes.push(source.slice(lastIndex, match.index))
        }
        nodes.push(
          h(
            'a',
            {
              href: match[2],
              target: '_blank',
              rel: 'noopener noreferrer',
              class: 'text-accent hover:underline',
            },
            match[1],
          ),
        )
        lastIndex = match.index + match[0].length
      }
      if (lastIndex < source.length) {
        nodes.push(source.slice(lastIndex))
      }

      return h('span', nodes)
    }
  },
})
</script>
