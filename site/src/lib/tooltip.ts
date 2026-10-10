// Global tooltip layer: every `title` attribute in the app renders as one
// styled tooltip (GitHub-like) instead of the browser's native box.
//
// Components keep writing plain `title="…"`, so markup, SSR tests and the
// no-JS fallback are unchanged. While an element is hovered or keyboard
// focused its `title` is moved aside (removing it is the only way to stop the
// native tooltip) and put back when the pointer/focus leaves.

const SHOW_DELAY_MS = 300
// Moving from one titled element to the next within this window shows the
// next tooltip immediately, like GitHub's toolbar buttons.
const WARM_WINDOW_MS = 300
const GAP_PX = 6
const VIEWPORT_MARGIN_PX = 8
const TOOLTIP_ID = 'hibou-tooltip'

interface Claim {
  el: Element
  text: string
  source: 'pointer' | 'focus'
  observer: MutationObserver
  addedDescribedBy: boolean
}

export function installTooltips(doc: Document = document): () => void {
  const tip = doc.createElement('div')
  tip.id = TOOLTIP_ID
  tip.className = 'hibou-tooltip'
  tip.setAttribute('role', 'tooltip')
  tip.hidden = true
  doc.body.appendChild(tip)

  let claim: Claim | null = null
  let showTimer: ReturnType<typeof setTimeout> | undefined
  let lastHiddenAt = 0

  // Nearest element that owns the tooltip for `target`: the claimed element
  // (its title is stashed) or the closest ancestor with a title. An empty
  // title stops the walk, as it suppresses ancestors' native tooltips too.
  function owner(target: EventTarget | null): Element | null {
    let node = target instanceof Element ? target : null
    while (node) {
      if (claim && node === claim.el) return node
      const title = node.getAttribute('title')
      if (title !== null) return title.trim() ? node : null
      node = node.parentElement
    }
    return null
  }

  function show() {
    if (!claim) return
    if (!tip.isConnected) doc.body.appendChild(tip)
    tip.textContent = claim.text
    tip.hidden = false
    position()
  }

  function hide() {
    clearTimeout(showTimer)
    if (!tip.hidden) {
      tip.hidden = true
      lastHiddenAt = Date.now()
    }
  }

  function position() {
    if (!claim || tip.hidden) return
    const anchor = claim.el.getBoundingClientRect()
    const view = doc.documentElement
    const width = tip.offsetWidth
    const height = tip.offsetHeight
    let top = anchor.top - height - GAP_PX
    let placement = 'top'
    if (top < VIEWPORT_MARGIN_PX) {
      top = anchor.bottom + GAP_PX
      placement = 'bottom'
    }
    const centered = anchor.left + anchor.width / 2 - width / 2
    const left = Math.min(Math.max(centered, VIEWPORT_MARGIN_PX), view.clientWidth - width - VIEWPORT_MARGIN_PX)
    tip.style.top = `${Math.round(top)}px`
    tip.style.left = `${Math.round(Math.max(left, VIEWPORT_MARGIN_PX))}px`
    tip.dataset.placement = placement
  }

  function take(el: Element, source: Claim['source']) {
    release()
    const text = el.getAttribute('title') ?? ''
    el.removeAttribute('title')
    const addedDescribedBy = !el.hasAttribute('aria-describedby')
    if (addedDescribedBy) el.setAttribute('aria-describedby', TOOLTIP_ID)
    // A re-render can write the title back while hovered: take the new text
    // and remove it again so the native box never appears.
    const observer = new MutationObserver(() => {
      if (!claim || claim.el !== el) return
      const next = el.getAttribute('title')
      if (next === null) return
      claim.text = next
      el.removeAttribute('title')
      if (!next.trim()) hide()
      else if (!tip.hidden) show()
    })
    observer.observe(el, { attributes: true, attributeFilter: ['title'] })
    claim = { el, text, source, observer, addedDescribedBy }

    clearTimeout(showTimer)
    if (Date.now() - lastHiddenAt < WARM_WINDOW_MS) show()
    else showTimer = setTimeout(show, SHOW_DELAY_MS)
  }

  function release() {
    if (!claim) return
    const { el, text, observer, addedDescribedBy } = claim
    claim = null
    observer.disconnect()
    hide()
    if (!el.hasAttribute('title')) el.setAttribute('title', text)
    if (addedDescribedBy && el.getAttribute('aria-describedby') === TOOLTIP_ID) {
      el.removeAttribute('aria-describedby')
    }
  }

  function onPointerOver(event: PointerEvent) {
    const el = owner(event.target)
    if (el === claim?.el) return
    if (el) take(el, 'pointer')
    else if (claim?.source === 'pointer') release()
  }

  function onPointerOut(event: PointerEvent) {
    // Leaving the window: no pointerover follows.
    if (event.relatedTarget === null && claim?.source === 'pointer') release()
  }

  function onFocusIn(event: FocusEvent) {
    const target = event.target
    if (!(target instanceof Element) || !target.matches(':focus-visible')) return
    const el = owner(target)
    if (el && el !== claim?.el) take(el, 'focus')
  }

  function onFocusOut() {
    if (claim?.source === 'focus') release()
  }

  function onKeyDown(event: KeyboardEvent) {
    if (event.key === 'Escape') hide()
  }

  const listeners: [string, EventListener, AddEventListenerOptions?][] = [
    ['pointerover', onPointerOver as EventListener],
    ['pointerout', onPointerOut as EventListener],
    ['focusin', onFocusIn as EventListener],
    ['focusout', onFocusOut],
    ['keydown', onKeyDown as EventListener],
    // Clicking usually changes what the element means (opens, navigates):
    // drop the tooltip but keep the title stashed until the pointer leaves.
    ['pointerdown', hide],
    ['scroll', hide, { capture: true, passive: true }],
  ]
  for (const [type, listener, options] of listeners) doc.addEventListener(type, listener, options)
  doc.defaultView?.addEventListener('resize', hide)

  return () => {
    release()
    for (const [type, listener, options] of listeners) doc.removeEventListener(type, listener, options)
    doc.defaultView?.removeEventListener('resize', hide)
    tip.remove()
  }
}
