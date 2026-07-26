// Directory tree over coverage files, shared by the treemap and the tree view.
// Folder metrics are computed from their descendants.

export interface CoverageTreeFile {
  path: string
  valid: number
  covered: number
  rate: number | null
  /** Optional per-file delta vs a base snapshot (PR context). */
  delta?: number | null
}

export interface CoverageTreeNode {
  path: string
  name: string
  isFile: boolean
  valid: number
  covered: number
  rate: number | null
  fileCount: number
  /** Aggregated rate delta vs base, weighted by instrumented lines. Null when unknown. */
  delta: number | null
  children: CoverageTreeNode[]
}

export function buildCoverageTree(files: CoverageTreeFile[]): CoverageTreeNode {
  interface Mutable extends Omit<CoverageTreeNode, 'children'> {
    children: Map<string, Mutable>
    deltaWeight: number
    deltaSum: number
  }

  const newNode = (path: string, name: string, isFile: boolean): Mutable => ({
    path,
    name,
    isFile,
    valid: 0,
    covered: 0,
    rate: null,
    fileCount: 0,
    delta: null,
    deltaWeight: 0,
    deltaSum: 0,
    children: new Map(),
  })

  const root = newNode('', '', false)
  for (const file of files) {
    if (file.valid <= 0) continue
    const segments = file.path.split('/').filter(Boolean)
    let node = root
    accumulate(node, file)
    for (let i = 0; i < segments.length; i++) {
      const childPath = segments.slice(0, i + 1).join('/')
      let child = node.children.get(segments[i])
      if (!child) {
        child = newNode(childPath, segments[i], i === segments.length - 1)
        node.children.set(segments[i], child)
      }
      accumulate(child, file)
      node = child
    }
  }

  function accumulate(node: Mutable, file: CoverageTreeFile) {
    node.valid += file.valid
    node.covered += file.covered
    node.fileCount += 1
    if (typeof file.delta === 'number') {
      node.deltaWeight += file.valid
      node.deltaSum += file.delta * file.valid
    }
  }

  function finalize(node: Mutable): CoverageTreeNode {
    const children = [...node.children.values()]
      .map(finalize)
      // Directories first, then by weight, mirroring code-browser trees.
      .sort((a, b) => Number(a.isFile) - Number(b.isFile) || b.valid - a.valid)
    return {
      path: node.path,
      name: node.name,
      isFile: node.isFile,
      valid: node.valid,
      covered: node.covered,
      rate: node.valid > 0 ? node.covered / node.valid : null,
      fileCount: node.fileCount,
      delta: node.deltaWeight > 0 ? node.deltaSum / node.deltaWeight : null,
      children,
    }
  }

  return finalize(root)
}

export function findTreeNode(root: CoverageTreeNode, path: string): CoverageTreeNode | null {
  if (!path) return root
  let node: CoverageTreeNode | undefined = root
  for (const segment of path.split('/')) {
    node = node?.children.find((child) => child.name === segment)
    if (!node) return null
  }
  return node
}

export interface TreemapTile {
  node: CoverageTreeNode
  x: number
  y: number
  w: number
  h: number
}

/** Squarified treemap (Bruls et al.): lay rows of tiles keeping aspect ratios near 1. */
export function squarify(nodes: CoverageTreeNode[], x: number, y: number, w: number, h: number): TreemapTile[] {
  const total = nodes.reduce((sum, node) => sum + node.valid, 0)
  if (total <= 0 || nodes.length === 0) return []
  const scale = (w * h) / total
  const result: TreemapTile[] = []
  let rest = [...nodes].sort((a, b) => b.valid - a.valid)
  while (rest.length > 0) {
    const horizontal = w < h
    const side = horizontal ? w : h
    let row = [rest[0]]
    let rowArea = rest[0].valid * scale
    let worst = worstRatio(row, rowArea, side, scale)
    for (let i = 1; i < rest.length; i++) {
      const candidate = [...row, rest[i]]
      const candidateArea = rowArea + rest[i].valid * scale
      const candidateWorst = worstRatio(candidate, candidateArea, side, scale)
      if (candidateWorst > worst) break
      row = candidate
      rowArea = candidateArea
      worst = candidateWorst
    }
    const thickness = rowArea / side
    let offset = 0
    for (const node of row) {
      const length = (node.valid * scale) / thickness
      result.push(
        horizontal
          ? { node, x: x + offset, y, w: length, h: thickness }
          : { node, x, y: y + offset, w: thickness, h: length },
      )
      offset += length
    }
    if (horizontal) {
      y += thickness
      h -= thickness
    } else {
      x += thickness
      w -= thickness
    }
    rest = rest.slice(row.length)
  }
  return result
}

function worstRatio(row: CoverageTreeNode[], rowArea: number, side: number, scale: number): number {
  const thickness = rowArea / side
  let worst = 1
  for (const node of row) {
    const length = (node.valid * scale) / thickness
    worst = Math.max(worst, length / thickness, thickness / length)
  }
  return worst
}

export function coverageRateColor(rate: number | null): string {
  if (rate === null) return 'var(--color-text-muted, #6b7280)'
  const percent = rate * 100
  if (percent >= 80) return 'var(--color-ok, #3fb950)'
  if (percent >= 60) return 'var(--color-warn, #d29922)'
  return 'var(--color-danger, #f85149)'
}

export function formatCoverageRate(rate: number | null): string {
  return rate === null ? 'n/a' : `${(rate * 100).toFixed(1)}%`
}
