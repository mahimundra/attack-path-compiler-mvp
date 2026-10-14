import { useEffect, useMemo, useRef, useState } from 'react'
import cytoscape, { type Core, type ElementDefinition, type EventObject } from 'cytoscape'
import dagre from 'cytoscape-dagre'
import { Focus, Maximize2, Minus, Plus } from 'lucide-react'
import type { AttackPath, EntityNode, GraphData, RelationshipEdge } from '../models'

cytoscape.use(dagre)

interface Props {
  graph?: GraphData
  paths?: AttackPath[]
  selectedPath?: AttackPath
  selectedElementId?: string
  cutEdgeIds?: string[]
  cutNodeIds?: string[]
  onSelectNode: (node: EntityNode) => void
  onSelectEdge: (edge: RelationshipEdge) => void
}

const colors: Record<string, string> = {
  external: '#ff6b4a',
  identity: '#c084fc',
  host: '#54e8ff',
  service: '#f6c85f',
  cloud: '#6ee7b7',
  database: '#fb7185',
  critical_asset: '#fb7185',
}

export function AttackGraph({
  graph,
  paths = [],
  selectedPath,
  selectedElementId,
  cutEdgeIds = [],
  cutNodeIds = [],
  onSelectNode,
  onSelectEdge,
}: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | undefined>(undefined)
  const [hover, setHover] = useState<{ label: string; type: string; x: number; y: number }>()

  const visibleGraph = useMemo(() => {
    if (!graph || paths.length === 0) return graph
    const pathNodeIds = new Set(paths.flatMap((path) => path.node_ids))
    const pathEdgeIds = new Set(paths.flatMap((path) => path.edge_ids))
    const contextEdges = graph.edges.filter((edge) => pathNodeIds.has(edge.source) || pathNodeIds.has(edge.target))
    const contextNodeIds = new Set([...pathNodeIds, ...contextEdges.flatMap((edge) => [edge.source, edge.target])])
    return {
      ...graph,
      nodes: graph.nodes.filter((node) => contextNodeIds.has(node.id)),
      edges: graph.edges.filter((edge) => pathEdgeIds.has(edge.id) || contextEdges.some((context) => context.id === edge.id)),
    }
  }, [graph, paths])

  useEffect(() => {
    if (!containerRef.current || !visibleGraph) return
    const selectedNodes = new Set(selectedPath?.node_ids ?? [])
    const selectedEdges = new Set(selectedPath?.edge_ids ?? [])
    const cuts = new Set(cutEdgeIds)
    const cutNodes = new Set(cutNodeIds)
    const elements: ElementDefinition[] = [
      ...visibleGraph.nodes.map((node) => ({
        data: { ...node, color: colors[node.type] ?? '#94a3b8' },
        classes: [node.critical ? 'critical' : '', selectedNodes.has(node.id) ? 'path' : '', cutNodes.has(node.id) ? 'cut' : ''].filter(Boolean).join(' '),
      })),
      ...visibleGraph.edges.map((edge) => ({
        data: edge,
        classes: [selectedEdges.has(edge.id) ? 'path' : '', cuts.has(edge.id) ? 'cut' : ''].filter(Boolean).join(' '),
      })),
    ]

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      minZoom: 0.35,
      maxZoom: 2.2,
      wheelSensitivity: 0.18,
      boxSelectionEnabled: false,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            'background-opacity': 0.14,
            'border-width': 1.5,
            'border-color': 'data(color)',
            label: 'data(label)',
            color: '#d8e2ef',
            'font-family': 'Inter, sans-serif',
            'font-size': 10,
            'text-valign': 'bottom',
            'text-margin-y': 9,
            width: 32,
            height: 32,
            'overlay-opacity': 0,
          },
        },
        { selector: 'node.critical', style: { 'border-width': 3, 'border-color': '#fb7185', 'shadow-blur': 18, 'shadow-color': '#fb7185', 'shadow-opacity': 0.35 } },
        { selector: 'edge', style: { width: 1.2, 'line-color': '#344152', 'target-arrow-color': '#526174', 'target-arrow-shape': 'triangle', 'arrow-scale': 0.75, 'curve-style': 'bezier', opacity: 0.72, label: 'data(label)', color: '#66778c', 'font-size': 7, 'text-background-color': '#080c12', 'text-background-opacity': 0.85, 'text-background-padding': 2, 'text-rotation': 'autorotate' } },
        { selector: '.path', style: { 'border-color': '#b7f34a', 'line-color': '#b7f34a', 'target-arrow-color': '#b7f34a', opacity: 1, 'z-index': 20 } },
        { selector: 'node.path', style: { 'background-color': '#b7f34a', 'background-opacity': 0.22, 'shadow-blur': 16, 'shadow-color': '#b7f34a', 'shadow-opacity': 0.3 } },
        { selector: '.cut', style: { 'line-color': '#ff6b4a', 'target-arrow-color': '#ff6b4a', 'line-style': 'dashed', opacity: 0.9 } },
        { selector: 'node.cut', style: { 'border-color': '#ff6b4a', 'border-style': 'dashed' } },
        { selector: ':selected', style: { 'border-color': '#ffffff', 'border-width': 3, 'line-color': '#ffffff', 'target-arrow-color': '#ffffff' } },
      ],
      layout: { name: 'dagre', rankDir: 'LR', nodeSep: 42, rankSep: 88, padding: 30 } as cytoscape.LayoutOptions,
    })

    cy.on('tap', 'node', (event: EventObject) => {
      const node = visibleGraph.nodes.find((item) => item.id === event.target.id())
      if (node) onSelectNode(node)
    })
    cy.on('tap', 'edge', (event: EventObject) => {
      const edge = visibleGraph.edges.find((item) => item.id === event.target.id())
      if (edge) onSelectEdge(edge)
    })
    cy.on('mouseover', 'node, edge', (event: EventObject) => {
      const rendered = event.renderedPosition ?? { x: 0, y: 0 }
      setHover({ label: event.target.data('label') || event.target.id(), type: event.target.isNode() ? event.target.data('type') : 'relationship', x: rendered.x, y: rendered.y })
    })
    cy.on('mouseout', 'node, edge', () => setHover(undefined))
    cyRef.current = cy
    return () => {
      cy.destroy()
      cyRef.current = undefined
    }
  }, [visibleGraph, selectedPath, cutEdgeIds, cutNodeIds, onSelectNode, onSelectEdge])

  useEffect(() => {
    if (!selectedElementId || !cyRef.current) return
    const element = cyRef.current.getElementById(selectedElementId)
    if (element.nonempty()) {
      cyRef.current.elements().unselect()
      element.select()
    }
  }, [selectedElementId])

  const control = (action: 'in' | 'out' | 'fit') => {
    const cy = cyRef.current
    if (!cy) return
    if (action === 'fit') cy.animate({ fit: { eles: cy.elements(), padding: 45 }, duration: 250 })
    else cy.animate({ zoom: { level: cy.zoom() * (action === 'in' ? 1.2 : 0.8), position: { x: cy.width() / 2, y: cy.height() / 2 } }, duration: 150 })
  }

  if (!graph) {
    return <div className="graph-empty"><div className="radar-mark"><Focus size={28} /></div><strong>No attack surface loaded</strong><span>Load the demo scenario to assemble entities and trust relationships.</span></div>
  }

  return (
    <div className="graph-shell">
      <div ref={containerRef} className="graph-canvas" aria-label="Interactive attack graph" />
      {hover && <div className="graph-tooltip" style={{ left: hover.x + 14, top: hover.y + 12 }}><strong>{hover.label}</strong><span>{hover.type.replaceAll('_', ' ')}</span></div>}
      <div className="graph-controls" aria-label="Graph controls">
        <button onClick={() => control('in')} title="Zoom in" aria-label="Zoom in"><Plus size={15} /></button>
        <button onClick={() => control('out')} title="Zoom out" aria-label="Zoom out"><Minus size={15} /></button>
        <button onClick={() => control('fit')} title="Fit graph" aria-label="Fit graph"><Maximize2 size={15} /></button>
      </div>
      <div className="graph-legend">
        {Object.entries(colors).filter(([type]) => type !== 'critical_asset').map(([type, color]) => <span key={type}><i style={{ background: color }} />{type.replace('_', ' ')}</span>)}
      </div>
      {paths.length > 0 && <div className="graph-scope">Path union + 1-hop context</div>}
    </div>
  )
}
