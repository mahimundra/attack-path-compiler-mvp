/// <reference types="vite/client" />

declare module 'cytoscape-dagre' {
  const extension: (cytoscape: unknown) => void
  export default extension
}
