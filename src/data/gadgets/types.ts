// Gadget Chain 类型定义

export interface Metadata {
  chainId: string
  name: string
  targetDependency: string
  description: string
  author: string
  complexity: 'Low' | 'Medium' | 'High'
  cve?: string | null
}

export type NodeType = 'source' | 'gadget' | 'sink'

export interface GadgetNode {
  id: string
  type: NodeType
  className: string
  methodName: string
  label: string
  description: string
  codeSnippet: string
  highlightLines: number[]
}

export type InvocationType = 'direct' | 'reflection' | 'proxy' | 'override'

export interface GadgetEdge {
  id: string
  source: string
  target: string
  invocationType: InvocationType
  label: string
  description: string
  animated: boolean
}

export interface GadgetChain {
  metadata: Metadata
  nodes: GadgetNode[]
  edges: GadgetEdge[]
}
