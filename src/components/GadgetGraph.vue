<script setup lang="ts">
import { ref, watch, nextTick } from 'vue'
import { VueFlow, useVueFlow, Position, Panel } from '@vue-flow/core'
import { Background } from '@vue-flow/background'
import { Controls } from '@vue-flow/controls'
import { MiniMap } from '@vue-flow/minimap'
import dagre from 'dagre'
import GadgetNode from './GadgetNode.vue'
import StreamingEdge from './StreamingEdge.vue'
import StepPlayer from './StepPlayer.vue'
import NodeDetails from './NodeDetails.vue'
import type { GadgetChain, GadgetNode as GadgetNodeType, GadgetEdge as GadgetEdgeType, NodeType } from '../data/gadgets/types'

const props = defineProps<{
  chain: GadgetChain | null
}>()

const { fitView, setCenter } = useVueFlow()

const nodes = ref<any[]>([])
const edges = ref<any[]>([])
const selectedNode = ref<GadgetNodeType | null>(null)
const selectedEdge = ref<GadgetEdgeType | null>(null)
const currentStep = ref(-1)
const isPlaying = ref(false)
let playInterval: ReturnType<typeof setInterval> | null = null

function calculateLayout(nodesData: any[], edgesData: any[]) {
  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'LR', ranksep: 180, nodesep: 100 })

  nodesData.forEach((node) => {
    g.setNode(node.id, { width: 200, height: 90 })
  })

  edgesData.forEach((edge) => {
    g.setEdge(edge.source, edge.target)
  })

  dagre.layout(g)

  return nodesData.map((node) => {
    const nodeWithPosition = g.node(node.id)
    return {
      ...node,
      position: {
        x: nodeWithPosition.x - 100,
        y: nodeWithPosition.y - 45,
      },
      targetPosition: Position.Left,
      sourcePosition: Position.Right,
    }
  })
}

function transformData(chain: GadgetChain) {
  const flowNodes = chain.nodes.map((node, index) => ({
    id: node.id,
    type: 'gadget',
    label: node.label,
    data: {
      type: node.type,
      className: node.className,
      methodName: node.methodName,
      label: node.label,
      description: node.description,
      isActive: false,
      isHighlighted: false,
      stepIndex: index,
    },
    position: { x: 0, y: 0 },
  }))

  const flowEdges = chain.edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    type: 'streaming',
    data: {
      invocationType: edge.invocationType,
      label: edge.label,
      isActive: false,
    },
    animated: edge.animated,
  }))

  return { nodes: flowNodes, edges: flowEdges }
}

function updateGraph() {
  if (!props.chain) {
    nodes.value = []
    edges.value = []
    return
  }

  const { nodes: flowNodes, edges: flowEdges } = transformData(props.chain)
  const layoutedNodes = calculateLayout(flowNodes, flowEdges)

  nodes.value = layoutedNodes
  edges.value = flowEdges

  nextTick(() => {
    fitView({ padding: 0.2 })
  })
}

watch(() => props.chain, updateGraph, { immediate: true })

function getNodeColorByType(type: NodeType): string {
  const colors = {
    source: '#00ff88',
    gadget: '#00d4ff',
    sink: '#ff4d4d',
  }
  return colors[type]
}

function highlightStep(step: number) {
  if (!props.chain) return

  nodes.value.forEach((node) => {
    node.data.isActive = false
    node.data.isHighlighted = false
  })
  edges.value.forEach((edge) => {
    edge.data.isActive = false
  })

  if (step < 0) return

  const node = props.chain.nodes[step]
  if (node) {
    const flowNode = nodes.value.find((n) => n.id === node.id)
    if (flowNode) {
      flowNode.data.isActive = true

      // Focus tracking: center the view on the active node
      nextTick(() => {
        setCenter(
          flowNode.position.x + 100,
          flowNode.position.y + 45,
          { duration: 500, zoom: 1 }
        )
      })
    }

    const relatedEdges = props.chain.edges.filter(
      (e) => e.source === node.id || e.target === node.id
    )
    relatedEdges.forEach((edge) => {
      const flowEdge = edges.value.find((e) => e.id === edge.id)
      if (flowEdge && step > 0 && edge.target === node.id) {
        flowEdge.data.isActive = true
      }
    })

    selectedNode.value = node
    selectedEdge.value = null
  }
}

function nextStep() {
  if (!props.chain) return
  if (currentStep.value < props.chain.nodes.length - 1) {
    currentStep.value++
    highlightStep(currentStep.value)
  } else {
    pause()
  }
}

function prevStep() {
  if (currentStep.value > 0) {
    currentStep.value--
    highlightStep(currentStep.value)
  }
}

function play() {
  if (isPlaying.value) return
  isPlaying.value = true

  if (currentStep.value >= (props.chain?.nodes.length || 0) - 1) {
    currentStep.value = -1
  }

  playInterval = setInterval(() => {
    nextStep()
  }, 2000)
}

function pause() {
  isPlaying.value = false
  if (playInterval) {
    clearInterval(playInterval)
    playInterval = null
  }
}

function reset() {
  pause()
  currentStep.value = -1
  highlightStep(-1)
}

function onNodeClick({ node }: { node: any }) {
  const chainNode = props.chain?.nodes.find((n) => n.id === node.id)
  if (chainNode) {
    selectedNode.value = chainNode
    selectedEdge.value = null

    const stepIndex = props.chain?.nodes.findIndex((n) => n.id === node.id)
    if (stepIndex !== undefined && stepIndex >= 0) {
      currentStep.value = stepIndex
      highlightStep(stepIndex)
    }
  }
}

function onEdgeClick({ edge }: { edge: any }) {
  const chainEdge = props.chain?.edges.find((e) => e.id === edge.id)
  if (chainEdge) {
    selectedEdge.value = chainEdge
    selectedNode.value = null
  }
}
</script>

<template>
  <div class="flex h-full w-full">
    <!-- Left: Graph Area -->
    <div class="flex-1 flex flex-col min-w-0 bg-[#0a0a0f]">
      <!-- Header -->
      <div v-if="chain" class="h-14 flex-shrink-0 border-b border-[#2d2d44] bg-[#13131f] px-5 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <h2 class="text-base font-semibold text-white">{{ chain.metadata.name }}</h2>
          <span
            class="px-2 py-0.5 rounded text-[10px] font-medium border"
            :class="{
              'bg-green-500/10 text-green-400 border-green-500/30': chain.metadata.complexity === 'Low',
              'bg-yellow-500/10 text-yellow-400 border-yellow-500/30': chain.metadata.complexity === 'Medium',
              'bg-red-500/10 text-red-400 border-red-500/30': chain.metadata.complexity === 'High'
            }"
          >
            {{ chain.metadata.complexity }}
          </span>
          <span v-if="chain.metadata.cve" class="px-2 py-0.5 rounded text-[10px] font-medium bg-red-500/10 text-red-400 border border-red-500/30">
            {{ chain.metadata.cve }}
          </span>
        </div>
        <p class="text-xs text-gray-500 truncate max-w-lg">{{ chain.metadata.description }}</p>
      </div>

      <!-- Vue Flow Canvas -->
      <div class="flex-1 relative overflow-hidden">
        <VueFlow
          v-model:nodes="nodes"
          v-model:edges="edges"
          :default-zoom="0.85"
          :min-zoom="0.2"
          :max-zoom="4"
          :fit-view-on-init="true"
          @node-click="onNodeClick"
          @edge-click="onEdgeClick"
          class="bg-[#0a0a0f]"
        >
          <!-- Custom Node Registration -->
          <template #node-gadget="props">
            <GadgetNode v-bind="props" />
          </template>

          <!-- Custom Edge Registration -->
          <template #edge-streaming="props">
            <StreamingEdge v-bind="props" />
          </template>

          <Background pattern-color="#1a1a2e" :gap="24" />
          <Controls position="bottom-right" />
          <MiniMap
            position="bottom-left"
            :node-color="(node: any) => getNodeColorByType(node.data?.type || 'gadget')"
            :node-stroke-color="(node: any) => getNodeColorByType(node.data?.type || 'gadget')"
            :node-stroke-width="2"
            :mask-color="'rgba(10, 10, 15, 0.7)'"
          />

          <!-- Empty State -->
          <Panel v-if="!chain" position="top-center" class="text-gray-500">
            <div class="text-center bg-[#13131f] p-8 rounded-xl border border-[#2d2d44]">
              <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" class="mx-auto mb-4 opacity-50">
                <circle cx="12" cy="12" r="10"/>
                <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/>
                <path d="M2 12h20"/>
              </svg>
              <p class="text-sm">请选择一个 Gadget Chain</p>
            </div>
          </Panel>
        </VueFlow>
      </div>

      <!-- Step Player -->
      <div v-if="chain" class="h-16 flex-shrink-0 border-t border-[#2d2d44] bg-[#13131f] px-5">
        <StepPlayer
          :current-step="currentStep"
          :total-steps="chain.nodes.length"
          :is-playing="isPlaying"
          @prev="prevStep"
          @next="nextStep"
          @play="play"
          @pause="pause"
          @reset="reset"
        />
      </div>
    </div>

    <!-- Right: Details Panel -->
    <div class="w-80 flex-shrink-0 border-l border-[#2d2d44] bg-[#13131f]">
      <NodeDetails
        :node="selectedNode"
        :edge="selectedEdge"
        :chain="chain"
      />
    </div>
  </div>
</template>

<style>
/* Vue Flow Styles */
.vue-flow__node {
  border: none !important;
  background: transparent !important;
  padding: 0 !important;
}

.vue-flow__handle {
  width: 6px;
  height: 6px;
  background: #00d4ff;
  border: 2px solid #0a0a0f;
  opacity: 0.6;
}

.vue-flow__handle:hover {
  opacity: 1;
}

.vue-flow__controls {
  background: rgba(19, 19, 31, 0.9);
  border: 1px solid #2d2d44;
  border-radius: 8px;
  padding: 4px;
}

.vue-flow__controls-button {
  background: transparent;
  border: none;
  color: #6b7280;
  border-radius: 4px;
  width: 28px;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.vue-flow__controls-button:hover {
  background: rgba(0, 212, 255, 0.1);
  color: white;
}

.vue-flow__attribution {
  display: none;
}

/* MiniMap Styles */
.vue-flow__minimap {
  background: rgba(19, 19, 31, 0.95);
  border: 1px solid #2d2d44;
  border-radius: 8px;
  overflow: hidden;
}

.vue-flow__minimap-svg {
  border-radius: 8px;
}

.vue-flow__minimap-mask {
  fill: rgba(10, 10, 15, 0.7);
}
</style>
