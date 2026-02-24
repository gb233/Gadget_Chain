<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { VueFlow, useVueFlow, Position } from '@vue-flow/core'
import { Background } from '@vue-flow/background'
import { Controls } from '@vue-flow/controls'
import { MiniMap } from '@vue-flow/minimap'
import dagre from 'dagre'
import GadgetNode from './GadgetNode.vue'
import StreamingEdge from './StreamingEdge.vue'
import PayloadSelector from './PayloadSelector.vue'
import CodePanel from './CodePanel.vue'
import type { GadgetChain, GadgetNode as GadgetNodeType, NodeType } from '../data/gadgets/types'

const props = defineProps<{
  chainA: GadgetChain | null
  chainB: GadgetChain | null
}>()

const emit = defineEmits<{
  (e: 'update:chainA', chain: GadgetChain): void
  (e: 'update:chainB', chain: GadgetChain): void
  (e: 'close'): void
}>()

const nodes = ref<any[]>([])
const edges = ref<any[]>([])
const { fitView } = useVueFlow({ id: 'vue-flow-compare' })

// 选中的节点用于代码对比
const selectedNodeA = ref<GadgetNodeType | null>(null)
const selectedNodeB = ref<GadgetNodeType | null>(null)
const isCodePanelExpanded = ref(false)

// 同步步进
const currentStep = ref(0)
const isPlaying = ref(false)
let playInterval: ReturnType<typeof setInterval> | null = null

// 计算差异（使用diff算法）
function computeDiff(codeA: string, codeB: string) {
  const linesA = codeA.split('\n')
  const linesB = codeB.split('\n')
  const diffLines: number[] = []
  const maxLines = Math.max(linesA.length, linesB.length)

  for (let i = 0; i < maxLines; i++) {
    const lineA = linesA[i] || ''
    const lineB = linesB[i] || ''
    // 忽略空白字符的差异
    const normalizedA = lineA.replace(/\s+/g, ' ').trim()
    const normalizedB = lineB.replace(/\s+/g, ' ').trim()
    if (normalizedA !== normalizedB) {
      diffLines.push(i + 1)
    }
  }
  return diffLines
}

// 构建对齐的融合图谱
const alignedGraph = computed(() => {
  const chainA = props.chainA
  const chainB = props.chainB
  if (!chainA || !chainB) return null

  // 创建节点唯一标识
  const getNodeKey = (n: GadgetNodeType) => `${n.className}#${n.methodName}`

  // 构建节点映射
  const nodeIndexA = new Map(chainA.nodes.map((n, i) => [getNodeKey(n), i]))
  const nodeIndexB = new Map(chainB.nodes.map((n, i) => [getNodeKey(n), i]))

  // 找出所有唯一节点（按出现顺序）
  const allNodes: Array<{
    key: string
    nodeA?: GadgetNodeType
    nodeB?: GadgetNodeType
    indexA: number
    indexB: number
    isCommon: boolean
  }> = []

  const addedKeys = new Set<string>()

  // 先添加chainA的所有节点
  chainA.nodes.forEach((node, index) => {
    const key = getNodeKey(node)
    if (!addedKeys.has(key)) {
      const indexB = nodeIndexB.get(key) ?? -1
      const nodeB = indexB >= 0 ? chainB.nodes[indexB] : undefined
      allNodes.push({
        key,
        nodeA: node,
        nodeB,
        indexA: index,
        indexB,
        isCommon: !!nodeB
      })
      addedKeys.add(key)
    }
  })

  // 再添加chainB独有的节点
  chainB.nodes.forEach((node, index) => {
    const key = getNodeKey(node)
    if (!addedKeys.has(key)) {
      allNodes.push({
        key,
        nodeB: node,
        indexA: -1,
        indexB: index,
        isCommon: false
      })
      addedKeys.add(key)
    }
  })

  // 按逻辑顺序排序（尽量让共用节点在一起）
  allNodes.sort((a, b) => {
    // 如果都是共用节点，按chainA的顺序
    if (a.isCommon && b.isCommon) {
      return a.indexA - b.indexA
    }
    // 如果只有一个是共用节点，共用节点排前面
    if (a.isCommon !== b.isCommon) {
      return a.isCommon ? -1 : 1
    }
    // 都不是共用节点，按各自链的顺序
    if (a.indexA >= 0 && b.indexA >= 0) {
      return a.indexA - b.indexA
    }
    if (a.indexB >= 0 && b.indexB >= 0) {
      return a.indexB - b.indexB
    }
    return 0
  })

  // 构建Vue Flow节点
  const flowNodes: any[] = []
  const flowEdges: any[] = []

  for (let rank = 0; rank < allNodes.length; rank++) {
    const item = allNodes[rank]
    if (!item) continue
    const isOnlyA = item.indexA >= 0 && item.indexB < 0
    const isOnlyB = item.indexA < 0 && item.indexB >= 0
    const isCommon = item.isCommon

    // 确定节点类型和颜色
    const nodeType = item.nodeA?.type || item.nodeB?.type || 'gadget'

    // 共用节点使用绿色，独有节点使用链的颜色
    const chain = isOnlyB ? 'B' : 'A'

    flowNodes.push({
      id: item.key,
      type: 'gadget',
      position: { x: rank * 250, y: isCommon ? 0 : (isOnlyB ? 180 : 0) },
      data: {
        type: nodeType,
        className: item.nodeA?.className || item.nodeB?.className || '',
        methodName: item.nodeA?.methodName || item.nodeB?.methodName || '',
        label: item.nodeA?.label || item.nodeB?.label || '',
        description: item.nodeA?.description || item.nodeB?.description || '',
        isCommon,
        isOnlyA,
        isOnlyB,
        chain,
        nodeA: item.nodeA,
        nodeB: item.nodeB,
        stepIndexA: item.indexA,
        stepIndexB: item.indexB,
      }
    })

    // 构建边
    if (rank > 0) {
      const prevItem = allNodes[rank - 1]
      if (!prevItem) continue

      // Chain A的边
      if (item.indexA > 0 && prevItem.indexA === item.indexA - 1) {
        flowEdges.push({
          id: `edge-a-${rank}`,
          source: prevItem.key,
          target: item.key,
          type: 'streaming',
          data: {
            chain: 'A',
            isCommon: item.isCommon && prevItem.isCommon,
            invocationType: 'direct',
            label: '',
          },
          style: {
            stroke: item.isCommon && prevItem.isCommon ? '#00ff88' : '#00d4ff',
            strokeWidth: item.isCommon && prevItem.isCommon ? 4 : 2,
          }
        })
      }

      // Chain B的边（对于共用节点，如果chainB也是连续的）
      if (item.indexB > 0 && prevItem.indexB === item.indexB - 1 &&
          !(item.indexA > 0 && prevItem.indexA === item.indexA - 1)) {
        // 只有B的边，且A没有这条边
        flowEdges.push({
          id: `edge-b-${rank}`,
          source: prevItem.key,
          target: item.key,
          type: 'streaming',
          data: {
            chain: 'B',
            isCommon: false,
            invocationType: 'direct',
            label: '',
          },
          style: {
            stroke: '#ff4d4d',
            strokeWidth: 2,
          }
        })
      }

      // 分支边：从共用节点到B独有节点
      if (isOnlyB && prevItem.isCommon) {
        const existingEdge = flowEdges.find(e => e.target === item.key)
        if (!existingEdge) {
          flowEdges.push({
            id: `branch-b-${rank}`,
            source: prevItem.key,
            target: item.key,
            type: 'streaming',
            data: {
              chain: 'B',
              isBranch: true,
              invocationType: 'reflection',
              label: 'B分支',
            },
            style: {
              stroke: '#ff4d4d',
              strokeWidth: 2,
              strokeDasharray: '5,5',
            }
          })
        }
      }
    }
  }

  return { nodes: flowNodes, edges: flowEdges, allNodes }
})

// v3.0 Y型合并布局 - 将对比可视化为Y型结构
function calculateLayout() {
  if (!alignedGraph.value) return

  const { allNodes } = alignedGraph.value

  // 1. 按逻辑层级分组
  const levelGroups = new Map<number, {
    common: typeof allNodes,
    onlyA: typeof allNodes,
    onlyB: typeof allNodes
  }>()

  allNodes.forEach((item) => {
    const level = item.isCommon
      ? Math.min(item.indexA, item.indexB)
      : (item.indexA >= 0 ? item.indexA : item.indexB)

    if (!levelGroups.has(level)) {
      levelGroups.set(level, { common: [], onlyA: [], onlyB: [] })
    }

    const group = levelGroups.get(level)!
    if (item.isCommon) {
      group.common.push(item)
    } else if (item.indexA >= 0 && item.indexB < 0) {
      group.onlyA.push(item)
    } else {
      group.onlyB.push(item)
    }
  })

  // 2. 计算节点位置 - Y型结构
  const flowNodes: any[] = []
  const nodePositions = new Map<string, { x: number, y: number }>()

  // 按层级排序
  const sortedLevels = Array.from(levelGroups.keys()).sort((a, b) => a - b)

  sortedLevels.forEach((level, levelIndex) => {
    const group = levelGroups.get(level)!
    const baseX = levelIndex * 220  // 层级间距

    // 共用节点在中轴线 Y=0
    group.common.forEach((item, idx) => {
      const y = idx * 100  // 多个共用节点时垂直分散
      const node = createFlowNode(item, baseX, y, 'common')
      flowNodes.push(node)
      nodePositions.set(item.key, { x: baseX, y })
    })

    // A独有节点在上方 Y=-120 起
    group.onlyA.forEach((item, idx) => {
      const y = -120 - (idx * 100)
      const node = createFlowNode(item, baseX, y, 'onlyA')
      flowNodes.push(node)
      nodePositions.set(item.key, { x: baseX, y })
    })

    // B独有节点在下方 Y=+120 起
    group.onlyB.forEach((item, idx) => {
      const y = 120 + (idx * 100)
      const node = createFlowNode(item, baseX, y, 'onlyB')
      flowNodes.push(node)
      nodePositions.set(item.key, { x: baseX, y })
    })
  })

  // 3. 构建边 - 创建Y型连接
  const flowEdges: any[] = []

  for (let i = 0; i < allNodes.length; i++) {
    const item = allNodes[i]
    if (!item) continue

    // Chain A 的边
    if (item.indexA > 0) {
      const prevA = allNodes.find(n => n.indexA === item.indexA - 1)
      if (prevA) {
        const isCommonPath = item.isCommon && prevA.isCommon
        flowEdges.push(createEdge(prevA.key, item.key, 'A', isCommonPath))
      }
    }

    // Chain B 的边
    if (item.indexB > 0) {
      const prevB = allNodes.find(n => n.indexB === item.indexB - 1)
      if (prevB && !(item.indexA > 0 && prevB.indexA === item.indexA - 1)) {
        flowEdges.push(createEdge(prevB.key, item.key, 'B', false))
      }
    }
  }

  nodes.value = flowNodes
  edges.value = flowEdges
}

// 辅助函数：创建流节点
function createFlowNode(item: any, x: number, y: number, type: 'common' | 'onlyA' | 'onlyB') {
  const isCommon = type === 'common'
  const isOnlyA = type === 'onlyA'
  const isOnlyB = type === 'onlyB'

  return {
    id: item.key,
    type: 'gadget',
    position: { x, y },
    data: {
      type: item.nodeA?.type || item.nodeB?.type || 'gadget',
      className: item.nodeA?.className || item.nodeB?.className || '',
      methodName: item.nodeA?.methodName || item.nodeB?.methodName || '',
      label: item.nodeA?.label || item.nodeB?.label || '',
      description: item.nodeA?.description || item.nodeB?.description || '',
      isCommon,
      isOnlyA,
      isOnlyB,
      chain: isOnlyB ? 'B' : 'A',
      nodeA: item.nodeA,
      nodeB: item.nodeB,
      stepIndexA: item.indexA,
      stepIndexB: item.indexB,
    }
  }
}

// 辅助函数：创建边
function createEdge(source: string, target: string, chain: 'A' | 'B', isCommon: boolean) {
  return {
    id: `edge-${chain}-${source}-${target}`,
    source,
    target,
    type: 'streaming',
    data: {
      chain,
      isCommon,
      invocationType: 'direct',
      label: '',
    },
    style: {
      stroke: isCommon ? '#00ff88' : (chain === 'A' ? '#00d4ff' : '#ff4d4d'),
      strokeWidth: isCommon ? 4 : 2,
    },
    animated: !isCommon,
  }
}

watch(() => [props.chainA, props.chainB], () => {
  calculateLayout()
  currentStep.value = 0
  selectedNodeA.value = null
  selectedNodeB.value = null
}, { immediate: true })

// 同步步进
const maxSteps = computed(() => {
  return Math.max(
    props.chainA?.nodes.length || 0,
    props.chainB?.nodes.length || 0
  )
})

function highlightStep(step: number) {
  // 高亮当前步骤的节点
  nodes.value.forEach((node: any) => {
    const isActiveA = node.data.stepIndexA === step
    const isActiveB = node.data.stepIndexB === step
    node.data.isActive = isActiveA || isActiveB

    // 如果步进到这个节点，自动选择用于代码对比
    if (isActiveA && node.data.nodeA) {
      selectedNodeA.value = node.data.nodeA
    }
    if (isActiveB && node.data.nodeB) {
      selectedNodeB.value = node.data.nodeB
    }
  })
}

function nextStep() {
  if (currentStep.value < maxSteps.value - 1) {
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
  playInterval = setInterval(nextStep, 2000)
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
  currentStep.value = 0
  highlightStep(0)
}

// 点击节点选择
function onNodeClick({ node }: { node: any }) {
  if (node.data.nodeA) {
    selectedNodeA.value = node.data.nodeA
  }
  if (node.data.nodeB) {
    selectedNodeB.value = node.data.nodeB
  }
  // 自动展开代码面板
  if (selectedNodeA.value && selectedNodeB.value) {
    isCodePanelExpanded.value = true
  }
}

function getNodeColorByType(type: NodeType, isCommon: boolean, isOnlyB: boolean): string {
  if (isCommon) return '#00ff88' // 共用节点绿色
  if (isOnlyB) return '#ff4d4d'  // B独有红色
  return '#00d4ff'               // A独有蓝色
}

// 代码差异计算
const codeDiff = computed(() => {
  if (!selectedNodeA.value || !selectedNodeB.value) return null

  const isSameClass = selectedNodeA.value.className === selectedNodeB.value.className
  const isSameMethod = selectedNodeA.value.methodName === selectedNodeB.value.methodName

  // P1 Fix: 只有同类同方法时才计算差异行
  const diffLines = (isSameClass && isSameMethod)
    ? computeDiff(
        selectedNodeA.value.codeSnippet || '',
        selectedNodeB.value.codeSnippet || ''
      )
    : []

  return {
    classNameA: selectedNodeA.value.className,
    classNameB: selectedNodeB.value.className,
    methodNameA: selectedNodeA.value.methodName,
    methodNameB: selectedNodeB.value.methodName,
    codeA: selectedNodeA.value.codeSnippet,
    codeB: selectedNodeB.value.codeSnippet,
    highlightLinesA: selectedNodeA.value.highlightLines,
    highlightLinesB: selectedNodeB.value.highlightLines,
    diffLines,
    isSameClass,
    isSameMethod,
    isIdentical: isSameClass && isSameMethod && diffLines.length === 0,
  }
})

// 统计信息
const stats = computed(() => {
  if (!alignedGraph.value) return null
  const common = alignedGraph.value.allNodes.filter(n => n.isCommon).length
  const onlyA = alignedGraph.value.allNodes.filter(n => n.indexA >= 0 && n.indexB < 0).length
  const onlyB = alignedGraph.value.allNodes.filter(n => n.indexA < 0 && n.indexB >= 0).length
  return { common, onlyA, onlyB }
})

function onSelectChainA(chain: GadgetChain) {
  emit('update:chainA', chain)
}

function onSelectChainB(chain: GadgetChain) {
  emit('update:chainB', chain)
}
</script>

<template>
  <div class="flex flex-col h-full bg-[#0a0a0f]">
    <!-- Header -->
    <div class="h-16 flex-shrink-0 border-b border-[#2d2d44] bg-[#13131f] px-6 flex items-center justify-between">
      <div class="flex items-center gap-4">
        <div class="flex items-center gap-2">
          <div class="w-8 h-8 rounded-lg bg-[#00d4ff]/20 flex items-center justify-center">
            <span class="text-[#00d4ff] text-xs font-bold">A</span>
          </div>
          <PayloadSelector :model-value="chainA" @select="onSelectChainA" />
        </div>

        <div class="flex items-center gap-2 px-2">
          <div class="h-px w-6 bg-[#2d2d44]"></div>
          <span class="text-xs text-gray-500">VS</span>
          <div class="h-px w-6 bg-[#2d2d44]"></div>
        </div>

        <div class="flex items-center gap-2">
          <div class="w-8 h-8 rounded-lg bg-[#ff4d4d]/20 flex items-center justify-center">
            <span class="text-[#ff4d4d] text-xs font-bold">B</span>
          </div>
          <PayloadSelector :model-value="chainB" @select="onSelectChainB" />
        </div>
      </div>

      <button
        @click="$emit('close')"
        class="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#1a1a2e] hover:bg-[#252536] border border-[#2d2d44] transition-all"
      >
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-gray-400">
          <path d="M18 6 6 18" />
          <path d="m6 6 12 12" />
        </svg>
        <span class="text-sm text-gray-400">退出对比</span>
      </button>
    </div>

    <!-- Main Content -->
    <div class="flex-1 flex overflow-hidden">
      <!-- Graph Area -->
      <div class="flex-1 flex flex-col">
        <!-- Legend & Stats -->
        <div class="h-10 flex-shrink-0 bg-[#0a0a0f] px-4 flex items-center justify-between border-b border-[#2d2d44]">
          <div class="flex items-center gap-4 text-xs">
            <span class="flex items-center gap-2">
              <span class="w-3 h-3 rounded-full bg-[#00ff88] shadow-[0_0_8px_rgba(0,255,136,0.5)]"></span>
              <span class="text-gray-400">共用节点 ({{ stats?.common || 0 }})</span>
            </span>
            <span class="flex items-center gap-2">
              <span class="w-3 h-3 rounded-full bg-[#00d4ff] shadow-[0_0_8px_rgba(0,212,255,0.5)]"></span>
              <span class="text-gray-400">仅A有 ({{ stats?.onlyA || 0 }})</span>
            </span>
            <span class="flex items-center gap-2">
              <span class="w-3 h-3 rounded-full bg-[#ff4d4d] shadow-[0_0_8px_rgba(255,77,77,0.5)]"></span>
              <span class="text-gray-400">仅B有 ({{ stats?.onlyB || 0 }})</span>
            </span>
          </div>
        </div>

        <!-- Vue Flow Canvas -->
        <div class="flex-1 relative">
          <VueFlow
            v-if="chainA && chainB"
            :id="'vue-flow-compare'"
            v-model:nodes="nodes"
            v-model:edges="edges"
            :default-zoom="0.7"
            :min-zoom="0.2"
            :max-zoom="4"
            :fit-view-on-init="true"
            class="bg-[#0a0a0f]"
            @node-click="onNodeClick"
          >
            <template #node-gadget="props">
              <GadgetNode v-bind="props" />
            </template>
            <template #edge-streaming="props">
              <StreamingEdge v-bind="props" />
            </template>
            <Background pattern-color="#1a1a2e" :gap="24" />
            <Controls position="bottom-right" />
            <MiniMap
              position="bottom-left"
              :node-color="(node: any) => getNodeColorByType(node.data?.type, node.data?.isCommon, node.data?.isOnlyB)"
              :node-stroke-color="(node: any) => getNodeColorByType(node.data?.type, node.data?.isCommon, node.data?.isOnlyB)"
              :node-stroke-width="3"
              :mask-color="'rgba(10, 10, 15, 0.7)'"
            />
          </VueFlow>
          <div v-else class="flex items-center justify-center h-full text-gray-500">
            <p>请选择两个 Chain 进行对比</p>
          </div>
        </div>

        <!-- Step Player -->
        <div class="h-14 flex-shrink-0 border-t border-[#2d2d44] bg-[#13131f] px-5 flex items-center gap-4">
          <button @click="prevStep" :disabled="currentStep <= 0" class="w-8 h-8 rounded-lg bg-[#1a1a2e] hover:bg-[#2d2d44] flex items-center justify-center text-gray-400 disabled:opacity-30">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
              <polygon points="19 20 9 12 19 4 19 20"/>
            </svg>
          </button>
          <button @click="isPlaying ? pause() : play()" class="w-10 h-10 rounded-lg bg-gradient-to-r from-[#00ff88] to-[#00d4ff] flex items-center justify-center text-[#0a0a0f]">
            <svg v-if="isPlaying" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <rect x="6" y="4" width="4" height="16"/>
              <rect x="14" y="4" width="4" height="16"/>
            </svg>
            <svg v-else xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <polygon points="5 3 19 12 5 21 5 3"/>
            </svg>
          </button>
          <button @click="nextStep" :disabled="currentStep >= maxSteps - 1" class="w-8 h-8 rounded-lg bg-[#1a1a2e] hover:bg-[#2d2d44] flex items-center justify-center text-gray-400 disabled:opacity-30">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
              <polygon points="5 4 15 12 5 20 5 4"/>
            </svg>
          </button>
          <div class="flex-1 flex flex-col gap-1">
            <div class="flex items-center justify-between text-xs">
              <span class="text-gray-400">同步步进 <span class="text-white font-mono">{{ currentStep + 1 }}</span> / {{ maxSteps }}</span>
              <span class="text-gray-500">{{ isPlaying ? '播放中...' : '已暂停' }}</span>
            </div>
            <div class="h-1.5 bg-[#1a1a2e] rounded-full overflow-hidden">
              <div class="h-full bg-gradient-to-r from-[#00ff88] to-[#00d4ff] transition-all duration-300" :style="{ width: `${((currentStep + 1) / maxSteps) * 100}%` }" />
            </div>
          </div>
        </div>
      </div>

      <!-- Code Diff Panel -->
      <div
        class="flex-shrink-0 border-l border-[#2d2d44] bg-[#13131f] flex flex-col transition-all duration-300"
        :class="isCodePanelExpanded ? 'w-[700px]' : 'w-[400px]'"
      >
        <div class="h-12 flex-shrink-0 border-b border-[#2d2d44] bg-[#1a1a2e] px-4 flex items-center justify-between">
          <h3 class="text-sm font-semibold text-white">代码对比</h3>
          <div class="flex items-center gap-2">
            <button
              v-if="selectedNodeA || selectedNodeB"
              @click="selectedNodeA = null; selectedNodeB = null; isCodePanelExpanded = false"
              class="text-xs text-gray-500 hover:text-white"
            >
              清除选择
            </button>
            <button
              @click="isCodePanelExpanded = !isCodePanelExpanded"
              class="w-8 h-8 rounded-lg bg-[#252536] hover:bg-[#3d3d5c] flex items-center justify-center text-gray-400"
              :title="isCodePanelExpanded ? '收起' : '展开'"
            >
              <svg v-if="isCodePanelExpanded" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M4 14h6v6"/>
                <path d="M20 10h-6V4"/>
                <path d="M14 10 7.3 4.3"/>
                <path d="M21 20 10 10"/>
              </svg>
              <svg v-else xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M15 3h6v6"/>
                <path d="M9 21H3v-6"/>
                <path d="M21 3l-7 7"/>
                <path d="M3 21l7-7"/>
              </svg>
            </button>
          </div>
        </div>

        <div class="flex-1 overflow-auto p-4">
          <div v-if="!selectedNodeA && !selectedNodeB" class="text-center text-gray-500 py-20">
            <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" class="mx-auto mb-4 opacity-50">
              <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/>
              <polyline points="14 2 14 8 20 8"/>
            </svg>
            <p class="text-sm">点击图谱中的节点</p>
            <p class="text-xs mt-1 opacity-70">选择两个节点进行代码对比</p>
          </div>

          <div v-else-if="codeDiff" class="space-y-4">
            <!-- Diff Header -->
            <div class="space-y-2">
              <div class="flex items-center justify-between text-xs">
                <div class="flex-1 min-w-0">
                  <div class="text-[#00d4ff] font-mono truncate">{{ codeDiff.classNameA }}</div>
                  <div class="text-white font-mono">{{ codeDiff.methodNameA }}()</div>
                </div>
                <div class="px-3">
                  <span class="text-gray-500">VS</span>
                </div>
                <div class="flex-1 min-w-0 text-right">
                  <div class="text-[#ff4d4d] font-mono truncate">{{ codeDiff.classNameB }}</div>
                  <div class="text-white font-mono">{{ codeDiff.methodNameB }}()</div>
                </div>
              </div>

              <!-- Diff Indicators -->
              <div class="flex flex-wrap gap-2">
                <div v-if="codeDiff.isIdentical" class="px-2 py-1 rounded bg-green-500/10 text-green-400 text-xs border border-green-500/30">
                  代码完全相同
                </div>
                <div v-else-if="codeDiff.isSameClass && codeDiff.isSameMethod" class="px-2 py-1 rounded bg-yellow-500/10 text-yellow-400 text-xs border border-yellow-500/30">
                  同类同方法 - {{ codeDiff.diffLines.length }} 行差异
                </div>
                <div v-else-if="codeDiff.isSameClass" class="px-2 py-1 rounded bg-orange-500/10 text-orange-400 text-xs border border-orange-500/30">
                  同类不同方法
                </div>
                <div v-else class="px-2 py-1 rounded bg-red-500/10 text-red-400 text-xs border border-red-500/30">
                  完全不同的类
                </div>
              </div>
            </div>

            <!-- Side by Side Code -->
            <div class="grid gap-2" :class="isCodePanelExpanded ? 'grid-cols-2' : 'grid-cols-1'">
              <!-- Chain A Code -->
              <div class="bg-[#0a0a0f] rounded-lg border border-[#2d2d44] overflow-hidden">
                <div class="px-3 py-2 bg-[#1a1a2e] border-b border-[#2d2d44] flex items-center justify-between">
                  <span class="text-xs text-[#00d4ff]">Chain A</span>
                  <span v-if="codeDiff.diffLines.length > 0 && !codeDiff.isIdentical" class="text-[10px] text-yellow-400">
                    {{ codeDiff.diffLines.length }} 处差异
                  </span>
                </div>
                <CodePanel
                  v-if="selectedNodeA?.codeSnippet"
                  :code="selectedNodeA.codeSnippet"
                  :highlight-lines="selectedNodeA.highlightLines"
                  :diff-lines="codeDiff.isSameClass ? codeDiff.diffLines : []"
                />
                <div v-else class="p-4 text-xs text-gray-500">无代码片段</div>
              </div>

              <!-- Chain B Code (only shown when expanded or has content) -->
              <div v-if="isCodePanelExpanded" class="bg-[#0a0a0f] rounded-lg border border-[#2d2d44] overflow-hidden">
                <div class="px-3 py-2 bg-[#1a1a2e] border-b border-[#2d2d44] flex items-center justify-between">
                  <span class="text-xs text-[#ff4d4d]">Chain B</span>
                  <span v-if="codeDiff.diffLines.length > 0 && !codeDiff.isIdentical" class="text-[10px] text-yellow-400">
                    {{ codeDiff.diffLines.length }} 处差异
                  </span>
                </div>
                <CodePanel
                  v-if="selectedNodeB?.codeSnippet"
                  :code="selectedNodeB.codeSnippet"
                  :highlight-lines="selectedNodeB.highlightLines"
                  :diff-lines="codeDiff.isSameClass ? codeDiff.diffLines : []"
                />
                <div v-else class="p-4 text-xs text-gray-500">无代码片段</div>
              </div>
            </div>

            <!-- Diff Lines Detail (when expanded) -->
            <div v-if="isCodePanelExpanded && codeDiff.diffLines.length > 0 && !codeDiff.isIdentical" class="bg-[#1a1a2e] rounded-lg border border-[#2d2d44] p-3">
              <div class="text-xs text-gray-400 mb-2">差异行号</div>
              <div class="flex flex-wrap gap-1">
                <span
                  v-for="line in codeDiff.diffLines.slice(0, 20)"
                  :key="line"
                  class="px-1.5 py-0.5 rounded text-[10px] bg-yellow-500/10 text-yellow-400 border border-yellow-500/30"
                >
                  第 {{ line }} 行
                </span>
                <span v-if="codeDiff.diffLines.length > 20" class="text-[10px] text-gray-500 px-1">
                  +{{ codeDiff.diffLines.length - 20 }} 更多
                </span>
              </div>
            </div>
          </div>

          <!-- Single Selection State -->
          <div v-else-if="selectedNodeA || selectedNodeB" class="space-y-4">
            <div class="text-center text-gray-500 py-4 bg-[#1a1a2e] rounded-lg border border-[#2d2d44]">
              <p class="text-sm">已选择一个节点</p>
              <p class="text-xs mt-1">请点击另一条链的节点进行对比</p>
            </div>
            <div v-if="selectedNodeA" class="bg-[#0a0a0f] rounded-lg border border-[#2d2d44] overflow-hidden">
              <div class="px-3 py-2 bg-[#1a1a2e] border-b border-[#2d2d44] text-xs text-[#00d4ff]">
                Chain A - {{ selectedNodeA.className.split('.').pop() }}.{{ selectedNodeA.methodName }}()
              </div>
              <CodePanel :code="selectedNodeA.codeSnippet" :highlight-lines="selectedNodeA.highlightLines" />
            </div>
            <div v-if="selectedNodeB" class="bg-[#0a0a0f] rounded-lg border border-[#2d2d44] overflow-hidden">
              <div class="px-3 py-2 bg-[#1a1a2e] border-b border-[#2d2d44] text-xs text-[#ff4d4d]">
                Chain B - {{ selectedNodeB.className.split('.').pop() }}.{{ selectedNodeB.methodName }}()
              </div>
              <CodePanel :code="selectedNodeB.codeSnippet" :highlight-lines="selectedNodeB.highlightLines" />
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
:deep(.vue-flow__node) {
  border: none !important;
  background: transparent !important;
  padding: 0 !important;
}

:deep(.vue-flow__handle) {
  width: 6px;
  height: 6px;
  background: #00d4ff;
  border: 2px solid #0a0a0f;
  opacity: 0.6;
}

:deep(.vue-flow__handle:hover) {
  opacity: 1;
}

:deep(.vue-flow__controls) {
  background: rgba(19, 19, 31, 0.9);
  border: 1px solid #2d2d44;
  border-radius: 8px;
  padding: 4px;
}

:deep(.vue-flow__controls-button) {
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

:deep(.vue-flow__controls-button:hover) {
  background: rgba(0, 212, 255, 0.1);
  color: white;
}

:deep(.vue-flow__attribution) {
  display: none;
}

:deep(.vue-flow__minimap) {
  background: rgba(19, 19, 31, 0.95);
  border: 1px solid #2d2d44;
  border-radius: 8px;
  overflow: hidden;
}

:deep(.vue-flow__minimap-mask) {
  fill: rgba(10, 10, 15, 0.7);
}
</style>