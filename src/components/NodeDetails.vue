<script setup lang="ts">
import { ref, computed } from 'vue'
import type { GadgetNode, GadgetEdge, GadgetChain } from '../data/gadgets/types'
import CodePanel from './CodePanel.vue'

const props = defineProps<{
  node: GadgetNode | null
  edge: GadgetEdge | null
  chain: GadgetChain | null
}>()

const emit = defineEmits<{
  (e: 'toggleExpand'): void
}>()

const isExpanded = ref(false)

const nodeTypeLabels = {
  source: '入口点 (Source)',
  gadget: '跳板 (Gadget)',
  sink: '执行点 (Sink)',
}

const nodeTypeColors = {
  source: { text: '#00ff88', bg: 'rgba(0, 255, 136, 0.1)', border: '#00ff88' },
  gadget: { text: '#00d4ff', bg: 'rgba(0, 212, 255, 0.1)', border: '#00d4ff' },
  sink: { text: '#ff4d4d', bg: 'rgba(255, 77, 77, 0.1)', border: '#ff4d4d' },
}

const invocationTypeLabels = {
  direct: '直接调用',
  reflection: '反射调用',
  proxy: '动态代理',
  override: '方法重写',
}

const invocationTypeColors = {
  direct: '#6b7280',
  reflection: '#a855f7',
  proxy: '#f59e0b',
  override: '#00d4ff',
}

function toggleExpand() {
  isExpanded.value = !isExpanded.value
  emit('toggleExpand')
}

const codeLanguage = computed(() => {
  if (!props.node) return 'java'
  // 根据类名判断语言
  if (props.node.className.includes('python') || props.node.className.includes('jython')) return 'python'
  if (props.node.className.includes('javascript') || props.node.className.includes('js')) return 'javascript'
  return 'java'
})
</script>

<template>
  <div
    :class="[
      'h-full flex flex-col bg-[#13131f] transition-all duration-300 ease-out',
      isExpanded ? 'w-[70vw] absolute right-0 top-16 bottom-0 z-50 shadow-2xl' : 'w-full relative'
    ]"
  >
    <!-- Header -->
    <div class="h-12 flex-shrink-0 border-b border-[#2d2d44] bg-[#1a1a2e] px-4 flex items-center justify-between">
      <h2 class="text-sm font-semibold text-white flex items-center gap-2">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-[#00d4ff]">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="16" x2="12" y2="12"/>
          <line x1="12" y1="8" x2="12.01" y2="8"/>
        </svg>
        节点详情
      </h2>
      <button
        @click="toggleExpand"
        class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
        :class="isExpanded
          ? 'bg-[#ff4d4d]/10 text-[#ff4d4d] hover:bg-[#ff4d4d]/20'
          : 'bg-[#00d4ff]/10 text-[#00d4ff] hover:bg-[#00d4ff]/20'"
      >
        <svg v-if="isExpanded" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
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
        {{ isExpanded ? '收起' : '展开' }}
      </button>
    </div>

    <!-- Content -->
    <div class="flex-1 overflow-y-auto p-4">
      <!-- Empty State -->
      <div v-if="!node && !edge" class="flex flex-col items-center justify-center h-40 text-gray-500">
        <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="mb-3 opacity-50">
          <circle cx="12" cy="12" r="10"/>
          <path d="M12 16v-4"/>
          <path d="M12 8h.01"/>
        </svg>
        <p class="text-sm">点击节点或连线</p>
        <p class="text-xs mt-1 opacity-70">查看详细信息</p>
      </div>

      <!-- Node Details -->
      <template v-if="node">
        <div class="grid gap-4" :class="isExpanded ? 'grid-cols-2' : 'grid-cols-1'">
          <!-- Left Column: Basic Info -->
          <div>
            <!-- Type Badge -->
            <div class="mb-4">
              <span
                class="text-[10px] font-bold px-3 py-1.5 rounded-full border"
                :style="{
                  color: nodeTypeColors[node.type].text,
                  backgroundColor: nodeTypeColors[node.type].bg,
                  borderColor: nodeTypeColors[node.type].border
                }"
              >
                {{ nodeTypeLabels[node.type] }}
              </span>
            </div>

            <!-- Class & Method -->
            <div class="space-y-3 mb-4">
              <div>
                <div class="text-[10px] text-gray-500 uppercase mb-1.5 tracking-wider">类名</div>
                <div class="text-sm text-[#00d4ff] font-mono bg-[#0a0a0f] px-3 py-2.5 rounded-lg border border-[#2d2d44] break-all">
                  {{ node.className }}
                </div>
              </div>

              <div>
                <div class="text-[10px] text-gray-500 uppercase mb-1.5 tracking-wider">方法</div>
                <div class="text-base text-white font-mono bg-[#0a0a0f] px-3 py-2.5 rounded-lg border border-[#2d2d44]">
                  {{ node.methodName }}()
                </div>
              </div>
            </div>

            <!-- Description -->
            <div class="mb-4">
              <div class="text-[10px] text-gray-500 uppercase mb-1.5 tracking-wider">说明</div>
              <p class="text-sm text-gray-300 leading-relaxed bg-[#1a1a2e] px-3 py-2.5 rounded-lg border border-[#2d2d44]">
                {{ node.description }}
              </p>
            </div>
          </div>

          <!-- Right Column: Code (or full width when not expanded) -->
          <div v-if="node.codeSnippet" :class="isExpanded ? '' : 'mt-4'">
            <div class="flex items-center justify-between mb-2">
              <div class="text-[10px] text-gray-500 uppercase tracking-wider">关键代码</div>
              <div class="flex items-center gap-2">
                <span class="text-[10px] px-2 py-0.5 rounded bg-[#ff4d4d]/10 text-[#ff4d4d] border border-[#ff4d4d]/30">
                  第 {{ node.highlightLines.join(', ') }} 行
                </span>
              </div>
            </div>
            <div class="bg-[#0a0a0f] rounded-lg border border-[#2d2d44] overflow-hidden">
              <CodePanel
                :code="node.codeSnippet"
                :highlight-lines="node.highlightLines"
                :language="codeLanguage"
              />
            </div>
          </div>
        </div>
      </template>

      <!-- Edge Details -->
      <template v-if="edge">
        <div class="space-y-4">
          <div class="bg-[#1a1a2e] rounded-lg border border-[#2d2d44] p-4">
            <div class="text-[10px] text-gray-500 uppercase mb-3 tracking-wider">调用关系</div>
            <div class="flex items-center gap-3 text-sm">
              <span class="text-[#00d4ff] font-mono bg-[#0a0a0f] px-3 py-1.5 rounded">{{ edge.source }}</span>
              <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-gray-500">
                <path d="M5 12h14"/>
                <path d="m12 5 7 7-7 7"/>
              </svg>
              <span class="text-[#ff4d4d] font-mono bg-[#0a0a0f] px-3 py-1.5 rounded">{{ edge.target }}</span>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div class="bg-[#1a1a2e] rounded-lg border border-[#2d2d44] p-4">
              <div class="text-[10px] text-gray-500 uppercase mb-2 tracking-wider">调用类型</div>
              <div class="text-sm font-medium flex items-center gap-2" :style="{ color: invocationTypeColors[edge.invocationType] }">
                <span class="w-2 h-2 rounded-full" :style="{ backgroundColor: invocationTypeColors[edge.invocationType] }"></span>
                {{ invocationTypeLabels[edge.invocationType] }}
              </div>
            </div>

            <div class="bg-[#1a1a2e] rounded-lg border border-[#2d2d44] p-4">
              <div class="text-[10px] text-gray-500 uppercase mb-2 tracking-wider">标签</div>
              <div class="text-sm text-gray-300">{{ edge.label }}</div>
            </div>
          </div>

          <div class="bg-[#1a1a2e] rounded-lg border border-[#2d2d44] p-4">
            <div class="text-[10px] text-gray-500 uppercase mb-2 tracking-wider">说明</div>
            <p class="text-sm text-gray-300 leading-relaxed">
              {{ edge.description }}
            </p>
          </div>
        </div>
      </template>
    </div>

    <!-- Footer -->
    <div v-if="chain" class="h-10 flex-shrink-0 border-t border-[#2d2d44] bg-[#1a1a2e] px-4 flex items-center justify-between text-[10px]">
      <div class="text-gray-500 truncate flex items-center gap-2">
        <span class="text-gray-600">依赖:</span>
        <span class="text-gray-400">{{ chain.metadata.targetDependency }}</span>
      </div>
      <div class="text-gray-500 flex items-center gap-2">
        <span class="text-gray-600">作者:</span>
        <span class="text-gray-400">@{{ chain.metadata.author }}</span>
      </div>
    </div>
  </div>
</template>
