<script setup lang="ts">
import { computed, ref } from 'vue'
import { Handle, Position } from '@vue-flow/core'
import type { NodeType } from '../data/gadgets/types'

const props = defineProps<{
  data: {
    type: NodeType
    className: string
    methodName: string
    label: string
    description?: string
    isActive?: boolean
    isHighlighted?: boolean
    stepIndex?: number
  }
}>()

const showTooltip = ref(false)
let tooltipTimeout: ReturnType<typeof setTimeout> | null = null

const nodeColors = {
  source: {
    border: '#00ff88',
    bg: 'rgba(0, 255, 136, 0.1)',
    glow: '0 0 20px rgba(0, 255, 136, 0.4)',
  },
  gadget: {
    border: '#00d4ff',
    bg: 'rgba(0, 212, 255, 0.1)',
    glow: '0 0 20px rgba(0, 212, 255, 0.4)',
  },
  sink: {
    border: '#ff4d4d',
    bg: 'rgba(255, 77, 77, 0.1)',
    glow: '0 0 25px rgba(255, 77, 77, 0.5)',
  },
}

const typeLabels = {
  source: 'SOURCE',
  gadget: 'GADGET',
  sink: 'SINK',
}

const shortClassName = computed(() => {
  const parts = props.data.className.split('.')
  return parts[parts.length - 1]
})

const containerStyle = computed(() => {
  const style = nodeColors[props.data.type]
  return {
    borderLeft: `3px solid ${style.border}`,
    backgroundColor: props.data.isActive ? style.bg : '#1a1a2e',
    boxShadow: props.data.isActive ? style.glow : 'none',
    transform: props.data.isActive ? 'scale(1.02)' : 'scale(1)',
    transition: 'all 0.3s ease',
  }
})

function onMouseEnter() {
  if (tooltipTimeout) clearTimeout(tooltipTimeout)
  tooltipTimeout = setTimeout(() => {
    showTooltip.value = true
  }, 300)
}

function onMouseLeave() {
  if (tooltipTimeout) clearTimeout(tooltipTimeout)
  tooltipTimeout = setTimeout(() => {
    showTooltip.value = false
  }, 100)
}
</script>

<template>
  <div
    :style="containerStyle"
    class="w-[200px] p-3 cursor-pointer hover:scale-[1.02] border border-[#2d2d44] rounded-md relative"
    @mouseenter="onMouseEnter"
    @mouseleave="onMouseLeave"
  >
    <!-- Target Handle -->
    <Handle
      type="target"
      :position="Position.Left"
      class="w-2 h-2 !bg-[#2d2d44] !border-[#0a0a0f]"
    />

    <!-- Node Content -->
    <div class="flex flex-col gap-1.5">
      <!-- Type Badge -->
      <div class="flex items-center justify-between">
        <span
          class="text-[9px] font-bold px-1.5 py-0.5 rounded"
          :style="{ color: nodeColors[data.type].border, backgroundColor: nodeColors[data.type].bg }"
        >
          {{ typeLabels[data.type] }}
        </span>
        <span v-if="data.stepIndex !== undefined" class="text-[9px] text-gray-600">
          #{{ data.stepIndex + 1 }}
        </span>
      </div>

      <!-- Class Name -->
      <div class="text-[10px] text-gray-500 font-mono truncate">
        {{ shortClassName }}
      </div>

      <!-- Method Name -->
      <div
        class="font-mono font-semibold text-xs truncate"
        :style="{ color: nodeColors[data.type].border }"
      >
        {{ data.methodName }}()
      </div>
    </div>

    <!-- Source Handle -->
    <Handle
      type="source"
      :position="Position.Right"
      class="w-2 h-2 !bg-[#2d2d44] !border-[#0a0a0f]"
    />

    <!-- Hover Tooltip -->
    <Transition
      enter-active-class="transition-all duration-200 ease-out"
      enter-from-class="opacity-0 scale-95 translate-y-2"
      enter-to-class="opacity-100 scale-100 translate-y-0"
      leave-active-class="transition-all duration-150 ease-in"
      leave-from-class="opacity-100 scale-100 translate-y-0"
      leave-to-class="opacity-0 scale-95 translate-y-2"
    >
      <div
        v-if="showTooltip"
        class="absolute left-full top-0 ml-3 w-[320px] p-4 rounded-xl bg-[#1a1a2e] border border-[#2d2d44] shadow-2xl z-50 pointer-events-none"
        :style="{ borderLeftColor: nodeColors[data.type].border, borderLeftWidth: '3px' }"
      >
        <!-- Type Badge -->
        <div class="flex items-center justify-between mb-3">
          <span
            class="text-[10px] font-bold px-2 py-1 rounded"
            :style="{ color: nodeColors[data.type].border, backgroundColor: nodeColors[data.type].bg }"
          >
            {{ typeLabels[data.type] }}
          </span>
          <span v-if="data.stepIndex !== undefined" class="text-xs text-gray-500">
            Step {{ data.stepIndex + 1 }}
          </span>
        </div>

        <!-- Full Class Name -->
        <div class="mb-3">
          <div class="text-[10px] text-gray-500 uppercase tracking-wider mb-1">类名</div>
          <div class="text-sm text-[#00d4ff] font-mono break-all leading-tight">
            {{ data.className }}
          </div>
        </div>

        <!-- Method Name -->
        <div class="mb-3">
          <div class="text-[10px] text-gray-500 uppercase tracking-wider mb-1">方法</div>
          <div class="text-base text-white font-mono" :style="{ color: nodeColors[data.type].border }">
            {{ data.methodName }}()
          </div>
        </div>

        <!-- Description -->
        <div v-if="data.description" class="border-t border-[#2d2d44] pt-3 mt-3">
          <div class="text-[10px] text-gray-500 uppercase tracking-wider mb-1">说明</div>
          <p class="text-xs text-gray-300 leading-relaxed">{{ data.description }}</p>
        </div>
      </div>
    </Transition>
  </div>
</template>
