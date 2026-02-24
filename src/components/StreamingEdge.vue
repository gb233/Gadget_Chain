<script setup lang="ts">
import { computed } from 'vue'
import { BaseEdge, getSmoothStepPath } from '@vue-flow/core'
import type { InvocationType } from '../data/gadgets/types'

const props = defineProps<{
  id: string
  sourceX: number
  sourceY: number
  targetX: number
  targetY: number
  sourcePosition: any
  targetPosition: any
  data?: {
    invocationType: InvocationType
    label: string
    isActive?: boolean
  }
}>()

const path = computed(() =>
  getSmoothStepPath({
    sourceX: props.sourceX,
    sourceY: props.sourceY,
    targetX: props.targetX,
    targetY: props.targetY,
    sourcePosition: props.sourcePosition,
    targetPosition: props.targetPosition,
    borderRadius: 8,
    offset: 20,
  })
)

const edgeColors = {
  direct: '#2d2d44',
  reflection: '#a855f7',
  proxy: '#f59e0b',
  override: '#00d4ff',
}

const activeColors = {
  direct: '#00ff88',
  reflection: '#a855f7',
  proxy: '#f59e0b',
  override: '#00d4ff',
}

const invocationType = computed(() => props.data?.invocationType || 'direct')
const isActive = computed(() => props.data?.isActive || false)

const strokeColor = computed(() => {
  return isActive.value
    ? activeColors[invocationType.value]
    : edgeColors[invocationType.value]
})

const isAnimated = computed(() => {
  return invocationType.value === 'reflection' ||
         invocationType.value === 'proxy' ||
         isActive.value
})
</script>

<template>
  <g class="streaming-edge">
    <!-- Base Edge -->
    <BaseEdge
      :id="id"
      :path="path[0]"
      :style="{
        stroke: strokeColor,
        strokeWidth: isActive ? 3 : 2,
        opacity: isActive ? 1 : 0.6,
        transition: 'all 0.3s ease'
      }"
    />

    <!-- Animated Flow Layer -->
    <path
      v-if="isAnimated"
      :d="path[0]"
      fill="none"
      :stroke="activeColors[invocationType]"
      stroke-width="3"
      class="animated-path"
      :style="{
        filter: `drop-shadow(0 0 4px ${activeColors[invocationType]})`
      }"
    />

    <!-- Edge Label -->
    <foreignObject
      v-if="data?.label"
      :x="(sourceX + targetX) / 2 - 40"
      :y="(sourceY + targetY) / 2 - 10"
      width="80"
      height="20"
    >
      <div
        xmlns="http://www.w3.org/1999/xhtml"
        class="flex items-center justify-center h-full"
      >
        <span
          class="text-[9px] px-2 py-0.5 rounded-full font-medium whitespace-nowrap"
          :style="{
            backgroundColor: isActive ? `${activeColors[invocationType]}33` : '#0a0a0f',
            color: isActive ? activeColors[invocationType] : '#6b7280',
            border: `1px solid ${isActive ? activeColors[invocationType] : '#2d2d44'}`
          }"
        >
          {{ data.label }}
        </span>
      </div>
    </foreignObject>
  </g>
</template>

<style scoped>
.animated-path {
  stroke-dasharray: 8, 4;
  animation: flow 2s linear infinite;
}

@keyframes flow {
  from {
    stroke-dashoffset: 24;
  }
  to {
    stroke-dashoffset: 0;
  }
}
</style>