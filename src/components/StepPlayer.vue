<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  currentStep: number
  totalSteps: number
  isPlaying: boolean
}>()

const emit = defineEmits<{
  (e: 'prev'): void
  (e: 'next'): void
  (e: 'play'): void
  (e: 'pause'): void
  (e: 'reset'): void
}>()

const progress = computed(() => {
  if (props.totalSteps === 0) return 0
  return ((props.currentStep + 1) / props.totalSteps) * 100
})

const currentStepDisplay = computed(() => {
  return props.currentStep >= 0 ? props.currentStep + 1 : 0
})
</script>

<template>
  <div class="h-full flex items-center gap-4">
    <!-- Control Buttons -->
    <div class="flex items-center gap-1">
      <button
        @click="$emit('reset')"
        class="w-8 h-8 rounded-lg bg-[#1a1a2e] hover:bg-[#2d2d44] transition-colors flex items-center justify-center text-gray-400 hover:text-white"
        title="重置"
      >
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 12"/>
          <path d="M3 3v9h9"/>
        </svg>
      </button>

      <button
        @click="$emit('prev')"
        :disabled="currentStep <= 0"
        class="w-8 h-8 rounded-lg bg-[#1a1a2e] hover:bg-[#2d2d44] transition-colors flex items-center justify-center text-gray-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
        title="上一步"
      >
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="19 20 9 12 19 4 19 20"/>
          <line x1="5" y1="19" x2="5" y2="5"/>
        </svg>
      </button>

      <button
        @click="isPlaying ? $emit('pause') : $emit('play')"
        class="w-10 h-10 rounded-lg bg-gradient-to-r from-[#00ff88] to-[#00d4ff] hover:opacity-90 transition-all flex items-center justify-center text-[#0a0a0f]"
        title="播放/暂停"
      >
        <svg v-if="isPlaying" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
          <rect x="6" y="4" width="4" height="16"/>
          <rect x="14" y="4" width="4" height="16"/>
        </svg>
        <svg v-else xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
          <polygon points="5 3 19 12 5 21 5 3"/>
        </svg>
      </button>

      <button
        @click="$emit('next')"
        :disabled="currentStep >= totalSteps - 1"
        class="w-8 h-8 rounded-lg bg-[#1a1a2e] hover:bg-[#2d2d44] transition-colors flex items-center justify-center text-gray-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
        title="下一步"
      >
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="5 4 15 12 5 20 5 4"/>
          <line x1="19" y1="5" x2="19" y2="19"/>
        </svg>
      </button>
    </div>

    <!-- Progress -->
    <div class="flex-1 flex flex-col gap-1.5 min-w-[150px]">
      <div class="flex items-center justify-between text-xs">
        <span class="text-gray-400">
          步骤 <span class="text-white font-mono">{{ currentStepDisplay }}</span> / {{ totalSteps }}
        </span>
        <span class="text-gray-500">
          {{ isPlaying ? '播放中...' : '已暂停' }}
        </span>
      </div>

      <!-- Progress Bar -->
      <div class="h-1.5 bg-[#1a1a2e] rounded-full overflow-hidden">
        <div
          class="h-full bg-gradient-to-r from-[#00ff88] to-[#00d4ff] transition-all duration-300"
          :style="{ width: `${progress}%` }"
        />
      </div>
    </div>

    <!-- Current Status -->
    <div class="hidden md:flex items-center gap-2 px-3 py-1.5 bg-[#1a1a2e] rounded-lg">
      <span class="text-[10px] text-gray-500">当前</span>
      <span class="text-xs font-medium text-white">
        {{ currentStep >= 0 ? `Step ${currentStep + 1}` : '准备就绪' }}
      </span>
    </div>
  </div>
</template>
