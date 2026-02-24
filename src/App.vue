<script setup lang="ts">
import { ref } from 'vue'
import GadgetGraph from './components/GadgetGraph.vue'
import PayloadSelector from './components/PayloadSelector.vue'
import CompareView from './components/CompareView.vue'
import { urldns, commonsCollections1 } from './data/gadgets'
import type { GadgetChain } from './data/gadgets'

const selectedChain = ref<GadgetChain>(urldns)
const isCompareMode = ref(false)
const compareChainA = ref<GadgetChain>(urldns)
const compareChainB = ref<GadgetChain>(commonsCollections1)

function onChainSelect(chain: GadgetChain) {
  selectedChain.value = chain
}

function toggleCompareMode() {
  isCompareMode.value = !isCompareMode.value
  if (isCompareMode.value) {
    compareChainA.value = selectedChain.value
  }
}
</script>

<template>
  <div class="h-screen flex flex-col bg-[#0a0a0f] text-white overflow-hidden">
    <!-- Header -->
    <header class="h-16 flex-shrink-0 border-b border-[#2d2d44] bg-[#13131f] flex items-center justify-between px-6">
      <!-- Logo -->
      <div class="flex items-center gap-3">
        <div class="w-9 h-9 rounded-lg bg-gradient-to-br from-[#00ff88] to-[#00d4ff] flex items-center justify-center shadow-lg shadow-[#00ff88]/20">
          <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#0a0a0f" stroke-width="2.5">
            <circle cx="12" cy="12" r="10"/>
            <path d="M12 6v6l4 2"/>
          </svg>
        </div>
        <div>
          <h1 class="text-lg font-bold bg-gradient-to-r from-[#00ff88] to-[#00d4ff] bg-clip-text text-transparent">
            Gadget_Chain
          </h1>
          <p class="text-[10px] text-gray-500">Java反序列化漏洞Gadget Chain可视化图谱</p>
        </div>
      </div>

      <!-- Right Toolbar -->
      <div class="flex items-center gap-3">
        <!-- Compare Mode Toggle -->
        <button
          @click="toggleCompareMode"
          class="flex items-center gap-2 px-3 py-2 rounded-lg transition-all"
          :class="isCompareMode
            ? 'bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/50'
            : 'bg-[#1a1a2e] hover:bg-[#252536] border border-[#2d2d44] text-gray-400'"
        >
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 3v18" />
            <path d="M8 8l-4 4 4 4" />
            <path d="M16 16l4-4-4-4" />
          </svg>
          <span class="text-sm">{{ isCompareMode ? '退出对比' : '对比模式' }}</span>
        </button>

        <PayloadSelector v-if="!isCompareMode" :model-value="selectedChain" @select="onChainSelect" />

        <a
          href="https://github.com/gb233/Gadget_Chain"
          target="_blank"
          rel="noopener noreferrer"
          class="w-9 h-9 rounded-lg bg-[#1a1a2e] hover:bg-[#252536] border border-[#2d2d44] flex items-center justify-center transition-all"
          title="查看GitHub仓库"
        >
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="currentColor" class="text-gray-400 hover:text-white">
            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
          </svg>
        </a>
      </div>
    </header>

    <!-- Main Content -->
    <main class="flex-1 overflow-hidden">
      <CompareView
        v-if="isCompareMode"
        v-model:chain-a="compareChainA"
        v-model:chain-b="compareChainB"
        @close="isCompareMode = false"
      />
      <GadgetGraph v-else :chain="selectedChain" />
    </main>

    <!-- Footer Legend (hidden in compare mode) -->
    <footer v-if="!isCompareMode" class="h-10 flex-shrink-0 border-t border-[#2d2d44] bg-[#13131f] px-6 flex items-center justify-between text-xs">
      <div class="flex items-center gap-6">
        <span class="flex items-center gap-2">
          <span class="w-2.5 h-2.5 rounded-full bg-[#00ff88] shadow-[0_0_8px_rgba(0,255,136,0.5)]"></span>
          <span class="text-gray-400">Source (入口)</span>
        </span>
        <span class="flex items-center gap-2">
          <span class="w-2.5 h-2.5 rounded-full bg-[#00d4ff] shadow-[0_0_8px_rgba(0,212,255,0.5)]"></span>
          <span class="text-gray-400">Gadget (跳板)</span>
        </span>
        <span class="flex items-center gap-2">
          <span class="w-2.5 h-2.5 rounded-full bg-[#ff4d4d] shadow-[0_0_8px_rgba(255,77,77,0.5)]"></span>
          <span class="text-gray-400">Sink (执行)</span>
        </span>
        <span class="flex items-center gap-2">
          <span class="w-6 h-0.5 bg-gradient-to-r from-transparent via-[#a855f7] to-transparent"></span>
          <span class="text-gray-400">反射/代理调用</span>
        </span>
      </div>

      <div class="text-gray-500">
        基于 <a href="https://github.com/frohoff/ysoserial" target="_blank" class="text-[#00d4ff] hover:underline">ysoserial</a> 项目构建
      </div>
    </footer>
  </div>
</template>

<style>
/* Vue Flow imports - must be first */
@import '@vue-flow/core/dist/style.css';
@import '@vue-flow/core/dist/theme-default.css';
@import '@vue-flow/minimap/dist/style.css';

/* Global styles */
* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
}

/* Vue Flow custom styles */
.vue-flow {
  background: #0a0a0f;
}

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
</style>
