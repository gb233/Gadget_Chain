<script setup lang="ts">
import { ref, computed } from 'vue'
import { allGadgetChains, searchGadgetChains, chainsByCategory } from '../data/gadgets'
import type { GadgetChain } from '../data/gadgets'

const props = defineProps<{
  modelValue?: GadgetChain | null
}>()

const emit = defineEmits<{
  (e: 'select', chain: GadgetChain): void
}>()

const isOpen = ref(false)
const searchQuery = ref('')
const selectedCategory = ref<string | null>(null)

const categories = Object.keys(chainsByCategory)

const filteredChains = computed(() => {
  let chains = allGadgetChains

  // 先按分类筛选
  if (selectedCategory.value) {
    chains = chainsByCategory[selectedCategory.value as keyof typeof chainsByCategory] || []
  }

  // 再按搜索词筛选
  if (searchQuery.value) {
    const lowerQuery = searchQuery.value.toLowerCase()
    chains = chains.filter(chain =>
      chain.metadata.name.toLowerCase().includes(lowerQuery) ||
      chain.metadata.description.toLowerCase().includes(lowerQuery) ||
      chain.metadata.targetDependency.toLowerCase().includes(lowerQuery)
    )
  }

  return chains
})

function selectChain(chain: GadgetChain) {
  emit('select', chain)
  isOpen.value = false
  searchQuery.value = ''
  selectedCategory.value = null
}

function toggleCategory(category: string) {
  selectedCategory.value = selectedCategory.value === category ? null : category
}

const complexityColors = {
  Low: { bg: 'rgba(34, 197, 94, 0.15)', text: '#22c55e', border: 'rgba(34, 197, 94, 0.4)' },
  Medium: { bg: 'rgba(234, 179, 8, 0.15)', text: '#eab308', border: 'rgba(234, 179, 8, 0.4)' },
  High: { bg: 'rgba(239, 68, 68, 0.15)', text: '#ef4444', border: 'rgba(239, 68, 68, 0.4)' },
}

const categoryIcons: Record<string, string> = {
  'Pure JDK': '☕',
  'Commons Collections': '📦',
  'Spring': '🌱',
  'Hibernate': '🐘',
  'JBoss': '🎩',
  'Scripting': '📜',
  'Web Frameworks': '🌐',
  'Others': '📎',
}
</script>

<template>
  <div class="relative">
    <!-- Trigger Button -->
    <button
      @click="isOpen = !isOpen"
      class="flex items-center gap-2 px-3 py-2 bg-[#1a1a2e] hover:bg-[#252536] border border-[#2d2d44] rounded-lg transition-all text-left min-w-[200px]"
    >
      <div class="flex-1 min-w-0">
        <div class="text-[10px] text-gray-500 uppercase tracking-wider">Payload</div>
        <div class="text-sm text-white font-medium">
          {{ modelValue?.metadata.name || '选择...' }}
        </div>
      </div>
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="16"
        height="16"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        class="text-gray-400 transition-transform flex-shrink-0"
        :class="{ 'rotate-180': isOpen }"
      >
        <path d="m6 9 6 6 6-6" />
      </svg>
    </button>

    <!-- Sidebar Drawer -->
    <Transition
      enter-active-class="transition-transform duration-300 ease-out"
      enter-from-class="translate-x-full"
      enter-to-class="translate-x-0"
      leave-active-class="transition-transform duration-300 ease-in"
      leave-from-class="translate-x-0"
      leave-to-class="translate-x-full"
    >
      <aside
        v-if="isOpen"
        class="fixed right-0 top-16 bottom-0 w-[420px] bg-[#13131f] border-l border-[#2d2d44] z-50 shadow-2xl flex flex-col"
      >
        <!-- Header -->
        <div class="p-4 border-b border-[#2d2d44]">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-lg font-semibold text-white">选择 Gadget Chain</h2>
            <button
              @click="isOpen = false"
              class="w-8 h-8 rounded-lg hover:bg-[#252536] flex items-center justify-center text-gray-400 transition-colors"
            >
              <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M18 6 6 18" />
                <path d="m6 6 12 12" />
              </svg>
            </button>
          </div>

          <!-- Search -->
          <div class="relative">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
            >
              <circle cx="11" cy="11" r="8" />
              <path d="m21 21-4.3-4.3" />
            </svg>
            <input
              v-model="searchQuery"
              type="text"
              placeholder="搜索 payload、依赖库..."
              class="w-full pl-10 pr-3 py-2.5 bg-[#0a0a0f] border border-[#2d2d44] rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-[#00d4ff] transition-colors"
            />
          </div>
        </div>

        <!-- Category Filter -->
        <div class="px-4 py-3 border-b border-[#2d2d44]">
          <div class="text-[10px] text-gray-500 uppercase tracking-wider mb-2">分类筛选</div>
          <div class="flex flex-wrap gap-2">
            <button
              v-for="category in categories"
              :key="category"
              @click="toggleCategory(category)"
              class="px-2.5 py-1 rounded-md text-xs border transition-all"
              :class="selectedCategory === category
                ? 'bg-[#00d4ff]/20 border-[#00d4ff]/50 text-[#00d4ff]'
                : 'bg-[#1a1a2e] border-[#2d2d44] text-gray-400 hover:border-[#3d3d5c]'"
            >
              {{ categoryIcons[category] || '📋' }} {{ category }}
            </button>
          </div>
        </div>

        <!-- Chain List -->
        <div class="flex-1 overflow-y-auto p-4">
          <div class="space-y-2">
            <div
              v-for="chain in filteredChains"
              :key="chain.metadata.chainId"
              @click="selectChain(chain)"
              class="group p-3 rounded-xl border cursor-pointer transition-all"
              :class="modelValue?.metadata.chainId === chain.metadata.chainId
                ? 'bg-[#00d4ff]/10 border-[#00d4ff]/50'
                : 'bg-[#1a1a2e] border-[#2d2d44] hover:border-[#3d3d5c] hover:bg-[#252536]'"
            >
              <!-- Name & Complexity -->
              <div class="flex items-start justify-between gap-3 mb-2">
                <h3 class="font-medium text-white text-base leading-tight">
                  {{ chain.metadata.name }}
                </h3>
                <span
                  class="px-2 py-0.5 rounded text-[10px] font-medium border flex-shrink-0"
                  :style="{
                    backgroundColor: complexityColors[chain.metadata.complexity].bg,
                    color: complexityColors[chain.metadata.complexity].text,
                    borderColor: complexityColors[chain.metadata.complexity].border
                  }"
                >
                  {{ chain.metadata.complexity }}
                </span>
              </div>

              <!-- Dependency -->
              <div class="text-xs text-gray-400 mb-2 font-mono">
                {{ chain.metadata.targetDependency }}
              </div>

              <!-- Description -->
              <p class="text-xs text-gray-500 line-clamp-2 mb-2">
                {{ chain.metadata.description }}
              </p>

              <!-- Footer: Author & CVE -->
              <div class="flex items-center justify-between text-[10px] text-gray-600">
                <div class="flex items-center gap-2">
                  <span>@{{ chain.metadata.author }}</span>
                  <span v-if="chain.metadata.cve" class="text-[#ff4d4d]">
                    {{ chain.metadata.cve }}
                  </span>
                </div>
                <span class="text-gray-500">
                  {{ chain.nodes.length }} 节点
                </span>
              </div>

              <!-- Selected Indicator -->
              <div
                v-if="modelValue?.metadata.chainId === chain.metadata.chainId"
                class="mt-2 pt-2 border-t border-[#00d4ff]/20 flex items-center gap-1 text-[#00d4ff] text-xs"
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M20 6 9 17l-5-5" />
                </svg>
                当前选中
              </div>
            </div>
          </div>

          <!-- Empty State -->
          <div v-if="filteredChains.length === 0" class="p-8 text-center">
            <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-[#1a1a2e] flex items-center justify-center">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="text-gray-500">
                <circle cx="11" cy="11" r="8" />
                <path d="m21 21-4.3-4.3" />
              </svg>
            </div>
            <p class="text-sm text-gray-400">未找到匹配的 Payload</p>
            <button
              @click="searchQuery = ''; selectedCategory = null"
              class="mt-2 text-xs text-[#00d4ff] hover:underline"
            >
              清除筛选条件
            </button>
          </div>
        </div>

        <!-- Footer Stats -->
        <div class="p-3 border-t border-[#2d2d44] bg-[#0a0a0f]/50">
          <div class="flex items-center justify-between text-xs text-gray-500">
            <span>共 {{ allGadgetChains.length }} 个 Payload</span>
            <span v-if="filteredChains.length !== allGadgetChains.length">
              显示 {{ filteredChains.length }} 个
            </span>
          </div>
        </div>
      </aside>
    </Transition>

    <!-- Backdrop -->
    <Transition
      enter-active-class="transition-opacity duration-300"
      enter-from-class="opacity-0"
      enter-to-class="opacity-100"
      leave-active-class="transition-opacity duration-300"
      leave-from-class="opacity-100"
      leave-to-class="opacity-0"
    >
      <div
        v-if="isOpen"
        class="fixed inset-0 bg-black/60 backdrop-blur-sm z-40"
        @click="isOpen = false"
      />
    </Transition>
  </div>
</template>
