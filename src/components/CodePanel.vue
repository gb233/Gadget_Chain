<script setup lang="ts">
import { ref, watch, onMounted } from 'vue'
import { codeToHtml } from 'shiki'

const props = defineProps<{
  code: string
  highlightLines?: number[]
  diffLines?: number[]
  language?: string
}>()

const highlightedCode = ref('')
const isLoading = ref(true)

onMounted(async () => {
  await highlightCode()
})

watch(() => props.code, async () => {
  await highlightCode()
})

async function highlightCode() {
  isLoading.value = true
  try {
    highlightedCode.value = await codeToHtml(props.code, {
      lang: props.language || 'java',
      theme: 'one-dark-pro',
      transformers: [
        {
          line(node, line) {
            // P3 Fix: 支持两种高亮样式
            const isHighlightLine = props.highlightLines?.includes(line)
            const isDiffLine = props.diffLines?.includes(line)

            if (isDiffLine) {
              // 差异行使用黄色高亮
              node.properties.class = 'diff-line'
            } else if (isHighlightLine) {
              // 关键行使用红色高亮
              node.properties.class = 'highlighted-line'
            }
          }
        }
      ]
    })
  } catch (e) {
    // 如果Shiki失败，使用简单的高亮
    highlightedCode.value = `<pre class="simple-code">${escapeHtml(props.code)}</pre>`
  }
  isLoading.value = false
}

function escapeHtml(text: string): string {
  const div = document.createElement('div')
  div.textContent = text
  return div.innerHTML
}
</script>

<template>
  <div class="code-panel relative">
    <div v-if="isLoading" class="absolute inset-0 flex items-center justify-center bg-[#0a0a0f]">
      <div class="text-gray-500 text-sm">加载中...</div>
    </div>
    <div
      class="shiki-container overflow-x-auto"
      :class="{ 'opacity-0': isLoading }"
      v-html="highlightedCode"
    />
  </div>
</template>

<style scoped>
.code-panel {
  background: #0a0a0f;
  border-radius: 8px;
}

:deep(.shiki) {
  background: transparent !important;
  padding: 1rem;
  font-size: 13px;
  line-height: 1.6;
  font-family: 'Fira Code', 'Consolas', 'Monaco', monospace;
}

:deep(.shiki code) {
  display: block;
  counter-reset: line;
}

:deep(.shiki .line) {
  display: block;
  padding: 0 0.5rem;
  border-left: 2px solid transparent;
}

:deep(.shiki .line::before) {
  counter-increment: line;
  content: counter(line);
  display: inline-block;
  width: 2rem;
  margin-right: 1rem;
  text-align: right;
  color: #4b5563;
  user-select: none;
}

:deep(.shiki .highlighted-line) {
  background: rgba(0, 212, 255, 0.15);
  border-left-color: #00d4ff;
}

:deep(.shiki .diff-line) {
  background: rgba(245, 158, 11, 0.2);
  border-left-color: #f59e0b;
}

.simple-code {
  padding: 1rem;
  font-family: 'Fira Code', monospace;
  font-size: 13px;
  white-space: pre;
  color: #e2e8f0;
}
</style>
