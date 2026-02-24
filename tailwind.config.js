/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // 暗色安全研究主题
        'cyber-dark': '#0a0a0f',
        'cyber-darker': '#050508',
        'cyber-gray': '#1a1a2e',
        'cyber-border': '#2d2d44',

        // 节点类型颜色
        'source': '#00ff88',
        'source-glow': 'rgba(0, 255, 136, 0.3)',
        'gadget': '#00d4ff',
        'gadget-glow': 'rgba(0, 212, 255, 0.3)',
        'sink': '#ff4d4d',
        'sink-glow': 'rgba(255, 77, 77, 0.4)',
        'proxy': '#a855f7',
        'proxy-glow': 'rgba(168, 85, 247, 0.3)',
      },
      fontFamily: {
        mono: ['Fira Code', 'Consolas', 'Monaco', 'monospace'],
      },
      animation: {
        'pulse-glow': 'pulseGlow 2s infinite',
        'flow': 'flow 3s linear infinite',
        'float': 'float 3s ease-in-out infinite',
      },
      keyframes: {
        pulseGlow: {
          '0%, 100%': { boxShadow: '0 0 0 0 rgba(255, 77, 77, 0.4)' },
          '50%': { boxShadow: '0 0 20px 10px rgba(255, 77, 77, 0)' },
        },
        flow: {
          '0%': { strokeDashoffset: '100' },
          '100%': { strokeDashoffset: '0' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-5px)' },
        },
      },
    },
  },
  plugins: [],
}
