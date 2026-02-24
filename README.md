# Gadget_Chain

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Java反序列化漏洞Gadget Chain可视化图谱工具

## 项目介绍

Gadget_Chain是一个交互式的Java反序列化漏洞Gadget Chain可视化工具，帮助安全研究人员直观理解从Source（入口）到Gadget（跳板）再到Sink（执行点）的完整调用链。

### 核心功能

- **交互式图谱展示**：使用Vue Flow实现节点拖拽、缩放、点击查看详情
- **双链对比模式**：对比两条Gadget Chain的差异，Y型布局展示共用节点和独有节点
- **代码高亮对比**：使用Shiki实现Java代码语法高亮，支持差异行高亮
- **步进播放**：自动播放展示调用链执行过程
- **MiniMap导航**：左下角缩略图快速定位

### 支持的Gadget Chain

- URLDNS
- CommonsCollections1/2/3/5/6/7
- Spring1/2
- Hibernate1/2
- 更多持续添加中...

## 技术栈

- **前端框架**: Vue 3 + TypeScript
- **构建工具**: Vite
- **图谱引擎**: Vue Flow 1.x
- **代码高亮**: Shiki
- **样式**: Tailwind CSS
- **布局**: Dagre.js

## 快速开始

### 安装依赖

```bash
npm install
```

### 开发模式

```bash
npm run dev
```

### 构建

```bash
npm run build
```

### 预览生产构建

```bash
npm run preview
```

## 使用说明

### 单链模式

1. 从顶部下拉框选择Payload
2. 点击节点查看代码详情
3. 使用步进播放器自动播放调用链

### 对比模式

1. 点击右上角"对比模式"按钮
2. 选择Chain A和Chain B
3. 查看Y型布局展示的共用节点和独有节点
4. 点击节点进行代码对比

## 项目结构

```
gadget-chain-visualizer/
├── src/
│   ├── components/        # Vue组件
│   │   ├── GadgetGraph.vue       # 图谱主组件
│   │   ├── CompareView.vue       # 对比模式组件
│   │   ├── GadgetNode.vue        # 节点组件
│   │   ├── CodePanel.vue         # 代码面板
│   │   └── PayloadSelector.vue   # Payload选择器
│   ├── data/             # Gadget数据
│   │   ├── gadgets/      # 各Chain定义
│   │   └── types.ts      # 类型定义
│   ├── App.vue           # 根组件
│   └── main.ts           # 入口
├── docs/                 # 文档
├── README.md
├── LICENSE
└── .gitignore
```

## 贡献指南

欢迎提交Issue和Pull Request！

## 许可证

[MIT License](./LICENSE)

## 致谢

本项目基于 [ysoserial](https://github.com/frohoff/ysoserial) 项目构建，感谢frohoff和所有ysoserial贡献者。

---

**注意**: 本工具仅供安全研究和教育目的使用，请勿用于非法用途。
