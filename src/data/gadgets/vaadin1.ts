import type { GadgetChain } from './types'

export const vaadin1: GadgetChain = {
  metadata: {
    chainId: 'vaadin1',
    name: 'Vaadin1',
    targetDependency: 'com.vaadin:vaadin-server:7.7.14',
    description: '利用 Vaadin Web 框架的 ServerRpcManager，通过反序列化触发 RPC 方法调用，利用 LazyList 触发任意方法执行。',
    author: 'mbechler',
    complexity: 'High',
    cve: null,
  },
  nodes: [
    {
      id: 'node-1',
      type: 'source',
      className: 'java.io.ObjectInputStream',
      methodName: 'readObject',
      label: 'ObjectInputStream.readObject()',
      description: 'Java反序列化标准入口。',
      codeSnippet: `public final Object readObject() throws IOException, ClassNotFoundException {
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'source',
      className: 'com.vaadin.server.communication.ServerRpcManager',
      methodName: 'readObject',
      label: 'ServerRpcManager.readObject()',
      description: 'Vaadin RPC管理器反序列化。',
      codeSnippet: `private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // ... 恢复RPC状态 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'com.vaadin.server.communication.ServerRpcManager',
      methodName: 'applyInvocation',
      label: 'ServerRpcManager.applyInvocation()',
      description: '应用RPC方法调用。',
      codeSnippet: `public void applyInvocation(ServerRpcMethodInvocation invocation) {
    // ... 执行RPC调用 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'com.vaadin.data.util.LazyList',
      methodName: 'get',
      label: 'LazyList.get()',
      description: '延迟加载列表元素。',
      codeSnippet: `public T get(int index) {
    return items.get(index);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-5',
      type: 'sink',
      className: 'java.lang.Runtime',
      methodName: 'exec',
      label: 'Runtime.exec()',
      description: '最终命令执行点。',
      codeSnippet: `public Process exec(String command) throws IOException {
    return exec(command, null, null);
}`,
      highlightLines: [1],
    },
  ],
  edges: [
    {
      id: 'edge-1',
      source: 'node-1',
      target: 'node-2',
      invocationType: 'direct',
      label: '反序列化触发',
      description: 'ObjectInputStream反序列化ServerRpcManager',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: 'RPC应用',
      description: '应用RPC调用',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '延迟加载',
      description: 'LazyList.get触发加载',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'reflection',
      label: '命令执行',
      description: '反射执行命令',
      animated: true,
    },
  ],
}
