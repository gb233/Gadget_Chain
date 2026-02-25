import type { GadgetChain } from './types'

export const vaadin1: GadgetChain = {
  metadata: {
    chainId: 'vaadin1',
    name: 'Vaadin1',
    targetDependency: 'com.vaadin:vaadin-server:7.7.14',
    description: '利用 Vaadin Web 框架的 ServerRpcManager，通过反序列化触发 RPC 方法调用，利用事件监听器触发任意代码执行。',
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
      type: 'gadget',
      className: 'java.util.HashMap',
      methodName: 'readObject',
      label: 'HashMap.readObject()',
      description: 'HashMap反序列化时重建映射关系。',
      codeSnippet: `private void readObject(ObjectInputStream s) throws IOException, ClassNotFoundException {
    // ... 重建HashMap ...
    for (int i = 0; i < mappings; i++) {
        K key = (K) s.readObject();
        V value = (V) s.readObject();
        putVal(hash(key), key, value, false, false);
    }
}`,
      highlightLines: [5, 6, 7],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'com.vaadin.event.ListenerMethod',
      methodName: 'readObject',
      label: 'ListenerMethod.readObject()',
      description: 'Vaadin监听器方法反序列化，包含要调用的目标方法信息。',
      codeSnippet: `private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // 恢复监听器方法
}`,
      highlightLines: [1],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'java.lang.reflect.Method',
      methodName: 'invoke',
      label: 'Method.invoke()',
      description: '反射调用目标方法。',
      codeSnippet: `public Object invoke(Object obj, Object... args) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
    return ma.invoke(obj, args);
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
      description: 'ObjectInputStream反序列化HashMap',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '监听器恢复',
      description: 'HashMap中的ListenerMethod被反序列化',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'reflection',
      label: '反射调用',
      description: 'ListenerMethod通过反射调用目标方法',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '命令执行',
      description: '调用Runtime.exec执行命令',
      animated: true,
    },
  ],
}
