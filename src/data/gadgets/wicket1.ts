import type { GadgetChain } from './types'

export const wicket1: GadgetChain = {
  metadata: {
    chainId: 'wicket1',
    name: 'Wicket1',
    targetDependency: 'org.apache.wicket:wicket-core:6.23.0',
    description: '利用 Apache Wicket Web 框架的 ListView 和 Component，通过反序列化触发任意方法调用。',
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
      className: 'java.util.ArrayList',
      methodName: 'readObject',
      label: 'ArrayList.readObject()',
      description: 'ArrayList反序列化时恢复元素。',
      codeSnippet: `private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    // ... 读取元素 ...
    for (int i = 0; i < size; i++) {
        elementData[i] = in.readObject();
    }
}`,
      highlightLines: [4],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.apache.wicket.markup.html.list.ListView',
      methodName: 'onPopulate',
      label: 'ListView.onPopulate()',
      description: 'Wicket列表视图填充时触发。',
      codeSnippet: `protected void onPopulate() {
    // 填充列表项
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
      description: 'ObjectInputStream反序列化ArrayList',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '列表填充',
      description: 'ArrayList中的ListView组件被处理',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'reflection',
      label: '反射调用',
      description: 'ListView通过反射调用方法',
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
