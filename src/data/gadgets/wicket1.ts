import type { GadgetChain } from './types'

export const wicket1: GadgetChain = {
  metadata: {
    chainId: 'wicket1',
    name: 'Wicket1',
    targetDependency: 'org.apache.wicket:wicket-core:6.23.0',
    description: '利用 Apache Wicket Web 框架的 Behavior，通过反序列化触发任意方法调用，利用行为监听器执行恶意代码。',
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
      className: 'org.apache.wicket.Component',
      methodName: 'readObject',
      label: 'Component.readObject()',
      description: 'Wicket组件反序列化。',
      codeSnippet: `private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // ... 恢复组件状态 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.apache.wicket.behavior.Behavior',
      methodName: 'onEvent',
      label: 'Behavior.onEvent()',
      description: 'Wicket行为事件处理。',
      codeSnippet: `public void onEvent(Component component, IEvent<?> event) {
    // ... 处理事件 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.apache.wicket.ajax.AjaxRequestTarget',
      methodName: 'respond',
      label: 'AjaxRequestTarget.respond()',
      description: '响应Ajax请求。',
      codeSnippet: `public void respond(IRequestCycle requestCycle) {
    // ... 响应处理 ...
}`,
      highlightLines: [1],
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
      description: 'ObjectInputStream反序列化Wicket Component',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '行为触发',
      description: '组件触发Behavior.onEvent',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '事件响应',
      description: 'Behavior响应AjaxRequest',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'reflection',
      label: '命令执行',
      description: '反射执行Runtime.exec',
      animated: true,
    },
  ],
}
