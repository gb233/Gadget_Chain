import type { GadgetChain } from './types'

export const groovy1: GadgetChain = {
  metadata: {
    chainId: 'groovy1',
    name: 'Groovy1',
    targetDependency: 'org.codehaus.groovy:groovy:2.3.9',
    description: '利用 Groovy 语言的 MethodClosure 类，通过反序列化触发任意方法调用。Groovy 是 JVM 上的动态语言。',
    author: 'frohoff',
    complexity: 'Low',
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
      codeSnippet: `public final Object readObject()
    throws IOException, ClassNotFoundException {
    // ... 反序列化流程 ...
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'gadget',
      className: 'org.codehaus.groovy.runtime.MethodClosure',
      methodName: 'readObject',
      label: 'MethodClosure',
      description: 'Groovy MethodClosure 包装了对象和方法引用，可被序列化。',
      codeSnippet: `public class MethodClosure extends Closure {
    private String method;

    public MethodClosure(Object owner, String method) {
        super(owner);
        this.method = method;
    }
}`,
      highlightLines: [5, 6],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.codehaus.groovy.runtime.MethodClosure',
      methodName: 'call',
      label: 'MethodClosure.call()',
      description: '调用包装的方法。',
      codeSnippet: `public Object call(Object[] args) {
    return InvokerHelper.invokeMethod(getOwner(), method, args);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-4',
      type: 'sink',
      className: 'java.lang.ProcessBuilder',
      methodName: 'start',
      label: 'ProcessBuilder.start()',
      description: '最终触发点：启动新进程执行任意命令。',
      codeSnippet: `public Process start() throws IOException {
    // ... 启动进程 ...
    return new ProcessImpl(...);
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
      description: 'ObjectInputStream反序列化MethodClosure',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '方法调用',
      description: '调用MethodClosure包装的exec方法',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'reflection',
      label: '命令执行',
      description: '调用ProcessBuilder.start执行命令',
      animated: true,
    },
  ],
}
