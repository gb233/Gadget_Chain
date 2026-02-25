import type { GadgetChain } from './types'

export const beanShell1: GadgetChain = {
  metadata: {
    chainId: 'beanshell1',
    name: 'BeanShell1',
    targetDependency: 'org.beanshell:bsh:2.0b5',
    description: '利用 BeanShell 解释器的 XThis 类，通过动态代理触发代码执行。PriorityQueue 触发 Comparator 比较，进而调用 BeanShell 脚本方法。',
    author: 'frohoff',
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
      codeSnippet: `public final Object readObject()
    throws IOException, ClassNotFoundException {
    // ... 反序列化流程 ...
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'source',
      className: 'java.util.PriorityQueue',
      methodName: 'readObject',
      label: 'PriorityQueue.readObject()',
      description: 'PriorityQueue反序列化时会重建堆结构，需要对元素进行比较排序。',
      codeSnippet: `private void readObject(ObjectInputStream s)
    throws IOException, ClassNotFoundException {
    // ... 读取元素 ...
    heapify();
}`,
      highlightLines: [4],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'java.util.PriorityQueue',
      methodName: 'heapify',
      label: 'PriorityQueue.heapify()',
      description: '重建堆结构时会调用siftDown，进而使用比较器比较元素。',
      codeSnippet: `private void heapify() {
    for (int i = (size >>> 1) - 1; i >= 0; i--)
        siftDown(i, (E) queue[i]);
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'java.util.PriorityQueue',
      methodName: 'siftDownUsingComparator',
      label: 'PriorityQueue.siftDownUsingComparator()',
      description: '使用自定义比较器进行元素比较。',
      codeSnippet: `private void siftDownUsingComparator(int k, E x) {
    int half = size >>> 1;
    while (k < half) {
        int child = (k << 1) + 1;
        Object c = queue[child];
        if (comparator.compare(x, (E) c) <= 0)
            break;
        queue[k] = c;
        k = child;
    }
    queue[k] = x;
}`,
      highlightLines: [7],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'bsh.XThis',
      methodName: 'invoke',
      label: 'XThis.invoke()',
      description: 'BeanShell XThis 类的动态代理 invoke 方法，处理代理对象的方法调用。',
      codeSnippet: `public Object invoke(Object proxy, Method method,
    Object[] args) throws Throwable {
    // ... 处理方法调用 ...
    return invokeImpl(method, args);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'bsh.This',
      methodName: 'invokeMethod',
      label: 'This.invokeMethod()',
      description: '调用 BeanShell 脚本中定义的方法，准备执行脚本代码。',
      codeSnippet: `public Object invokeMethod(String methodName,
    Object[] args) throws EvalError {
    return invokeMethod(methodName, types, args, false);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'bsh.BshMethod',
      methodName: 'invoke',
      label: 'BshMethod.invoke()',
      description: '执行 BeanShell 方法，解析并执行脚本代码。',
      codeSnippet: `public Object invoke(Object[] args, Interpreter interpreter,
    CallStack callstack, SimpleNode callerInfo) throws EvalError {
    // ... 执行方法体 ...
    return Primitive.unwrap(ret);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: 'bsh.Interpreter',
      methodName: 'eval',
      label: 'Interpreter.eval()',
      description: '解析并执行 BeanShell 脚本代码片段。',
      codeSnippet: `public Object eval(String statements) throws EvalError {
    return eval(statements, globalNamespace);
}`,
      highlightLines: [1],
    },
    {
      id: 'node-9',
      type: 'sink',
      className: 'java.lang.Runtime',
      methodName: 'exec',
      label: 'Runtime.exec()',
      description: '最终触发点：BeanShell 脚本中调用 Runtime.getRuntime().exec() 执行任意命令。',
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
      description: 'ObjectInputStream 反序列化 PriorityQueue',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '堆重建',
      description: 'PriorityQueue 调用 heapify 重建堆结构',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '比较器调用',
      description: 'siftDown 调用 siftDownUsingComparator',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'proxy',
      label: '动态代理',
      description: '比较器调用触发 XThis.invoke()',
      animated: true,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '方法调用',
      description: 'invoke 调用 This.invokeMethod',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '脚本执行',
      description: 'invokeMethod 调用 BshMethod.invoke',
      animated: false,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '解析执行',
      description: 'BshMethod 调用 Interpreter.eval 解析脚本',
      animated: false,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'reflection',
      label: '代码执行',
      description: 'BeanShell 脚本执行 Runtime.exec()',
      animated: true,
    },
  ],
}
