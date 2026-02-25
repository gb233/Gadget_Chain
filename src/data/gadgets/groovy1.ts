import type { GadgetChain } from './types'

export const groovy1: GadgetChain = {
  metadata: {
    chainId: 'groovy1',
    name: 'Groovy1',
    targetDependency: 'org.codehaus.groovy:groovy:2.3.9',
    description: '利用 Groovy 语言的 MethodClosure 类，通过转换为 Comparator 触发任意方法调用。Groovy 是 JVM 上的动态语言。',
    author: 'frohoff',
    complexity: 'Medium',
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
      className: 'org.codehaus.groovy.runtime.ConvertedClosure',
      methodName: 'compare',
      label: 'ConvertedClosure.compare()',
      description: 'Groovy的ConvertedClosure类实现了Comparator接口，将闭包转换为比较器。',
      codeSnippet: `public int compare(Object o1, Object o2) {
    return (Integer) ((Closure) this).call(new Object[]{o1, o2});
}`,
      highlightLines: [2],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.codehaus.groovy.runtime.MethodClosure',
      methodName: 'call',
      label: 'MethodClosure.call()',
      description: 'MethodClosure包装了对象和方法引用，调用时执行指定方法。',
      codeSnippet: `public Object call(Object[] args) {
    return InvokerHelper.invokeMethod(getOwner(), method, args);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'org.codehaus.groovy.runtime.InvokerHelper',
      methodName: 'invokeMethod',
      label: 'InvokerHelper.invokeMethod()',
      description: 'Groovy的调用助手，通过反射调用指定对象的方法。',
      codeSnippet: `public static Object invokeMethod(Object object, String methodName, Object arguments) {
    // ... 方法调用逻辑 ...
    return invokePojoMethod(object, methodName, arguments);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-8',
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
      description: 'ObjectInputStream反序列化PriorityQueue',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '堆重建',
      description: 'PriorityQueue调用heapify重建堆',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '比较器调用',
      description: 'siftDown调用siftDownUsingComparator',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: 'Groovy比较',
      description: '调用ConvertedClosure.compare()',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '闭包调用',
      description: 'ConvertedClosure调用MethodClosure',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'reflection',
      label: '反射调用',
      description: 'MethodClosure通过InvokerHelper反射调用',
      animated: true,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'reflection',
      label: '命令执行',
      description: '调用ProcessBuilder.start执行命令',
      animated: true,
    },
  ],
}
