import type { GadgetChain } from './types'

export const clojure: GadgetChain = {
  metadata: {
    chainId: 'clojure',
    name: 'Clojure',
    targetDependency: 'org.clojure:clojure:1.8.0',
    description: '利用 Clojure 的动态特性和 PersistentTreeMap。通过反序列化触发 Comparator 比较，比较器被实现为 Clojure 函数，最终导致任意代码执行。',
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
      className: 'clojure.lang.PersistentTreeMap',
      methodName: 'readObject',
      label: 'PersistentTreeMap.readObject()',
      description: 'Clojure 持久化树形 Map 的反序列化方法，恢复时会重建树结构。',
      codeSnippet: `private void readObject(ObjectInputStream s)
    throws IOException, ClassNotFoundException {
    s.defaultReadObject();
    // ... 重建树结构 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'clojure.lang.PersistentTreeMap',
      methodName: 'createTree',
      label: 'PersistentTreeMap.createTree()',
      description: '从序列化数据重建树结构，使用比较器对键进行排序。',
      codeSnippet: `private Node createTree(Object[] keyvals) {
    // ... 使用比较器对键进行比较和排序 ...
    return createTree(seq, comp);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'clojure.lang.PersistentTreeMap',
      methodName: 'compare',
      label: 'PersistentTreeMap.compare()',
      description: '树形 Map 使用比较器对键进行比较。',
      codeSnippet: `int compare(Object k1, Object k2) {
    Comparator c = comp;
    if (c != null)
        return c.compare(k1, k2);
    return ((Comparable) k1).compareTo(k2);
}`,
      highlightLines: [4],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'clojure.lang.AFn',
      methodName: 'invoke',
      label: 'AFn.invoke()',
      description: 'Clojure 函数抽象基类的调用方法，执行函数逻辑。',
      codeSnippet: `public Object invoke(Object arg1) {
    return throwArity(1);
}`,
      highlightLines: [1],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'clojure.core$comp$fn__4727',
      methodName: 'invoke',
      label: 'core$comp$fn.invoke()',
      description: 'Clojure 组合函数，将多个函数组合成管道。',
      codeSnippet: `public Object invoke(Object x) {
    // ... 组合函数调用 ...
    return f2.invoke(f1.invoke(x));
}`,
      highlightLines: [3],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'clojure.core$eval',
      methodName: 'invoke',
      label: 'core$eval.invoke()',
      description: 'Clojure eval 函数，执行代码字符串。',
      codeSnippet: `static public Object eval(Object form) {
    // ... 评估表达式 ...
    return ret;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: 'clojure.lang.Compiler',
      methodName: 'eval',
      label: 'Compiler.eval()',
      description: 'Clojure 编译器执行代码，解析并执行表达式。',
      codeSnippet: `public static Object eval(Object form, boolean freshLoader) {
    // ... 编译并执行代码 ...
    return ret;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-9',
      type: 'sink',
      className: 'java.lang.Runtime',
      methodName: 'exec',
      label: 'Runtime.exec()',
      description: '最终触发点：Clojure 代码执行 Runtime.getRuntime().exec() 执行任意命令。',
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
      description: 'ObjectInputStream 反序列化 PersistentTreeMap',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '重建树',
      description: '反序列化后重建树结构',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '比较器调用',
      description: '树重建过程中使用比较器对键进行比较',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '函数调用',
      description: '比较器被实现为 Clojure 函数，调用 AFn.invoke',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '组合函数',
      description: '调用组合函数管道',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'reflection',
      label: 'eval 调用',
      description: '组合函数调用 eval 函数',
      animated: true,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '编译执行',
      description: 'eval 调用 Compiler 编译并执行代码',
      animated: false,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'reflection',
      label: '代码执行',
      description: 'Clojure 代码执行 Runtime.exec()',
      animated: true,
    },
  ],
}
