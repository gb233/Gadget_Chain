import type { GadgetChain } from './types'

export const clojure: GadgetChain = {
  metadata: {
    chainId: 'clojure',
    name: 'Clojure',
    targetDependency: 'org.clojure:clojure:1.8.0',
    description: '利用 Clojure 的动态特性，通过 Comparator 接口触发代码执行。Clojure 是 Lisp 方言的 JVM 语言。',
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
      description: 'Clojure 持久化树形 Map 的反序列化方法。',
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
      id: 'node-4',
      type: 'gadget',
      className: 'clojure.lang.AFn',
      methodName: 'invoke',
      label: 'AFn.invoke()',
      description: 'Clojure 函数抽象基类的调用方法。',
      codeSnippet: `public Object invoke(Object arg1) {
    return throwArity(1);
}`,
      highlightLines: [1],
    },
    {
      id: 'node-5',
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
      id: 'node-6',
      type: 'sink',
      className: 'clojure.lang.Compiler',
      methodName: 'eval',
      label: 'Compiler.eval()',
      description: '最终触发点：Clojure 编译器执行代码，可导致任意代码执行。',
      codeSnippet: `public static Object eval(Object form, boolean freshLoader) {
    // ... 编译并执行代码 ...
    return ret;
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
      label: '比较器调用',
      description: '树重建过程中使用比较器',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '函数调用',
      description: '比较器被实现为 Clojure 函数',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'reflection',
      label: 'eval 调用',
      description: 'AFn 调用 eval 函数',
      animated: true,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '代码执行',
      description: '调用 Clojure Compiler 执行代码',
      animated: true,
    },
  ],
}
