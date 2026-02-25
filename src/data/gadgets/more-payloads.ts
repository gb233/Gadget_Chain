import type { GadgetChain } from './types'

// JavassistWeld1
export const javassistWeld1: GadgetChain = {
  metadata: {
    chainId: 'javassist-weld1',
    name: 'JavassistWeld1',
    targetDependency: 'org.javassist:javassist:3.12.1.GA, org.jboss.weld:weld-core:1.1.33.Final',
    description: '利用 Javassist 字节码操作库和 Weld CDI 框架。通过 PriorityQueue 触发代理比较器，进而触发 Javassist 代理的方法调用。',
    author: 'matthias_kaiser',
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
      description: 'PriorityQueue反序列化时重建堆结构，触发比较器。',
      codeSnippet: `private void readObject(ObjectInputStream s) throws IOException, ClassNotFoundException {
    // ... 读取元素 ...
    heapify();
}`,
      highlightLines: [3],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'java.util.PriorityQueue',
      methodName: 'heapify',
      label: 'PriorityQueue.heapify()',
      description: '重建堆时触发比较器比较元素。',
      codeSnippet: `private void heapify() {
    for (int i = (size >>> 1) - 1; i >= 0; i--)
        siftDown(i, (E) queue[i]);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'java.util.PriorityQueue',
      methodName: 'siftDownUsingComparator',
      label: 'PriorityQueue.siftDownUsingComparator()',
      description: '使用比较器下沉元素。',
      codeSnippet: `private void siftDownUsingComparator(int k, E x) {
    while (k < half) {
        int child = (k << 1) + 1;
        // ... 使用比较器比较 ...
        if (comparator.compare(x, (E) c) <= 0)
            break;
    }
}`,
      highlightLines: [6],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'javassist.util.proxy.ProxyObject',
      methodName: 'invoke',
      label: 'ProxyObject.invoke()',
      description: 'Javassist代理对象的方法调用，触发MethodHandler。',
      codeSnippet: `public Object invoke(Object self, Method thisMethod, Method proceed,
                       Object[] args) throws Throwable {
    return handler.invoke(self, thisMethod, proceed, args);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'javassist.util.proxy.MethodHandler',
      methodName: 'invoke',
      label: 'MethodHandler.invoke()',
      description: 'Javassist方法处理器，执行任意代码。',
      codeSnippet: `public Object invoke(Object self, Method m, Method proceed, Object[] args)
    throws Throwable {
    // ... 执行恶意代码 ...
    return Runtime.getRuntime().exec(command);
}`,
      highlightLines: [4],
    },
    {
      id: 'node-7',
      type: 'sink',
      className: 'java.lang.Runtime',
      methodName: 'exec',
      label: 'Runtime.exec()',
      description: '最终触发点：执行任意系统命令。',
      codeSnippet: `public Process exec(String command) throws IOException {
    return exec(command, null, null);
}`,
      highlightLines: [2],
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
      description: 'PriorityQueue.readObject调用heapify()',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '比较器触发',
      description: 'heapify调用siftDownUsingComparator()',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'proxy',
      label: '代理调用',
      description: '比较器比较触发ProxyObject.invoke()',
      animated: true,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'proxy',
      label: '方法处理',
      description: 'ProxyObject调用MethodHandler.invoke()',
      animated: true,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'reflection',
      label: '命令执行',
      description: 'MethodHandler反射调用Runtime.exec()',
      animated: true,
    },
  ],
}

// Jdk7u21
export const jdk7u21: GadgetChain = {
  metadata: {
    chainId: 'jdk7u21',
    name: 'Jdk7u21',
    targetDependency: 'JRE 1.7u21 and earlier',
    description: '利用 JRE 1.7u21 中 AnnotationInvocationHandler 和 TemplatesImpl 的漏洞。通过 LinkedHashSet 的 hashCode 碰撞和动态代理触发 equalsImpl 方法调用。',
    author: 'matthias_kaiser',
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
    // ... 反序列化流程 ...
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'source',
      className: 'java.util.LinkedHashSet',
      methodName: 'readObject',
      label: 'LinkedHashSet.readObject()',
      description: 'LinkedHashSet反序列化时添加元素。',
      codeSnippet: `private void readObject(ObjectInputStream s) throws IOException, ClassNotFoundException {
    s.defaultReadObject();
    int size = s.readInt();
    for (int i=0; i<size; i++) {
        add(s.readObject());
    }
}`,
      highlightLines: [6],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'java.util.HashMap',
      methodName: 'put',
      label: 'HashMap.put()',
      description: '添加元素时计算hashCode并检查是否已存在。',
      codeSnippet: `public V put(K key, V value) {
    return putVal(hash(key), key, value, false, true);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'java.util.HashMap',
      methodName: 'hash',
      label: 'HashMap.hash()',
      description: '计算key的hashCode。',
      codeSnippet: `static final int hash(Object key) {
    int h;
    return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: '$Proxy0',
      methodName: 'hashCode',
      label: 'Proxy.hashCode()',
      description: '代理对象hashCode调用AnnotationInvocationHandler。',
      codeSnippet: `public int hashCode() {
    return handler.hashCode(this);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'sun.reflect.annotation.AnnotationInvocationHandler',
      methodName: 'invoke',
      label: 'AnnotationInvocationHandler.invoke()',
      description: '动态代理的调用处理器，分发hashCode和equals方法。',
      codeSnippet: `public Object invoke(Object proxy, Method method, Object[] args) {
    String member = method.getName();
    if (member.equals("hashCode"))
        return hashCodeImpl();
    else if (member.equals("equals"))
        return equalsImpl(proxy, args[0]);
    // ...
}`,
      highlightLines: [4, 6],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'java.util.HashMap',
      methodName: 'putVal',
      label: 'HashMap.putVal()',
      description: 'hashCode碰撞时调用equals比较。',
      codeSnippet: `final V putVal(int hash, K key, V value, boolean onlyIfAbsent, boolean evict) {
    // ...
    if (p.hash == hash && ((k = p.key) == key || (key != null && key.equals(k))))
        // ...
    // ...
}`,
      highlightLines: [3],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: '$Proxy0',
      methodName: 'equals',
      label: 'Proxy.equals()',
      description: '代理对象equals调用AnnotationInvocationHandler。',
      codeSnippet: `public boolean equals(Object obj) {
    return handler.equals(this, obj);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-9',
      type: 'gadget',
      className: 'sun.reflect.annotation.AnnotationInvocationHandler',
      methodName: 'equalsImpl',
      label: 'AnnotationInvocationHandler.equalsImpl()',
      description: '比较注解实现时反射调用目标对象的所有方法。',
      codeSnippet: `private Boolean equalsImpl(Object proxy, Object other) {
    // ...
    for (Method memberMethod : getMemberMethods()) {
        // ...
        Object ourValue = memberMethod.invoke(proxy, new Object[0]);
        // ...
    }
}`,
      highlightLines: [4],
    },
    {
      id: 'node-10',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getOutputProperties',
      label: 'TemplatesImpl.getOutputProperties()',
      description: '获取输出属性触发模板加载。',
      codeSnippet: `public Properties getOutputProperties() {
    try {
        return newTransformer().getOutputProperties();
    } catch (TransformerConfigurationException e) {
        return null;
    }
}`,
      highlightLines: [3],
    },
    {
      id: 'node-11',
      type: 'sink',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'newTransformer',
      label: 'TemplatesImpl.newTransformer()',
      description: '最终触发点：加载恶意字节码执行任意代码。',
      codeSnippet: `public synchronized Transformer newTransformer()
        throws TransformerConfigurationException {
    return new TransformerImpl(getTransletInstance(), ...);
}`,
      highlightLines: [3],
    },
  ],
  edges: [
    {
      id: 'edge-1',
      source: 'node-1',
      target: 'node-2',
      invocationType: 'direct',
      label: '反序列化触发',
      description: 'ObjectInputStream反序列化LinkedHashSet',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '添加元素',
      description: 'LinkedHashSet.add调用HashMap.put',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '计算hash',
      description: 'HashMap.put调用hash()',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'override',
      label: 'hashCode',
      description: '调用代理对象的hashCode()',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'proxy',
      label: '代理分发',
      description: 'Proxy.hashCode调用AnnotationInvocationHandler.invoke()',
      animated: true,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: 'hashCode返回',
      description: 'hashCodeImpl返回，继续putVal执行',
      animated: false,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: 'equals比较',
      description: 'hashCode碰撞触发equals比较',
      animated: false,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'proxy',
      label: 'equals处理',
      description: 'Proxy.equals调用AnnotationInvocationHandler.equalsImpl()',
      animated: true,
    },
    {
      id: 'edge-9',
      source: 'node-9',
      target: 'node-10',
      invocationType: 'reflection',
      label: '反射调用',
      description: 'equalsImpl反射调用getOutputProperties',
      animated: true,
    },
    {
      id: 'edge-10',
      source: 'node-10',
      target: 'node-11',
      invocationType: 'direct',
      label: '模板加载',
      description: 'getOutputProperties调用newTransformer',
      animated: true,
    },
  ],
}

// Jython1
export const jython1: GadgetChain = {
  metadata: {
    chainId: 'jython1',
    name: 'Jython1',
    targetDependency: 'org.python:jython-standalone:2.5.2',
    description: '利用 Jython（Python 的 Java 实现）的 PyFunction 类，通过反序列化触发 Python 代码执行。利用 PyFunction 的 func_globals 和 func_code 执行任意 Python 代码。',
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
      codeSnippet: `public final Object readObject() throws IOException, ClassNotFoundException {
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
      description: 'PriorityQueue反序列化时重建堆结构，触发比较器。',
      codeSnippet: `private void readObject(ObjectInputStream s) throws IOException, ClassNotFoundException {
    // ... 读取元素 ...
    heapify();
}`,
      highlightLines: [3],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'java.util.PriorityQueue',
      methodName: 'heapify',
      label: 'PriorityQueue.heapify()',
      description: '重建堆时触发比较器比较元素。',
      codeSnippet: `private void heapify() {
    for (int i = (size >>> 1) - 1; i >= 0; i--)
        siftDown(i, (E) queue[i]);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'java.util.PriorityQueue',
      methodName: 'siftDown',
      label: 'PriorityQueue.siftDown()',
      description: '下沉操作触发比较器。',
      codeSnippet: `private void siftDown(int k, E x) {
    if (comparator != null)
        siftDownUsingComparator(k, x);
    // ...
}`,
      highlightLines: [3],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.python.core.PyFunction',
      methodName: '__call__',
      label: 'PyFunction.__call__()',
      description: '调用Python函数，触发函数代码执行。',
      codeSnippet: `public PyObject __call__(PyObject[] args, String[] keywords) {
    return func_code.call(this, func_globals, args, keywords, func_defaults);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.python.core.PyTableCode',
      methodName: 'call',
      label: 'PyTableCode.call()',
      description: '执行Python字节码。',
      codeSnippet: `public PyObject call(PyFrame frame, PyObject[] args) {
    // ... 创建执行帧 ...
    return interpret(frame);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'org.python.core.Py',
      methodName: 'runCode',
      label: 'Py.runCode()',
      description: '运行Python代码块。',
      codeSnippet: `public static PyObject runCode(PyCode code, PyObject locals, PyObject globals) {
    // ... 执行Python代码 ...
    return result;
}`,
      highlightLines: [2],
    },
    {
      id: 'node-8',
      type: 'sink',
      className: 'org.python.core.PySystemState',
      methodName: 'exec',
      label: 'PySystemState.exec() / exec()',
      description: '最终触发点：执行Python代码实现任意命令执行。',
      codeSnippet: `public static PyObject exec(PyObject code, PyObject globals, PyObject locals) {
    // ... 执行Python代码 ...
    return result;
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
      description: 'PriorityQueue.readObject调用heapify()',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '下沉操作',
      description: 'heapify调用siftDown()',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '函数调用',
      description: '比较器比较触发PyFunction.__call__()',
      animated: true,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '字节码执行',
      description: 'PyFunction调用PyTableCode.call()',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '代码运行',
      description: 'PyTableCode调用Py.runCode()',
      animated: false,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '命令执行',
      description: '执行Python代码实现RCE',
      animated: true,
    },
  ],
}
