import type { GadgetChain } from './types'

// JavassistWeld1
export const javassistWeld1: GadgetChain = {
  metadata: {
    chainId: 'javassist-weld1',
    name: 'JavassistWeld1',
    targetDependency: 'org.javassist:javassist:3.18.1-GA, org.jboss.weld:weld-core:1.1.33.Final',
    description: '利用 Javassist 字节码操作库和 Weld CDI 框架。通过反序列化触发类加载和字节码转换。',
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
      className: 'org.jboss.weld.interceptor.util.proxy.TargetInstanceBeanProvider',
      methodName: 'getBeanInstance',
      label: 'TargetInstanceBeanProvider.getBeanInstance()',
      description: 'Weld拦截器获取目标bean实例。',
      codeSnippet: `public Object getBeanInstance() {
    return targetInstance;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'javassist.util.proxy.ProxyObject',
      methodName: 'setHandler',
      label: 'ProxyObject.setHandler()',
      description: '设置Javassist代理处理器。',
      codeSnippet: `public void setHandler(MethodHandler mi) {
    handler = mi;
}`,
      highlightLines: [2],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'javassist.util.proxy.ProxyObject',
      methodName: 'invoke',
      label: 'ProxyObject.invoke()',
      description: '代理方法调用。',
      codeSnippet: `public Object invoke(Object self, Method m, Method proceed, Object[] args) throws Throwable {
    return handler.invoke(self, m, proceed, args);
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
      description: '反序列化触发Weld拦截器',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '代理设置',
      description: '获取实例触发代理设置',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'proxy',
      label: '代理调用',
      description: '代理方法调用',
      animated: true,
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

// Jdk7u21
export const jdk7u21: GadgetChain = {
  metadata: {
    chainId: 'jdk7u21',
    name: 'Jdk7u21',
    targetDependency: 'JRE 1.7u21 and earlier',
    description: '利用 JRE 1.7u21 中 AnnotationInvocationHandler 和 TemplatesImpl 的漏洞。通过 LinkedHashSet 和代理触发 equalsImpl 方法。',
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
      className: 'java.util.HashSet',
      methodName: 'add',
      label: 'HashSet.add()',
      description: '添加元素时计算hashCode。',
      codeSnippet: `public boolean add(E e) {
    return map.put(e, PRESENT)==null;
}`,
      highlightLines: [2],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: '$Proxy',
      methodName: 'hashCode',
      label: 'Proxy.hashCode()',
      description: '代理对象hashCode调用AnnotationInvocationHandler。',
      codeSnippet: `public int hashCode() {
    return handler.hashCode(this);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'sun.reflect.annotation.AnnotationInvocationHandler',
      methodName: 'equalsImpl',
      label: 'AnnotationInvocationHandler.equalsImpl()',
      description: '比较注解实现时触发方法调用。',
      codeSnippet: `private Boolean equalsImpl(Object proxy, Object other) {
    // ... 比较注解成员 ...
    return ...;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getOutputProperties',
      label: 'TemplatesImpl.getOutputProperties()',
      description: '获取输出属性触发模板加载。',
      codeSnippet: `public Properties getOutputProperties() {
    return newTransformer().getOutputProperties();
}`,
      highlightLines: [2],
    },
    {
      id: 'node-7',
      type: 'sink',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'newTransformer',
      label: 'TemplatesImpl.newTransformer()',
      description: '最终触发点：加载恶意字节码。',
      codeSnippet: `public synchronized Transformer newTransformer() throws TransformerConfigurationException {
    return new TransformerImpl(getTransletInstance(), ...);
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
      description: '反序列化LinkedHashSet',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '添加元素',
      description: 'LinkedHashSet.add调用HashSet.add',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'override',
      label: 'hashCode',
      description: '计算hashCode触发代理',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'proxy',
      label: '代理处理',
      description: 'AnnotationInvocationHandler处理equals',
      animated: true,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'reflection',
      label: '反射调用',
      description: '反射调用getOutputProperties',
      animated: true,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '模板加载',
      description: '触发字节码加载',
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
    description: '利用 Jython（Python 的 Java 实现）的 PyFunction 类，通过反序列化触发 Python 代码执行。',
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
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'gadget',
      className: 'org.python.core.PyFunction',
      methodName: 'readObject',
      label: 'PyFunction.readObject()',
      description: 'Jython函数反序列化。',
      codeSnippet: `private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // ... 恢复函数状态 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.python.core.PyFunction',
      methodName: '__call__',
      label: 'PyFunction.__call__()',
      description: '调用Python函数。',
      codeSnippet: `public PyObject __call__(PyObject[] args, String[] keywords) {
    return func_code.call(this, args, keywords);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.python.core.PyCode',
      methodName: 'call',
      label: 'PyCode.call()',
      description: '执行Python字节码。',
      codeSnippet: `public PyObject call(PyFrame frame, PyObject[] args) {
    // ... 执行字节码 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-5',
      type: 'sink',
      className: 'org.python.core.__builtin__',
      methodName: 'execfile',
      label: '__builtin__.execfile()',
      description: '最终触发点：执行Python文件。',
      codeSnippet: `public static void execfile(String name) {
    // ... 执行Python脚本 ...
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
      description: '反序列化PyFunction',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '函数调用',
      description: '调用Python函数',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '字节码执行',
      description: '执行Python字节码',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '代码执行',
      description: '执行Python脚本',
      animated: true,
    },
  ],
}
