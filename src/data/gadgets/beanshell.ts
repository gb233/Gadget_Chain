import type { GadgetChain } from './types'

export const beanShell1: GadgetChain = {
  metadata: {
    chainId: 'beanshell1',
    name: 'BeanShell1',
    targetDependency: 'org.beanshell:bsh:2.0b5',
    description: '利用 BeanShell 解释器的 XThis 类，通过动态代理触发代码执行。BeanShell 是一个轻量级的 Java 脚本解释器。',
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
      type: 'gadget',
      className: 'bsh.XThis',
      methodName: 'readObject',
      label: 'XThis.readObject()',
      description: 'BeanShell XThis 类的反序列化方法，恢复解释器状态。',
      codeSnippet: `private void readObject(ObjectInputStream in)
    throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    init();
}`,
      highlightLines: [4],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'bsh.XThis',
      methodName: 'invoke',
      label: 'XThis.invoke()',
      description: '动态代理的 invoke 方法，处理代理对象的方法调用。',
      codeSnippet: `public Object invoke(Object proxy, Method method,
    Object[] args) throws Throwable {
    // ... 处理方法调用 ...
    return invokeImpl(method, args);
}`,
      highlightLines: [1],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'bsh.This',
      methodName: 'invokeMethod',
      label: 'This.invokeMethod()',
      description: '调用 BeanShell 脚本中定义的方法。',
      codeSnippet: `public Object invokeMethod(String methodName,
    Object[] args) throws EvalError {
    return invokeMethod(methodName, types, args, false);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-5',
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
      id: 'node-6',
      type: 'sink',
      className: 'bsh.Interpreter',
      methodName: 'eval',
      label: 'Interpreter.eval()',
      description: '最终触发点：执行 BeanShell 脚本代码，可导致任意代码执行。',
      codeSnippet: `public Object eval(String statements) throws EvalError {
    return eval(statements, globalNamespace);
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
      description: 'ObjectInputStream 反序列化 XThis 对象',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'proxy',
      label: '动态代理',
      description: '反序列化后代理对象的方法调用触发 invoke',
      animated: true,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '方法调用',
      description: 'invoke 调用 This.invokeMethod',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '脚本执行',
      description: 'invokeMethod 调用 BshMethod.invoke',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'reflection',
      label: '代码执行',
      description: 'BshMethod 调用 Interpreter.eval 执行脚本',
      animated: true,
    },
  ],
}
