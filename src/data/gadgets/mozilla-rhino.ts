import type { GadgetChain } from './types'

// MozillaRhino1
export const mozillaRhino1: GadgetChain = {
  metadata: {
    chainId: 'mozilla-rhino1',
    name: 'MozillaRhino1',
    targetDependency: 'rhino:js:1.7R2',
    description: '利用 Mozilla Rhino JavaScript 引擎的 NativeError 类，通过反序列化触发 JavaScript 代码执行。',
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
      codeSnippet: `public final Object readObject() throws IOException, ClassNotFoundException {
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'gadget',
      className: 'org.mozilla.javascript.NativeError',
      methodName: 'readObject',
      label: 'NativeError.readObject()',
      description: 'Rhino NativeError反序列化。',
      codeSnippet: `private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // ... 恢复错误对象 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.mozilla.javascript.Context',
      methodName: 'enter',
      label: 'Context.enter()',
      description: '进入JavaScript执行上下文。',
      codeSnippet: `public static Context enter() {
    return enter(ContextFactory.getGlobal());
}`,
      highlightLines: [2],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.mozilla.javascript.ScriptRuntime',
      methodName: 'eval',
      label: 'ScriptRuntime.eval()',
      description: '执行JavaScript代码。',
      codeSnippet: `public static Object eval(Context cx, Scriptable scope, String source, String sourceName) {
    // ... 解析并执行脚本 ...
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
      description: '反序列化NativeError',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '上下文进入',
      description: '进入Rhino上下文',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '脚本执行',
      description: '执行JavaScript代码',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'reflection',
      label: '命令执行',
      description: 'JS代码调用Runtime.exec',
      animated: true,
    },
  ],
}

// MozillaRhino2
export const mozillaRhino2: GadgetChain = {
  metadata: {
    chainId: 'mozilla-rhino2',
    name: 'MozillaRhino2',
    targetDependency: 'rhino:js:1.7R2',
    description: '利用 Rhino 的 NativeJavaObject 和 MemberBox，通过反序列化触发任意 Java 方法调用。',
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
      type: 'gadget',
      className: 'org.mozilla.javascript.NativeJavaObject',
      methodName: 'readObject',
      label: 'NativeJavaObject.readObject()',
      description: 'Rhino NativeJavaObject反序列化。',
      codeSnippet: `private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // ... 恢复Java对象包装 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.mozilla.javascript.MemberBox',
      methodName: 'invoke',
      label: 'MemberBox.invoke()',
      description: '调用Java成员方法。',
      codeSnippet: `public Object invoke(Object target, Object[] args) throws Exception {
    return method.invoke(target, args);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-4',
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
      description: '反序列化NativeJavaObject',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '方法调用',
      description: '调用MemberBox.invoke',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'reflection',
      label: '命令执行',
      description: '反射调用Runtime.exec',
      animated: true,
    },
  ],
}
