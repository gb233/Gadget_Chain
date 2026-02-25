import type { GadgetChain } from './types'

// MozillaRhino1
export const mozillaRhino1: GadgetChain = {
  metadata: {
    chainId: 'mozilla-rhino1',
    name: 'MozillaRhino1',
    targetDependency: 'rhino:js:1.7R2',
    description: '利用 Mozilla Rhino JavaScript 引擎的 NativeJavaObject 和 JavaAdapter，通过反序列化触发 JavaScript 代码执行。',
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
    // ... 反序列化流程 ...
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'source',
      className: 'org.mozilla.javascript.NativeJavaObject',
      methodName: 'readObject',
      label: 'NativeJavaObject.readObject()',
      description: 'Rhino NativeJavaObject反序列化，触发JavaAdapter处理。',
      codeSnippet: `private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    if (isAdapter) {
        // ... 触发JavaAdapter处理 ...
    }
}`,
      highlightLines: [4],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.mozilla.javascript.JavaAdapter',
      methodName: 'readAdapterObject',
      label: 'JavaAdapter.readAdapterObject()',
      description: '读取适配器对象，触发类加载和方法调用。',
      codeSnippet: `static Object readAdapterObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    // ... 读取适配器信息 ...
    return getAdapterClass(...).newInstance();
}`,
      highlightLines: [3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.mozilla.javascript.JavaAdapter',
      methodName: 'getAdapterClass',
      label: 'JavaAdapter.getAdapterClass()',
      description: '获取适配器类，触发方法名收集。',
      codeSnippet: `static Class getAdapterClass(Scriptable scope, Class[] interfaces) {
    // ... 获取对象函数名 ...
    String[] functionNames = getObjectFunctionNames(scope);
    // ...
}`,
      highlightLines: [3],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.mozilla.javascript.ScriptableObject',
      methodName: 'getPropertyIds',
      label: 'ScriptableObject.getPropertyIds()',
      description: '获取属性ID列表。',
      codeSnippet: `public Object[] getPropertyIds() {
    // ... 获取所有属性ID ...
    return ids;
}`,
      highlightLines: [2],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.mozilla.javascript.MemberBox',
      methodName: 'invoke',
      label: 'MemberBox.invoke()',
      description: '反射调用Java方法。',
      codeSnippet: `public Object invoke(Object target, Object[] args) throws Exception {
    return method.invoke(target, args);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-7',
      type: 'sink',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getOutputProperties',
      label: 'TemplatesImpl.getOutputProperties()',
      description: '最终触发点：加载恶意字节码执行任意代码。',
      codeSnippet: `public Properties getOutputProperties() {
    try {
        return newTransformer().getOutputProperties();
    } catch (TransformerConfigurationException e) {
        return null;
    }
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
      description: 'ObjectInputStream反序列化NativeJavaObject',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '适配器处理',
      description: 'NativeJavaObject触发JavaAdapter.readAdapterObject()',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '获取适配器类',
      description: 'JavaAdapter.readAdapterObject调用getAdapterClass()',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '收集函数名',
      description: 'getAdapterClass触发getPropertyIds()',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '方法调用',
      description: '属性访问触发MemberBox.invoke()',
      animated: true,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'reflection',
      label: '字节码加载',
      description: '反射调用TemplatesImpl.getOutputProperties()',
      animated: true,
    },
  ],
}

// MozillaRhino2
export const mozillaRhino2: GadgetChain = {
  metadata: {
    chainId: 'mozilla-rhino2',
    name: 'MozillaRhino2',
    targetDependency: 'rhino:js:1.7R2 (or 1.6R6+)',
    description: '利用 Rhino 的 NativeJavaObject 和 JavaAdapter，通过反序列化触发任意 Java 方法调用。适用于更广泛的 Rhino 版本。',
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
      className: 'org.mozilla.javascript.NativeJavaObject',
      methodName: 'readObject',
      label: 'NativeJavaObject.readObject()',
      description: 'Rhino NativeJavaObject反序列化，触发JavaAdapter处理。',
      codeSnippet: `private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    if (isAdapter) {
        // ... 触发JavaAdapter处理 ...
    }
}`,
      highlightLines: [4],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.mozilla.javascript.tools.shell.Environment',
      methodName: 'getIds',
      label: 'Environment.getIds()',
      description: 'Rhino shell环境的getIds方法，触发原型链遍历。',
      codeSnippet: `public Object[] getIds() {
    // ... 返回属性ID列表 ...
    return super.getIds();
}`,
      highlightLines: [3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.mozilla.javascript.ScriptableObject',
      methodName: 'getProperty',
      label: 'ScriptableObject.getProperty()',
      description: '获取Scriptable对象的属性。',
      codeSnippet: `public static Object getProperty(Scriptable obj, String name) {
    // ... 获取属性值 ...
    return slot.getValue(obj);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.mozilla.javascript.NativeJavaArray',
      methodName: 'get',
      label: 'NativeJavaArray.get()',
      description: '获取Java数组元素。',
      codeSnippet: `public Object get(int index, Scriptable start) {
    // ... 返回数组元素 ...
    return javaMembers.get(this, name);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.mozilla.javascript.JavaMembers',
      methodName: 'get',
      label: 'JavaMembers.get()',
      description: '获取Java成员。',
      codeSnippet: `Object get(Object javaObject, String name) {
    // ... 查找并调用成员 ...
    return member.invoke(javaObject, args);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'org.mozilla.javascript.MemberBox',
      methodName: 'invoke',
      label: 'MemberBox.invoke()',
      description: '反射调用Java方法，触发TemplatesImpl.getOutputProperties()。',
      codeSnippet: `public Object invoke(Object target, Object[] args) throws Exception {
    return method.invoke(target, args);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-8',
      type: 'sink',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getOutputProperties',
      label: 'TemplatesImpl.getOutputProperties()',
      description: '最终触发点：加载恶意字节码执行任意代码。',
      codeSnippet: `public Properties getOutputProperties() {
    try {
        return newTransformer().getOutputProperties();
    } catch (TransformerConfigurationException e) {
        return null;
    }
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
      description: 'ObjectInputStream反序列化NativeJavaObject',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '原型链遍历',
      description: 'JavaAdapter处理触发Environment.getIds()',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '属性获取',
      description: 'getIds触发ScriptableObject.getProperty()',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '数组访问',
      description: 'getProperty触发NativeJavaArray.get()',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '成员查找',
      description: 'NativeJavaArray.get调用JavaMembers.get()',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '方法调用',
      description: 'JavaMembers.get调用MemberBox.invoke()',
      animated: true,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'reflection',
      label: '字节码加载',
      description: '反射调用TemplatesImpl.getOutputProperties()',
      animated: true,
    },
  ],
}
