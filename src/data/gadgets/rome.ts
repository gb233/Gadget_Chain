import type { GadgetChain } from './types'

export const rome: GadgetChain = {
  metadata: {
    chainId: 'rome',
    name: 'ROME',
    targetDependency: 'com.rometools:rome:1.0',
    description: '利用 ROME RSS/Atom 库，通过 HashMap 触发 toString()，进而触发 ObjectBean/EqualsBean 链。不需要 Commons Collections。',
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
      type: 'source',
      className: 'java.util.HashMap',
      methodName: 'readObject',
      label: 'HashMap.readObject()',
      description: 'HashMap反序列化时重组Map，计算Key的hash。',
      codeSnippet: `private void readObject(ObjectInputStream s) throws IOException, ClassNotFoundException {
    for (int i = 0; i < mappings; i++) {
        K key = (K) s.readObject();
        V value = (V) s.readObject();
        putVal(hash(key), key, value, false, false);
    }
}`,
      highlightLines: [4],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'com.rometools.rome.feed.impl.ObjectBean',
      methodName: 'hashCode',
      label: 'ObjectBean.hashCode()',
      description: '调用 EqualsBean.beanHashCode()。',
      codeSnippet: `public int hashCode() {
    return EqualsBean.beanHashCode(this);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'com.rometools.rome.feed.impl.EqualsBean',
      methodName: 'beanHashCode',
      label: 'EqualsBean.beanHashCode()',
      description: '通过反射获取所有属性值计算hashCode。',
      codeSnippet: `public static int beanHashCode(Object obj) {
    return obj.toString().hashCode();
}`,
      highlightLines: [2],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'com.rometools.rome.feed.impl.ToStringBean',
      methodName: 'toString',
      label: 'ToStringBean.toString()',
      description: '通过反射获取属性值拼接字符串。',
      codeSnippet: `public String toString() {
    return toString(obj.getClass(), obj);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'java.lang.reflect.Method',
      methodName: 'invoke',
      label: 'Method.invoke()',
      description: '反射调用 getter 方法，触发 TemplatesImpl.getOutputProperties()。',
      codeSnippet: `public Object invoke(Object obj, Object... args) throws IllegalAccessException, InvocationTargetException {
    return methodAccessor.invoke(obj, args);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getOutputProperties',
      label: 'TemplatesImpl.getOutputProperties()',
      description: '触发模板类加载。',
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
      id: 'node-8',
      type: 'sink',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'newTransformer',
      label: 'TemplatesImpl.newTransformer()',
      description: '最终触发点：加载恶意字节码执行任意代码。',
      codeSnippet: `public synchronized Transformer newTransformer() throws TransformerConfigurationException {
    TransformerImpl transformer = new TransformerImpl(getTransletInstance(), ...);
    return transformer;
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
      description: 'ObjectInputStream反序列化HashMap',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'override',
      label: 'hashCode',
      description: 'HashMap计算key的hashCode',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: 'beanHashCode',
      description: 'ObjectBean调用EqualsBean.beanHashCode',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: 'toString',
      description: 'EqualsBean.beanHashCode调用toString',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'reflection',
      label: '反射调用',
      description: 'ToStringBean反射调用getter方法',
      animated: true,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'reflection',
      label: '获取属性',
      description: '反射调用getOutputProperties',
      animated: true,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '模板加载',
      description: 'getOutputProperties调用newTransformer',
      animated: true,
    },
  ],
}
