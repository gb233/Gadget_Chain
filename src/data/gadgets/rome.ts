import type { GadgetChain } from './types'

export const rome: GadgetChain = {
  metadata: {
    chainId: 'rome',
    name: 'ROME',
    targetDependency: 'rome:rome:1.0',
    description: '利用 ROME RSS/Atom 库，通过 HashMap 触发 toString()，进而触发 ObjectBean/EqualsBean 链。不需要 Commons Collections。使用嵌套 ObjectBean 结构。',
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
    // ... 反序列化流程 ...
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
    // ... 读取元素 ...
    for (int i = 0; i < mappings; i++) {
        K key = (K) s.readObject();
        V value = (V) s.readObject();
        putVal(hash(key), key, value, false, false);
    }
}`,
      highlightLines: [5],
    },
    {
      id: 'node-3',
      type: 'source',
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
      id: 'node-4',
      type: 'gadget',
      className: 'com.sun.syndication.feed.impl.ObjectBean',
      methodName: 'hashCode',
      label: 'ObjectBean.hashCode()',
      description: '外部ObjectBean的hashCode，调用内部的EqualsBean.beanHashCode()。',
      codeSnippet: `public int hashCode() {
    return _equalsBean.beanHashCode();
}`,
      highlightLines: [2],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'com.sun.syndication.feed.impl.EqualsBean',
      methodName: 'beanHashCode',
      label: 'EqualsBean.beanHashCode()',
      description: '调用内部ObjectBean的toString()方法。',
      codeSnippet: `public int beanHashCode() {
    return _obj.toString().hashCode();
}`,
      highlightLines: [2],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'com.sun.syndication.feed.impl.ObjectBean',
      methodName: 'toString',
      label: 'ObjectBean.toString()',
      description: '内部ObjectBean的toString，调用ToStringBean.toString()。',
      codeSnippet: `public String toString() {
    return _toStringBean.toString();
}`,
      highlightLines: [2],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'com.sun.syndication.feed.impl.ToStringBean',
      methodName: 'toString',
      label: 'ToStringBean.toString()',
      description: '通过反射获取所有getter方法并调用。',
      codeSnippet: `public String toString() {
    return toString(_obj.getClass(), _obj);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: 'com.sun.syndication.feed.impl.ToStringBean',
      methodName: 'toString',
      label: 'ToStringBean.toString(String)',
      description: '反射调用TemplatesImpl的getOutputProperties()方法。',
      codeSnippet: `private String toString(Class clazz, Object obj) {
    // ... 反射获取所有属性 ...
    Method[] methods = clazz.getDeclaredMethods();
    for (Method method : methods) {
        if (isGetter(method)) {
            Object value = method.invoke(obj, NO_PARAMS);
            // ...
        }
    }
}`,
      highlightLines: [6],
    },
    {
      id: 'node-9',
      type: 'gadget',
      className: 'java.lang.reflect.Method',
      methodName: 'invoke',
      label: 'Method.invoke()',
      description: '反射调用 TemplatesImpl.getOutputProperties()。',
      codeSnippet: `public Object invoke(Object obj, Object... args)
    throws IllegalAccessException, InvocationTargetException {
    return methodAccessor.invoke(obj, args);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-10',
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
      description: 'ObjectInputStream反序列化HashMap',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '计算hash',
      description: 'HashMap.readObject调用hash()',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'override',
      label: 'hashCode',
      description: '调用外部ObjectBean.hashCode()',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: 'beanHashCode',
      description: '外部ObjectBean调用EqualsBean.beanHashCode()',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: 'toString',
      description: 'EqualsBean.beanHashCode调用内部ObjectBean.toString()',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: 'toString',
      description: '内部ObjectBean调用ToStringBean.toString()',
      animated: false,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: 'toString(String)',
      description: 'ToStringBean调用重载的toString方法',
      animated: false,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'reflection',
      label: '反射调用',
      description: 'ToStringBean反射调用getter方法',
      animated: true,
    },
    {
      id: 'edge-9',
      source: 'node-9',
      target: 'node-10',
      invocationType: 'reflection',
      label: '获取属性',
      description: '反射调用getOutputProperties',
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
