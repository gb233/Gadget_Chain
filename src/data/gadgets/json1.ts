import type { GadgetChain } from './types'

export const json1: GadgetChain = {
  metadata: {
    chainId: 'json1',
    name: 'JSON1',
    targetDependency: 'net.sf.json-lib:json-lib:2.4',
    description: '利用 json-lib 库的 JSONObject，通过反序列化触发任意 getter 方法调用，最终导致 TemplatesImpl 字节码加载执行。',
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
      codeSnippet: `public final Object readObject()
    throws IOException, ClassNotFoundException {
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'source',
      className: 'net.sf.json.JSONObject',
      methodName: 'readObject',
      label: 'JSONObject.readObject()',
      description: 'json-lib 的 JSONObject 反序列化，恢复 JSON 对象状态。',
      codeSnippet: `private void readObject(ObjectInputStream in)
    throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // ... 恢复JSON对象状态 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'net.sf.json.JSONObject',
      methodName: 'toBean',
      label: 'JSONObject.toBean()',
      description: '将 JSON 对象转换为 Java Bean，触发属性设置和 getter 调用。',
      codeSnippet: `public static Object toBean(JSONObject jsonObject, Class beanClass) {
    // ... 转换 JSON 到 Bean ...
    return toBean(jsonObject, beanClass, null);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'net.sf.json.util.PropertySetStrategy',
      methodName: 'setProperty',
      label: 'PropertySetStrategy.setProperty()',
      description: '设置 Bean 属性，触发类型转换。',
      codeSnippet: `public void setProperty(Object bean, String key, Object value) {
    // ... 设置属性 ...
    PropertyUtils.setSimpleProperty(bean, key, value);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.apache.commons.beanutils.PropertyUtils',
      methodName: 'getProperty',
      label: 'PropertyUtils.getProperty()',
      description: '获取属性值，触发 getter 方法调用。',
      codeSnippet: `public static Object getProperty(Object bean, String name)
    throws IllegalAccessException, InvocationTargetException,
           NoSuchMethodException {
    return PropertyUtilsBean.getInstance().getProperty(bean, name);
}`,
      highlightLines: [4],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getOutputProperties',
      label: 'TemplatesImpl.getOutputProperties()',
      description: '获取输出属性，触发模板类加载。',
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
      id: 'node-7',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'newTransformer',
      label: 'TemplatesImpl.newTransformer()',
      description: '创建 Transformer 实例，触发 getTransletInstance() 加载字节码。',
      codeSnippet: `public synchronized Transformer newTransformer()
    throws TransformerConfigurationException {
    TransformerImpl transformer = new TransformerImpl(
        getTransletInstance(), ...
    );
    return transformer;
}`,
      highlightLines: [3],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getTransletInstance',
      label: 'TemplatesImpl.getTransletInstance()',
      description: '获取 Translet 实例，如果未加载则调用 defineTransletClasses()。',
      codeSnippet: `private Translet getTransletInstance()
    throws TransformerConfigurationException {
    if (_name == null) return null;
    if (_class == null) defineTransletClasses();
    AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance();
    return translet;
}`,
      highlightLines: [4, 5],
    },
    {
      id: 'node-9',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'defineTransletClasses',
      label: 'TemplatesImpl.defineTransletClasses()',
      description: '从字节数组定义类，使用 TransletClassLoader 加载。',
      codeSnippet: `private void defineTransletClasses()
    throws TransformerConfigurationException {
    // ... 创建 TransletClassLoader ...
    for (int i = 0; i < classCount; i++) {
        _class[i] = loader.defineClass(_bytecodes[i]);
    }
}`,
      highlightLines: [4, 5],
    },
    {
      id: 'node-10',
      type: 'sink',
      className: 'java.lang.ClassLoader',
      methodName: 'defineClass',
      label: 'ClassLoader.defineClass()',
      description: '最终触发点：加载恶意类字节码，执行静态代码块中的任意代码。',
      codeSnippet: `protected final Class<?> defineClass(String name, byte[] b,
    int off, int len, ProtectionDomain protectionDomain)
    throws ClassFormatError {
    // ... 类加载 ...
    return defineClass1(name, b, off, len, protectionDomain, source);
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
      description: 'ObjectInputStream反序列化JSONObject',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '转换为Bean',
      description: 'JSONObject转换为Java Bean',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '属性设置',
      description: 'PropertySetStrategy处理属性设置',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '属性获取',
      description: '触发PropertyUtils.getProperty',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'reflection',
      label: 'Getter调用',
      description: '反射调用getOutputProperties',
      animated: true,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '创建Transformer',
      description: 'getOutputProperties调用newTransformer',
      animated: false,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '获取Translet',
      description: 'newTransformer调用getTransletInstance',
      animated: false,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'direct',
      label: '定义类',
      description: 'getTransletInstance调用defineTransletClasses',
      animated: false,
    },
    {
      id: 'edge-9',
      source: 'node-9',
      target: 'node-10',
      invocationType: 'reflection',
      label: '类加载',
      description: 'TransletClassLoader调用defineClass加载恶意类',
      animated: true,
    },
  ],
}
