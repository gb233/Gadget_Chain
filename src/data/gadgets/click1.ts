import type { GadgetChain } from './types'

export const click1: GadgetChain = {
  metadata: {
    chainId: 'click1',
    name: 'Click1',
    targetDependency: 'org.apache.click:click-nodeps:2.3.0',
    description: '利用 Apache Click 框架的 Column 类，通过反序列化触发属性编辑器处理，进而通过 PropertyUtils 调用任意 getter 方法，最终导致 TemplatesImpl 类加载执行。',
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
      className: 'org.apache.click.control.Column',
      methodName: 'readObject',
      label: 'Column.readObject()',
      description: 'Apache Click Column 类的反序列化方法，恢复列配置。',
      codeSnippet: `private void readObject(ObjectInputStream in)
    throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // ... 初始化列属性 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.apache.click.control.Column',
      methodName: 'setDataProvider',
      label: 'Column.setDataProvider()',
      description: '设置数据提供者，触发属性编辑器处理。',
      codeSnippet: `public void setDataProvider(DataProvider provider) {
    this.dataProvider = provider;
    // 触发属性处理
}`,
      highlightLines: [1, 3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.apache.click.util.PropertyUtils',
      methodName: 'setValue',
      label: 'PropertyUtils.setValue()',
      description: '设置属性值，通过属性编辑器转换值类型。',
      codeSnippet: `public static void setValue(Object target, String property,
    Object value) {
    // ... 属性设置逻辑 ...
    propertyEditor.setValue(value);
}`,
      highlightLines: [4],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.apache.click.util.PropertyUtils',
      methodName: 'getValue',
      label: 'PropertyUtils.getValue()',
      description: '获取属性值，触发 getter 方法调用。',
      codeSnippet: `public static Object getValue(Object target, String property) {
    // ... 获取属性 ...
    return method.invoke(target, EMPTY_ARGS);
}`,
      highlightLines: [3],
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
      description: '创建 Transformer 实例，触发 getTransletInstance()。',
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
      description: '获取 Translet 实例，如果未加载则加载类。',
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
      description: 'ObjectInputStream 反序列化 Column',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '属性设置',
      description: 'Column 设置 dataProvider 属性',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '属性编辑',
      description: '调用 PropertyUtils 处理属性',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '属性获取',
      description: 'PropertyUtils 调用 getValue 获取属性',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'reflection',
      label: 'Getter 调用',
      description: '反射调用 getOutputProperties',
      animated: true,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '创建 Transformer',
      description: 'getOutputProperties 调用 newTransformer',
      animated: false,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '获取 Translet',
      description: 'newTransformer 调用 getTransletInstance',
      animated: false,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'reflection',
      label: '类加载',
      description: 'defineTransletClasses 调用 defineClass 加载恶意类',
      animated: true,
    },
  ],
}
