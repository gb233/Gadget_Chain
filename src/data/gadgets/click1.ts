import type { GadgetChain } from './types'

export const click1: GadgetChain = {
  metadata: {
    chainId: 'click1',
    name: 'Click1',
    targetDependency: 'org.apache.click:click-nodeps:2.3.0',
    description: '利用 Apache Click 框架的 Column 类，通过属性编辑器机制触发 JNDI 查找。Apache Click 是一个 Web 应用框架。',
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
      type: 'source',
      className: 'org.apache.click.control.Column',
      methodName: 'readObject',
      label: 'Column.readObject()',
      description: 'Apache Click Column 类的反序列化方法。',
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
    // 可能触发 JNDI 查找
}`,
      highlightLines: [3],
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
      className: 'javax.naming.InitialContext',
      methodName: 'lookup',
      label: 'InitialContext.lookup()',
      description: 'JNDI 查找操作。',
      codeSnippet: `public Object lookup(String name) throws NamingException {
    return getURLOrDefaultInitCtx(name).lookup(name);
}`,
      highlightLines: [1],
    },
    {
      id: 'node-6',
      type: 'sink',
      className: 'javax.naming.spi.NamingManager',
      methodName: 'getObjectInstance',
      label: 'NamingManager.getObjectInstance()',
      description: '最终触发点：通过 JNDI 引用加载远程类。',
      codeSnippet: `public static Object getObjectInstance(Object refInfo,
    Name name, Context nameCtx, Hashtable<?,?> environment)
    throws Exception {
    // ... 加载工厂类 ...
    return factory.getObjectInstance(refInfo, name, nameCtx, environment);
}`,
      highlightLines: [4],
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
      invocationType: 'reflection',
      label: 'JNDI 触发',
      description: '属性编辑器触发 JNDI lookup',
      animated: true,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '远程加载',
      description: 'JNDI 查找触发远程类加载',
      animated: true,
    },
  ],
}
