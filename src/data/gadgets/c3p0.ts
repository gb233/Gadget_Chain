import type { GadgetChain } from './types'

export const c3p0: GadgetChain = {
  metadata: {
    chainId: 'c3p0',
    name: 'C3P0',
    targetDependency: 'com.mchange:c3p0:0.9.5.2',
    description: '利用 C3P0 数据库连接池的 JNDI 引用功能。通过 ReferenceableUtils 触发 JNDI 查询，导致远程代码执行。',
    author: 'mbechler',
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
      className: 'com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase',
      methodName: 'readObject',
      label: 'PoolBackedDataSourceBase.readObject()',
      description: 'C3P0 数据源的反序列化方法，恢复连接池配置。',
      codeSnippet: `private void readObject(ObjectInputStream ois)
    throws IOException, ClassNotFoundException {
    ois.defaultReadObject();
    // ... 重新初始化连接池 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'com.mchange.v2.naming.ReferenceIndirector',
      methodName: 'getObject',
      label: 'ReferenceIndirector.getObject()',
      description: '通过 JNDI 获取对象引用。',
      codeSnippet: `public Object getObject() throws NamingException {
    Context initialContext = new InitialContext();
    return initialContext.lookup(name);
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'javax.naming.InitialContext',
      methodName: 'lookup',
      label: 'InitialContext.lookup()',
      description: 'JNDI 查找操作，可能导致远程类加载。',
      codeSnippet: `public Object lookup(String name) throws NamingException {
    return getURLOrDefaultInitCtx(name).lookup(name);
}`,
      highlightLines: [1],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'com.sun.jndi.rmi.registry.RegistryContext',
      methodName: 'lookup',
      label: 'RegistryContext.lookup()',
      description: 'RMI 注册表查找，返回远程对象引用。',
      codeSnippet: `public Object lookup(Name name) throws NamingException {
    // ... 查找远程对象 ...
    return lookup(name.get(0));
}`,
      highlightLines: [2],
    },
    {
      id: 'node-6',
      type: 'sink',
      className: 'javax.naming.spi.NamingManager',
      methodName: 'getObjectInstance',
      label: 'NamingManager.getObjectInstance()',
      description: '最终触发点：通过 JNDI 引用加载远程类，执行恶意代码。',
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
      description: 'ObjectInputStream 反序列化 PoolBackedDataSourceBase',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '获取连接',
      description: '数据源尝试获取数据库连接，触发 JNDI 查询',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: 'JNDI 查找',
      description: 'ReferenceIndirector 调用 JNDI lookup',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: 'RMI 解析',
      description: 'InitialContext 解析 RMI 注册表地址',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'reflection',
      label: '远程加载',
      description: 'RMI 返回的引用触发远程类加载',
      animated: true,
    },
  ],
}
