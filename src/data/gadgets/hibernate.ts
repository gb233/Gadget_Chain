import type { GadgetChain } from './types'

export const hibernate1: GadgetChain = {
  metadata: {
    chainId: 'hibernate1',
    name: 'Hibernate1',
    targetDependency: 'org.hibernate:hibernate-core:4.3.11.Final',
    description: '利用 Hibernate 的 AbstractComponentTuplizer 和 Getter/Setter 机制，通过反序列化触发任意方法调用。',
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
    // ... 反序列化流程 ...
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'gadget',
      className: 'org.hibernate.property.access.spi.Getter',
      methodName: 'get',
      label: 'Getter.get()',
      description: 'Hibernate 属性访问器，通过反射获取属性值。',
      codeSnippet: `Object get(Object owner);

// 实现中通过反射调用getter方法
public Object get(Object owner) {
    return method.invoke(owner);
}`,
      highlightLines: [5],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.hibernate.tuple.component.AbstractComponentTuplizer',
      methodName: 'getPropertyValue',
      label: 'AbstractComponentTuplizer.getPropertyValue()',
      description: '获取组件属性值时调用 Getter。',
      codeSnippet: `public Object getPropertyValue(Object component, int i)
    throws HibernateException {
    return getters[i].get(component);
}`,
      highlightLines: [3],
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
      target: 'node-3',
      invocationType: 'direct',
      label: '反序列化触发',
      description: 'Hibernate反序列化组件时触发',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-3',
      target: 'node-2',
      invocationType: 'reflection',
      label: '属性访问',
      description: 'AbstractComponentTuplizer调用Getter',
      animated: true,
    },
    {
      id: 'edge-3',
      source: 'node-2',
      target: 'node-4',
      invocationType: 'reflection',
      label: '命令执行',
      description: 'Getter反射调用exec方法',
      animated: true,
    },
  ],
}

export const hibernate2: GadgetChain = {
  metadata: {
    chainId: 'hibernate2',
    name: 'Hibernate2',
    targetDependency: 'org.hibernate:hibernate-core:4.3.11.Final',
    description: '利用 Hibernate 的 EntityManager 和 JNDI 查找。通过反序列化触发 JNDI 注入，加载远程类。',
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
    // ... 反序列化流程 ...
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'gadget',
      className: 'org.hibernate.jndi.internal.JndiServiceImpl',
      methodName: 'locate',
      label: 'JndiServiceImpl.locate()',
      description: 'Hibernate JNDI 服务定位，触发 JNDI 查找。',
      codeSnippet: `public Reference locate(String jndiName) {
    InitialContext context = new InitialContext();
    return (Reference) context.lookup(jndiName);
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-3',
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
      id: 'node-4',
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
      description: 'Hibernate反序列化触发JNDI查找',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: 'JNDI 查找',
      description: 'JndiServiceImpl调用InitialContext.lookup',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '远程加载',
      description: 'JNDI查找触发远程类加载',
      animated: true,
    },
  ],
}
