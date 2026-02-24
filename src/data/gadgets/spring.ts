import type { GadgetChain } from './types'

export const spring1: GadgetChain = {
  metadata: {
    chainId: 'spring1',
    name: 'Spring1',
    targetDependency: 'org.springframework:spring-core:4.1.4.RELEASE',
    description: '利用 Spring Framework 的 JtaTransactionManager 和 JNDI，通过反序列化触发 JNDI 查找加载远程类。',
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
      type: 'source',
      className: 'org.springframework.transaction.jta.JtaTransactionManager',
      methodName: 'readObject',
      label: 'JtaTransactionManager.readObject()',
      description: 'Spring JTA事务管理器反序列化。',
      codeSnippet: `private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    ois.defaultReadObject();
    // ... 恢复事务管理器状态 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.springframework.transaction.jta.JtaTransactionManager',
      methodName: 'initUserTransactionAndTransactionManager',
      label: 'JtaTransactionManager.initUserTransactionAndTransactionManager()',
      description: '初始化时查找 UserTransaction。',
      codeSnippet: `protected void initUserTransactionAndTransactionManager() throws TransactionSystemException {
    if (this.userTransactionName != null) {
        this.userTransaction = lookupUserTransaction(this.userTransactionName);
    }
}`,
      highlightLines: [3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.springframework.transaction.jta.JtaTransactionManager',
      methodName: 'lookupUserTransaction',
      label: 'JtaTransactionManager.lookupUserTransaction()',
      description: '通过 JNDI 查找 UserTransaction。',
      codeSnippet: `protected UserTransaction lookupUserTransaction(String userTransactionName) throws NamingException {
    return getJndiTemplate().lookup(userTransactionName, UserTransaction.class);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.springframework.jndi.JndiTemplate',
      methodName: 'lookup',
      label: 'JndiTemplate.lookup()',
      description: '执行 JNDI 查找操作。',
      codeSnippet: `public <T> T lookup(String name, Class<T> requiredType) throws NamingException {
    return lookup(name, requiredType, null);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-6',
      type: 'sink',
      className: 'javax.naming.InitialContext',
      methodName: 'lookup',
      label: 'InitialContext.lookup()',
      description: '最终触发点：JNDI 查找加载远程类，执行恶意代码。',
      codeSnippet: `public Object lookup(String name) throws NamingException {
    return getURLOrDefaultInitCtx(name).lookup(name);
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
      description: 'ObjectInputStream反序列化JtaTransactionManager',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '初始化',
      description: '反序列化后初始化事务管理器',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '查找',
      description: '查找UserTransaction',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: 'JNDI模板',
      description: '使用JndiTemplate执行查找',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '远程加载',
      description: 'JNDI查找触发远程类加载',
      animated: true,
    },
  ],
}

export const spring2: GadgetChain = {
  metadata: {
    chainId: 'spring2',
    name: 'Spring2',
    targetDependency: 'org.springframework:spring-core:4.1.4.RELEASE',
    description: '利用 Spring 的 AbstractBeanFactoryPointcutAdvisor 和 SerializableTypeWrapper，通过动态代理和反射触发任意方法调用。',
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
      className: 'org.springframework.beans.factory.config.AbstractBeanFactoryPointcutAdvisor',
      methodName: 'readObject',
      label: 'AbstractBeanFactoryPointcutAdvisor.readObject()',
      description: 'Spring AOP 顾问反序列化。',
      codeSnippet: `private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    ois.defaultReadObject();
    // ... 恢复AOP状态 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.springframework.core.SerializableTypeWrapper',
      methodName: 'forTypeProvider',
      label: 'SerializableTypeWrapper.forTypeProvider()',
      description: '为 TypeProvider 创建代理。',
      codeSnippet: `public static Type forTypeProvider(TypeProvider provider) {
    // ... 创建动态代理 ...
    return (Type) Proxy.newProxyInstance(...);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: '$Proxy',
      methodName: 'getType',
      label: 'Proxy.getType()',
      description: '代理对象调用 getType 触发 TypeProvider。',
      codeSnippet: `public Type getType() {
    return handler.invoke(this, GET_TYPE_METHOD, null);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.springframework.beans.factory.ObjectFactory',
      methodName: 'getObject',
      label: 'ObjectFactory.getObject()',
      description: 'Spring 工厂模式获取对象。',
      codeSnippet: `T getObject() throws BeansException;`,
      highlightLines: [1],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.springframework.beans.factory.config.AutowireUtils',
      methodName: 'invokeMethod',
      label: 'AutowireUtils.invokeMethod()',
      description: '反射调用方法。',
      codeSnippet: `public static Object invokeMethod(Method method, Object target, Object... args) {
    return method.invoke(target, args);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-7',
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
      description: 'ObjectInputStream反序列化AbstractBeanFactoryPointcutAdvisor',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '类型包装',
      description: '创建SerializableTypeWrapper代理',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'proxy',
      label: '代理调用',
      description: '代理对象调用getType',
      animated: true,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '工厂获取',
      description: '调用ObjectFactory.getObject',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'reflection',
      label: '反射调用',
      description: 'AutowireUtils反射调用方法',
      animated: true,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'reflection',
      label: '命令执行',
      description: '反射调用Runtime.exec',
      animated: true,
    },
  ],
}
