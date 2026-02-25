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
      description: 'Spring JTA事务管理器反序列化，调用初始化方法。',
      codeSnippet: `private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    ois.defaultReadObject();
    initUserTransactionAndTransactionManager();
}`,
      highlightLines: [3],
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
    targetDependency: 'org.springframework:spring-core:4.1.4.RELEASE, org.springframework:spring-aop:4.1.4.RELEASE',
    description: '利用 Spring 的 SerializableTypeWrapper.MethodInvokeTypeProvider 和 JdkDynamicAopProxy，通过动态代理触发 TemplatesImpl.newTransformer() 执行任意代码。',
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
      className: 'org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider',
      methodName: 'readObject',
      label: 'MethodInvokeTypeProvider.readObject()',
      description: 'Spring 类型包装器反序列化，调用 getType() 获取类型并反射调用指定方法。',
      codeSnippet: `private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException {
    inputStream.defaultReadObject();
    Method method = ReflectionUtils.findMethod(this.provider.getType().getClass(), this.methodName);
    this.result = ReflectionUtils.invokeMethod(method, this.provider.getType());
}`,
      highlightLines: [3, 4, 5],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.springframework.core.SerializableTypeWrapper$TypeProvider',
      methodName: 'getType',
      label: 'TypeProvider.getType()',
      description: 'TypeProvider 代理对象调用 getType()。',
      codeSnippet: `public interface TypeProvider extends Serializable {
    Type getType();
    default Object getSource() { return null; }
}`,
      highlightLines: [2],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'java.lang.reflect.Proxy',
      methodName: 'invoke',
      label: 'Proxy.invoke()',
      description: '动态代理通过 AnnotationInvocationHandler 处理 getType 调用。',
      codeSnippet: `public Object invoke(Object proxy, Method method, Object[] args) {
    return handler.invoke(proxy, method, args);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.springframework.aop.framework.JdkDynamicAopProxy',
      methodName: 'invoke',
      label: 'JdkDynamicAopProxy.invoke()',
      description: 'Spring AOP 代理调用，获取目标对象并执行方法。',
      codeSnippet: `public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    TargetSource targetSource = this.advised.getTargetSource();
    return AopUtils.invokeJoinpointUsingReflection(target, method, args);
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.springframework.aop.support.AopUtils',
      methodName: 'invokeJoinpointUsingReflection',
      label: 'AopUtils.invokeJoinpointUsingReflection()',
      description: 'Spring AOP 工具类反射调用目标方法。',
      codeSnippet: `public static Object invokeJoinpointUsingReflection(Object target, Method method, Object[] args) {
    return method.invoke(target, args);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'newTransformer',
      label: 'TemplatesImpl.newTransformer()',
      description: '触发模板加载，调用 getTransletInstance() 加载恶意字节码。',
      codeSnippet: `public Transformer newTransformer() throws TransformerConfigurationException {
    return new TransformerImpl(getTransletInstance(), ...);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-8',
      type: 'sink',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getTransletInstance',
      label: 'TemplatesImpl.getTransletInstance()',
      description: '最终触发点：加载恶意 Translet 类并实例化，执行静态代码块中的命令。',
      codeSnippet: `private Translet getTransletInstance() throws TransformerConfigurationException {
    if (_name == null) return null;
    if (_class == null) defineTransletClasses();
    return (Translet) _class[_transletIndex].newInstance();
}`,
      highlightLines: [3, 4],
    },
  ],
  edges: [
    {
      id: 'edge-1',
      source: 'node-1',
      target: 'node-2',
      invocationType: 'direct',
      label: '反序列化触发',
      description: 'ObjectInputStream反序列化MethodInvokeTypeProvider',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '获取类型',
      description: '调用TypeProvider.getType()',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'proxy',
      label: '代理调用',
      description: 'TypeProvider代理调用',
      animated: true,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'proxy',
      label: 'AOP代理',
      description: 'JdkDynamicAopProxy处理newTransformer调用',
      animated: true,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'reflection',
      label: '反射调用',
      description: 'AopUtils反射调用方法',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'reflection',
      label: '模板转换',
      description: '调用TemplatesImpl.newTransformer()',
      animated: true,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '类加载',
      description: '加载恶意字节码并实例化',
      animated: true,
    },
  ],
}
