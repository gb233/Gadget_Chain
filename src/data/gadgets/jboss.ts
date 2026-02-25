import type { GadgetChain } from './types'

export const jBossInterceptors1: GadgetChain = {
  metadata: {
    chainId: 'jboss-interceptors1',
    name: 'JBossInterceptors1',
    targetDependency: 'org.jboss.interceptor:jboss-interceptor-core:2.0.0.Final',
    description: '利用 JBoss Interceptors 的 MethodInvocation 类，通过反序列化触发拦截器链执行，可导致任意方法调用。',
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
      className: 'org.jboss.interceptor.proxy.InterceptorMethodHandler',
      methodName: 'readObject',
      label: 'InterceptorMethodHandler.readObject()',
      description: 'JBoss拦截器方法处理器的反序列化。',
      codeSnippet: `private void readObject(ObjectInputStream in)
    throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // ... 恢复拦截器状态 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.jboss.interceptor.proxy.InterceptorMethodHandler',
      methodName: 'invoke',
      label: 'InterceptorMethodHandler.invoke()',
      description: '动态代理的 invoke 方法，触发拦截器链。',
      codeSnippet: `public Object invoke(Object self, Method method,
    Method proceed, Object[] args) throws Throwable {
    return interceptorChain.invoke(interceptionContext);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.jboss.interceptor.chain.InterceptorChain',
      methodName: 'invoke',
      label: 'InterceptorChain.invoke()',
      description: '执行拦截器链。',
      codeSnippet: `public Object invoke(InterceptionContext ctx) throws Exception {
    // ... 执行拦截器 ...
    return ctx.proceed();
}`,
      highlightLines: [3],
    },
    {
      id: 'node-5',
      type: 'sink',
      className: 'java.lang.reflect.Method',
      methodName: 'invoke',
      label: 'Method.invoke()',
      description: '最终触发点：反射调用目标方法。',
      codeSnippet: `public Object invoke(Object obj, Object... args)
    throws IllegalAccessException, InvocationTargetException {
    return methodAccessor.invoke(obj, args);
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
      description: 'ObjectInputStream反序列化InterceptorMethodHandler',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'proxy',
      label: '动态代理',
      description: '反序列化后代理对象触发invoke',
      animated: true,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '拦截器链',
      description: 'invoke调用InterceptorChain.invoke',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'reflection',
      label: '反射执行',
      description: '拦截器链反射调用目标方法',
      animated: true,
    },
  ],
}

export const jrmpClient: GadgetChain = {
  metadata: {
    chainId: 'jrmp-client',
    name: 'JRMPClient',
    targetDependency: 'Built-in (Java RT)',
    description: '利用 Java RMI 的 JRMP 协议。通过反序列化恶意代理对象触发向攻击者控制的 JRMP 服务器发起连接，用于配合 JRMPListener 实现二次反序列化攻击。',
    author: 'mbechler',
    complexity: 'Low',
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
      className: 'java.rmi.server.RemoteObjectInvocationHandler',
      methodName: 'readObject',
      label: 'RemoteObjectInvocationHandler.readObject()',
      description: 'RMI 调用处理器的反序列化，包含 UnicastRef。',
      codeSnippet: `private void readObject(ObjectInputStream in)
    throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // ... 恢复远程引用 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'sun.rmi.transport.LiveRef',
      methodName: 'readExternal',
      label: 'LiveRef.readExternal()',
      description: '读取远程对象引用信息，包含攻击者控制的端点。',
      codeSnippet: `public void readExternal(ObjectInput in)
    throws IOException, ClassNotFoundException {
    // ... 读取端点信息 ...
    ep = TCPEndpoint.read(in);
    // ...
}`,
      highlightLines: [4],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'sun.rmi.transport.DGCClient',
      methodName: 'registerRefs',
      label: 'DGCClient.registerRefs()',
      description: 'DGC 客户端注册远程引用时触发连接。',
      codeSnippet: `static void registerRefs(Endpoint ep, List refs) {
    // ... 建立到远程端点的连接 ...
    Connection conn = ep.getChannel().newConnection();
    // ...
}`,
      highlightLines: [3],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'sun.rmi.transport.tcp.TCPEndpoint',
      methodName: 'getChannel',
      label: 'TCPEndpoint.getChannel()',
      description: '获取 TCP 通道。',
      codeSnippet: `public Channel getChannel() {
    return tcpTransport.getChannel(this);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-6',
      type: 'sink',
      className: 'sun.rmi.transport.tcp.TCPChannel',
      methodName: 'newConnection',
      label: 'TCPChannel.newConnection()',
      description: '最终触发点：建立到攻击者控制的 RMI 服务器的 TCP 连接。',
      codeSnippet: `public Connection newConnection() throws RemoteException {
    // ... 建立TCP连接到攻击者服务器 ...
    return createConnection();
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
      description: 'ObjectInputStream反序列化RemoteObjectInvocationHandler',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '读取引用',
      description: 'UnicastRef触发LiveRef.readExternal()',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: 'DGC注册',
      description: 'LiveRef触发DGCClient.registerRefs()',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '获取通道',
      description: 'DGC获取TCPEndpoint的Channel',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '建立连接',
      description: 'TCPChannel建立到攻击者服务器的网络连接',
      animated: true,
    },
  ],
}

export const jrmpListener: GadgetChain = {
  metadata: {
    chainId: 'jrmp-listener',
    name: 'JRMPListener',
    targetDependency: 'Built-in (Java RT)',
    description: '配合 JRMPClient 使用。通过反序列化 ActivationGroupImpl 在目标服务器上开启 JRMP 监听端口，等待 JRMPClient 连接后返回恶意序列化对象实现远程代码执行。',
    author: 'mbechler',
    complexity: 'Low',
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
      className: 'java.rmi.server.UnicastRemoteObject',
      methodName: 'readObject',
      label: 'UnicastRemoteObject.readObject()',
      description: 'ActivationGroupImpl 继承 UnicastRemoteObject，反序列化时触发 reexport。',
      codeSnippet: `private void readObject(ObjectInputStream in)
    throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    reexport();
}`,
      highlightLines: [4],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'java.rmi.server.UnicastRemoteObject',
      methodName: 'reexport',
      label: 'UnicastRemoteObject.reexport()',
      description: '重新导出远程对象，创建监听端口。',
      codeSnippet: `private void reexport() throws RemoteException {
    if (csf == null && ssf == null) {
        exportObject((Remote) this, port);
    } else {
        exportObject((Remote) this, port, csf, ssf);
    }
}`,
      highlightLines: [3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'java.rmi.server.UnicastRemoteObject',
      methodName: 'exportObject',
      label: 'UnicastRemoteObject.exportObject()',
      description: '导出远程对象到指定端口。',
      codeSnippet: `public static Remote exportObject(Remote obj, int port)
    throws RemoteException {
    return exportObject(obj, new UnicastServerRef(port));
}`,
      highlightLines: [3],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'sun.rmi.server.UnicastServerRef',
      methodName: 'exportObject',
      label: 'UnicastServerRef.exportObject()',
      description: '创建 LiveRef 并监听端口。',
      codeSnippet: `public Remote exportObject(Remote impl, Object data,
        boolean permanent) throws RemoteException {
    // ... 创建 LiveRef ...
    return ref.exportObject(impl, data, permanent);
}`,
      highlightLines: [4],
    },
    {
      id: 'node-6',
      type: 'sink',
      className: 'sun.rmi.transport.tcp.TCPTransport',
      methodName: 'listen',
      label: 'TCPTransport.listen()',
      description: '最终触发点：在指定端口监听 JRMP 连接。',
      codeSnippet: `public void listen() throws RemoteException {
    // ... 创建 ServerSocket 监听端口 ...
    serverSocket = serverSocketFactory.createServerSocket(ep.getPort());
    // ... 启动监听线程 ...
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
      description: 'ObjectInputStream反序列化ActivationGroupImpl',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '重新导出',
      description: 'UnicastRemoteObject.readObject调用reexport()',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '导出对象',
      description: 'reexport调用exportObject()',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '创建引用',
      description: 'exportObject创建UnicastServerRef',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '开始监听',
      description: 'LiveRef.exportObject触发TCPTransport.listen()',
      animated: true,
    },
  ],
}
