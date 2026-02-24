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
    description: '利用 Java RMI 的 JRMP 协议。通过 UnicastRemoteObject 触发网络连接，用于 JRMPListener 的利用。',
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
      label: 'UnicastRemoteObject',
      description: 'RMI 远程对象反序列化时会重建远程引用。',
      codeSnippet: `private void readObject(ObjectInputStream in)
    throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // ... 重建导出状态 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'sun.rmi.transport.LiveRef',
      methodName: 'read',
      label: 'LiveRef.read()',
      description: '读取远程对象引用信息。',
      codeSnippet: `static LiveRef read(ObjectInputStream in, boolean persist)
    throws IOException {
    // ... 读取端点信息 ...
    return new LiveRef(ep, id, persist);
}`,
      highlightLines: [4],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'sun.rmi.transport.tcp.TCPEndpoint',
      methodName: 'getHost',
      label: 'TCPEndpoint.getHost()',
      description: '获取 RMI 服务端地址。',
      codeSnippet: `public String getHost() {
    return host;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-5',
      type: 'sink',
      className: 'sun.rmi.transport.tcp.TCPChannel',
      methodName: 'newConnection',
      label: 'TCPChannel.newConnection()',
      description: '最终触发点：建立到 RMI 服务器的 TCP 连接。',
      codeSnippet: `public Connection newConnection() throws RemoteException {
    // ... 建立TCP连接 ...
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
      description: 'ObjectInputStream反序列化UnicastRemoteObject',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '读取引用',
      description: '读取LiveRef信息',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '获取地址',
      description: '解析TCPEndpoint',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '建立连接',
      description: 'TCPChannel建立网络连接',
      animated: true,
    },
  ],
}

export const jrmpListener: GadgetChain = {
  metadata: {
    chainId: 'jrmp-listener',
    name: 'JRMPListener',
    targetDependency: 'Built-in (Java RT)',
    description: '配合 JRMPClient 使用，在指定端口监听 JRMP 连接，返回恶意对象实现远程代码执行。',
    author: 'mbechler',
    complexity: 'Low',
    cve: null,
  },
  nodes: [
    {
      id: 'node-1',
      type: 'source',
      className: 'sun.rmi.transport.tcp.TCPTransport',
      methodName: 'acceptConnection',
      label: 'TCPTransport.acceptConnection()',
      description: '监听并接受 JRMP 连接。',
      codeSnippet: `private void acceptConnection(Socket socket) {
    // ... 处理新连接 ...
    handleMessages(conn, false);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-2',
      type: 'gadget',
      className: 'sun.rmi.transport.tcp.TCPTransport',
      methodName: 'handleMessages',
      label: 'TCPTransport.handleMessages()',
      description: '处理 JRMP 协议消息。',
      codeSnippet: `private void handleMessages(Connection conn, boolean persistent) {
    // ... 读取消息并处理 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'sun.rmi.server.UnicastServerRef',
      methodName: 'dispatch',
      label: 'UnicastServerRef.dispatch()',
      description: '分发处理远程调用。',
      codeSnippet: `public void dispatch(Remote obj, RemoteCall call) throws ... {
    // ... 分发调用 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-4',
      type: 'sink',
      className: 'sun.rmi.server.UnicastServerRef',
      methodName: 'unmarshalCustomCallData',
      label: 'UnicastServerRef.unmarshalCustomCallData()',
      description: '最终触发点：反序列化调用参数，触发恶意 payload。',
      codeSnippet: `protected void unmarshalCustomCallData(ObjectInputStream in)
    throws IOException, ClassNotFoundException {
    // ... 反序列化数据 ...
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
      label: '接受连接',
      description: 'TCPTransport接受JRMP连接',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '消息分发',
      description: 'handleMessages调用dispatch',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '数据反序列化',
      description: 'dispatch触发unmarshalCustomCallData',
      animated: true,
    },
  ],
}
