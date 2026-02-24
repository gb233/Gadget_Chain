import type { GadgetChain } from './types'

export const myfaces1: GadgetChain = {
  metadata: {
    chainId: 'myfaces1',
    name: 'Myfaces1',
    targetDependency: 'org.apache.myfaces.core:myfaces-impl:2.2.9',
    description: '利用 Apache MyFaces JSF 框架的 StateUtils，通过反序列化触发 EL 表达式求值。',
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
      codeSnippet: `public final Object readObject() throws IOException, ClassNotFoundException {
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'source',
      className: 'org.apache.myfaces.shared.util.StateUtils',
      methodName: 'getAsObject',
      label: 'StateUtils.getAsObject()',
      description: 'MyFaces反序列化状态对象。',
      codeSnippet: `public static Object getAsObject(byte[] bytes) throws IOException {
    ObjectInputStream ois = new ObjectInputStream(bais);
    return ois.readObject();
}`,
      highlightLines: [3],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'javax.el.ELContext',
      methodName: 'getELResolver',
      label: 'ELContext.getELResolver()',
      description: '获取EL解析器。',
      codeSnippet: `public abstract ELResolver getELResolver();`,
      highlightLines: [1],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'javax.el.ELResolver',
      methodName: 'getValue',
      label: 'ELResolver.getValue()',
      description: '解析EL表达式获取值。',
      codeSnippet: `public abstract Object getValue(ELContext context, Object base, Object property);`,
      highlightLines: [1],
    },
    {
      id: 'node-5',
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
      description: 'MyFaces反序列化状态',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: 'EL上下文',
      description: '获取EL上下文',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: 'EL解析',
      description: '解析EL表达式',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'reflection',
      label: '命令执行',
      description: 'EL表达式执行命令',
      animated: true,
    },
  ],
}

export const myfaces2: GadgetChain = {
  metadata: {
    chainId: 'myfaces2',
    name: 'Myfaces2',
    targetDependency: 'org.apache.myfaces.core:myfaces-impl:2.2.9',
    description: '利用 MyFaces 的 ResourceUtils，通过反序列化触发资源加载和 EL 表达式执行。',
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
      type: 'gadget',
      className: 'org.apache.myfaces.shared.renderkit.html.util.ResourceUtils',
      methodName: 'getResourceURL',
      label: 'ResourceUtils.getResourceURL()',
      description: '获取资源URL。',
      codeSnippet: `public static String getResourceURL(FacesContext context, String value) {
    // ... 解析资源路径 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'javax.faces.application.Application',
      methodName: 'evaluateExpressionGet',
      label: 'Application.evaluateExpressionGet()',
      description: '求值EL表达式。',
      codeSnippet: `public Object evaluateExpressionGet(FacesContext context, String expression, Class expectedType) {
    // ... 求值表达式 ...
}`,
      highlightLines: [1],
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
      target: 'node-2',
      invocationType: 'direct',
      label: '反序列化触发',
      description: '反序列化触发资源加载',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: 'EL求值',
      description: '资源路径作为EL表达式求值',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'reflection',
      label: '命令执行',
      description: 'EL表达式执行命令',
      animated: true,
    },
  ],
}
