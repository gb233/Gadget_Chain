import type { GadgetChain } from './types'

export const myfaces1: GadgetChain = {
  metadata: {
    chainId: 'myfaces1',
    name: 'Myfaces1',
    targetDependency: 'org.apache.myfaces.core:myfaces-impl:2.2.9',
    description: '利用 Apache MyFaces JSF 框架的 SerializedView，通过反序列化触发 EL 表达式求值。',
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
      type: 'gadget',
      className: 'org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression',
      methodName: 'readObject',
      label: 'ValueExpressionMethodExpression.readObject()',
      description: 'MyFaces EL表达式包装类，反序列化时恢复EL表达式。',
      codeSnippet: `private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // 恢复ValueExpression状态
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'javax.el.ValueExpression',
      methodName: 'getValue',
      label: 'ValueExpression.getValue()',
      description: '获取EL表达式的值。',
      codeSnippet: `public abstract Object getValue(ELContext context);`,
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
      description: 'ObjectInputStream反序列化ValueExpressionMethodExpression',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: 'EL求值',
      description: '触发ValueExpression.getValue',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: 'EL解析',
      description: '通过ELResolver解析表达式',
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
    description: '利用 MyFaces 的 TagAttribute 和 MethodExpression，通过反序列化触发 EL 表达式执行。',
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
      className: 'org.apache.myfaces.view.facelets.tag.TagAttribute',
      methodName: 'getValueExpression',
      label: 'TagAttribute.getValueExpression()',
      description: '获取标签属性的ValueExpression。',
      codeSnippet: `public ValueExpression getValueExpression(FaceletContext ctx, Class type) {
    // 创建或获取ValueExpression
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'javax.el.MethodExpression',
      methodName: 'invoke',
      label: 'MethodExpression.invoke()',
      description: '调用EL方法表达式。',
      codeSnippet: `public abstract Object invoke(ELContext context, Object[] params);`,
      highlightLines: [1],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'javax.el.ELResolver',
      methodName: 'invoke',
      label: 'ELResolver.invoke()',
      description: '解析并调用EL表达式方法。',
      codeSnippet: `public abstract Object invoke(ELContext context, Object base, Object method, Class<?>[] paramTypes, Object[] params);`,
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
      description: '反序列化触发TagAttribute处理',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '方法调用',
      description: '触发MethodExpression.invoke',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: 'EL解析',
      description: '通过ELResolver解析方法调用',
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
