import type { GadgetChain } from './types'

export const json1: GadgetChain = {
  metadata: {
    chainId: 'json1',
    name: 'JSON1',
    targetDependency: 'net.sf.json-lib:json-lib:2.4',
    description: '利用 json-lib 库的 JSONObject，通过反序列化触发任意 getter 方法调用，最终导致 TemplatesImpl 类加载。',
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
      className: 'net.sf.json.JSONObject',
      methodName: 'readObject',
      label: 'JSONObject.readObject()',
      description: 'json-lib 的 JSONObject 反序列化。',
      codeSnippet: `private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // ... 恢复JSON对象状态 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'net.sf.json.JSONObject',
      methodName: 'get',
      label: 'JSONObject.get()',
      description: '获取 JSON 属性值，触发 getter 方法。',
      codeSnippet: `public Object get(String key) {
    if (key == null) throw new JSONException("Null key.");
    return this.properties.get(key);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'net.sf.json.util.PropertySetStrategy',
      methodName: 'setProperty',
      label: 'PropertySetStrategy.setProperty()',
      description: '设置属性时触发 getter 调用。',
      codeSnippet: `public abstract void setProperty(Object bean, String key, Object value) throws JSONException;`,
      highlightLines: [1],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'net.sf.json.util.JavaIdentifierTransformer',
      methodName: 'transformToJavaIdentifier',
      label: 'JavaIdentifierTransformer.transformToJavaIdentifier()',
      description: '转换属性名并查找 getter 方法。',
      codeSnippet: `public String transformToJavaIdentifier(String str) {
    // ... 转换标识符 ...
    return transformed;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getOutputProperties',
      label: 'TemplatesImpl.getOutputProperties()',
      description: '触发模板类加载。',
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
      type: 'sink',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'newTransformer',
      label: 'TemplatesImpl.newTransformer()',
      description: '最终触发点：加载恶意字节码执行任意代码。',
      codeSnippet: `public synchronized Transformer newTransformer() throws TransformerConfigurationException {
    TransformerImpl transformer = new TransformerImpl(getTransletInstance(), ...);
    return transformer;
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
      description: 'ObjectInputStream反序列化JSONObject',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '属性获取',
      description: 'JSONObject.get获取属性',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '属性设置策略',
      description: 'PropertySetStrategy处理属性',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '标识符转换',
      description: '转换Java标识符',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'reflection',
      label: 'Getter调用',
      description: '反射调用getOutputProperties',
      animated: true,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '模板加载',
      description: '触发字节码加载',
      animated: true,
    },
  ],
}
