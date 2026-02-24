import type { GadgetChain } from './types'

export const commonsBeanutils1: GadgetChain = {
  metadata: {
    chainId: 'commons-beanutils1',
    name: 'CommonsBeanutils1',
    targetDependency: 'commons-beanutils:commons-beanutils:1.9.2',
    description: '利用 Apache Commons BeanUtils 的 PropertyUtils，通过 PriorityQueue 触发任意 getter 方法调用，最终导致模板执行。',
    author: 'frohoff',
    complexity: 'Medium',
    cve: 'CVE-2014-0114',
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
      className: 'java.util.PriorityQueue',
      methodName: 'readObject',
      label: 'PriorityQueue.readObject()',
      description: 'PriorityQueue反序列化时会重建堆结构，需要对元素进行比较排序。',
      codeSnippet: `private void readObject(ObjectInputStream s)
    throws IOException, ClassNotFoundException {
    // ... 读取元素 ...
    heapify();
}`,
      highlightLines: [4],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.apache.commons.beanutils.BeanComparator',
      methodName: 'compare',
      label: 'BeanComparator.compare()',
      description: '通过 PropertyUtils 获取指定属性值进行比较。',
      codeSnippet: `public int compare(Object o1, Object o2) {
    Object value1 = PropertyUtils.getProperty(o1, property);
    Object value2 = PropertyUtils.getProperty(o2, property);
    return internalCompare(value1, value2);
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.apache.commons.beanutils.PropertyUtils',
      methodName: 'getProperty',
      label: 'PropertyUtils.getProperty()',
      description: '通过反射获取对象的属性值，调用对应的 getter 方法。',
      codeSnippet: `public static Object getProperty(Object bean, String name)
    throws IllegalAccessException, InvocationTargetException,
           NoSuchMethodException {
    return PropertyUtilsBean.getInstance().getProperty(bean, name);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getOutputProperties',
      label: 'TemplatesImpl.getOutputProperties()',
      description: '获取输出属性，会触发模板类的加载。',
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
      id: 'node-6',
      type: 'sink',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'newTransformer',
      label: 'TemplatesImpl.newTransformer()',
      description: '最终触发点：加载恶意字节码并实例化，执行静态代码块中的任意代码。',
      codeSnippet: `public synchronized Transformer newTransformer()
    throws TransformerConfigurationException {
    TransformerImpl transformer = new TransformerImpl(
        getTransletInstance(), ...
    );
    return transformer;
}`,
      highlightLines: [3],
    },
  ],
  edges: [
    {
      id: 'edge-1',
      source: 'node-1',
      target: 'node-2',
      invocationType: 'direct',
      label: '反序列化触发',
      description: 'ObjectInputStream反序列化PriorityQueue对象',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '比较器调用',
      description: 'PriorityQueue使用BeanComparator比较元素',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'reflection',
      label: '属性获取',
      description: 'BeanComparator调用PropertyUtils.getProperty',
      animated: true,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'reflection',
      label: 'Getter调用',
      description: 'PropertyUtils反射调用getOutputProperties',
      animated: true,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '模板加载',
      description: 'getOutputProperties调用newTransformer触发类加载',
      animated: true,
    },
  ],
}
