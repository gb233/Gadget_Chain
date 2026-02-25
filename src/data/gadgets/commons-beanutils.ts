import type { GadgetChain } from './types'

export const commonsBeanutils1: GadgetChain = {
  metadata: {
    chainId: 'commons-beanutils1',
    name: 'CommonsBeanutils1',
    targetDependency: 'commons-beanutils:commons-beanutils:1.9.2',
    description: '利用 Apache Commons BeanUtils 的 BeanComparator，通过 PriorityQueue 触发任意 getter 方法调用，最终导致 TemplatesImpl 字节码加载执行。',
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
      className: 'java.util.PriorityQueue',
      methodName: 'heapify',
      label: 'PriorityQueue.heapify()',
      description: '重建堆结构时会调用siftDown，进而使用比较器比较元素。',
      codeSnippet: `private void heapify() {
    for (int i = (size >>> 1) - 1; i >= 0; i--)
        siftDown(i, (E) queue[i]);
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'java.util.PriorityQueue',
      methodName: 'siftDown',
      label: 'PriorityQueue.siftDown()',
      description: '下沉操作中需要使用比较器比较父节点和子节点。',
      codeSnippet: `private void siftDown(int k, E x) {
    if (comparator != null)
        siftDownUsingComparator(k, x);
    else
        siftDownComparable(k, x);
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'java.util.PriorityQueue',
      methodName: 'siftDownUsingComparator',
      label: 'PriorityQueue.siftDownUsingComparator()',
      description: '使用自定义比较器进行元素比较。',
      codeSnippet: `private void siftDownUsingComparator(int k, E x) {
    int half = size >>> 1;
    while (k < half) {
        int child = (k << 1) + 1;
        Object c = queue[child];
        int right = child + 1;
        if (right < size &&
            comparator.compare((E) c, (E) queue[right]) > 0)
            c = queue[child = right];
        if (comparator.compare(x, (E) c) <= 0)
            break;
        queue[k] = c;
        k = child;
    }
    queue[k] = x;
}`,
      highlightLines: [9, 10],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.apache.commons.beanutils.BeanComparator',
      methodName: 'compare',
      label: 'BeanComparator.compare()',
      description: '通过 PropertyUtils 获取指定属性值进行比较。这里比较的是outputProperties属性。',
      codeSnippet: `public int compare(Object o1, Object o2) {
    Object value1 = PropertyUtils.getProperty(o1, property);
    Object value2 = PropertyUtils.getProperty(o2, property);
    return internalCompare(value1, value2);
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'org.apache.commons.beanutils.PropertyUtilsBean',
      methodName: 'getProperty',
      label: 'PropertyUtilsBean.getProperty()',
      description: '通过反射获取对象的属性值，调用对应的 getter 方法。',
      codeSnippet: `public Object getProperty(Object bean, String name)
    throws IllegalAccessException, InvocationTargetException,
           NoSuchMethodException {
    return getNestedProperty(bean, name);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getOutputProperties',
      label: 'TemplatesImpl.getOutputProperties()',
      description: '获取输出属性，内部调用newTransformer()，会触发模板类的加载。',
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
      id: 'node-9',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'newTransformer',
      label: 'TemplatesImpl.newTransformer()',
      description: '创建Transformer实例，内部调用getTransletInstance()加载字节码。',
      codeSnippet: `public synchronized Transformer newTransformer()
    throws TransformerConfigurationException {
    TransformerImpl transformer = new TransformerImpl(
        getTransletInstance(), ...
    );
    return transformer;
}`,
      highlightLines: [3],
    },
    {
      id: 'node-10',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getTransletInstance',
      label: 'TemplatesImpl.getTransletInstance()',
      description: '获取Translet实例，如果未加载则调用defineTransletClasses()加载类。',
      codeSnippet: `private Translet getTransletInstance()
    throws TransformerConfigurationException {
    if (_name == null) return null;
    if (_class == null) defineTransletClasses();
    AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance();
    return translet;
}`,
      highlightLines: [4, 5],
    },
    {
      id: 'node-11',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'defineTransletClasses',
      label: 'TemplatesImpl.defineTransletClasses()',
      description: '从字节数组定义类，使用自定义ClassLoader加载恶意类。',
      codeSnippet: `private void defineTransletClasses()
    throws TransformerConfigurationException {
    // ... 创建TransletClassLoader ...
    for (int i = 0; i < classCount; i++) {
        _class[i] = loader.defineClass(_bytecodes[i]);
    }
}`,
      highlightLines: [4, 5],
    },
    {
      id: 'node-12',
      type: 'sink',
      className: 'java.lang.ClassLoader',
      methodName: 'defineClass',
      label: 'ClassLoader.defineClass()',
      description: '最终触发点：加载恶意类字节码，执行静态代码块中的任意代码。',
      codeSnippet: `protected final Class<?> defineClass(String name, byte[] b,
    int off, int len, ProtectionDomain protectionDomain)
    throws ClassFormatError {
    // ... 类加载 ...
    return defineClass1(name, b, off, len, protectionDomain, source);
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
      description: 'ObjectInputStream反序列化PriorityQueue对象',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '堆重建',
      description: 'readObject完成后调用heapify重建堆结构',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '下沉操作',
      description: 'heapify调用siftDown进行元素下沉',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '使用比较器',
      description: 'siftDown调用siftDownUsingComparator',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '比较器调用',
      description: '排序过程中使用BeanComparator.compare()比较元素',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'reflection',
      label: '属性获取',
      description: 'BeanComparator调用PropertyUtilsBean.getProperty',
      animated: true,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'reflection',
      label: 'Getter调用',
      description: 'PropertyUtils反射调用getOutputProperties',
      animated: true,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'direct',
      label: '创建Transformer',
      description: 'getOutputProperties调用newTransformer',
      animated: false,
    },
    {
      id: 'edge-9',
      source: 'node-9',
      target: 'node-10',
      invocationType: 'direct',
      label: '获取Translet',
      description: 'newTransformer调用getTransletInstance',
      animated: false,
    },
    {
      id: 'edge-10',
      source: 'node-10',
      target: 'node-11',
      invocationType: 'direct',
      label: '定义类',
      description: 'getTransletInstance调用defineTransletClasses',
      animated: false,
    },
    {
      id: 'edge-11',
      source: 'node-11',
      target: 'node-12',
      invocationType: 'reflection',
      label: '类加载',
      description: 'TransletClassLoader调用defineClass加载恶意类',
      animated: true,
    },
  ],
}
