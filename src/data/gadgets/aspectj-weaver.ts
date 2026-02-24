import type { GadgetChain } from './types'

export const aspectJWeaver: GadgetChain = {
  metadata: {
    chainId: 'aspectj-weaver',
    name: 'AspectJWeaver',
    targetDependency: 'org.aspectj:aspectjweaver:1.9.2',
    description: '利用 AspectJ Weaver 的织入功能触发恶意类加载。通过反序列化 SimpleBeanFactory 触发类加载器加载恶意类文件。',
    author: 'Jang',
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
      className: 'org.aspectj.weaver.tools.cache.SimpleCacheFactory',
      methodName: 'readObject',
      label: 'SimpleCacheFactory.readObject()',
      description: 'AspectJ Weaver 缓存工厂的 readObject 方法，反序列化时会触发类加载。',
      codeSnippet: `private void readObject(ObjectInputStream in)
    throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // 触发缓存加载
    initializeCache();
}`,
      highlightLines: [4],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.aspectj.weaver.tools.cache.SimpleCache',
      methodName: 'get',
      label: 'SimpleCache.get()',
      description: '从缓存中获取类字节码，如果不存在则调用存储后端。',
      codeSnippet: `public byte[] get(String key) {
    byte[] bytes = memoryCache.get(key);
    if (bytes == null) {
        bytes = store.get(key);
        if (bytes != null) {
            memoryCache.put(key, bytes);
        }
    }
    return bytes;
}`,
      highlightLines: [3, 4, 5],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.aspectj.weaver.tools.cache.SimpleCacheStore',
      methodName: 'get',
      label: 'SimpleCacheStore.get()',
      description: '从存储中读取类字节码数据。',
      codeSnippet: `public byte[] get(String key) {
    File file = new File(directory, key.replace('/', '_'));
    if (file.exists()) {
        return readFile(file);
    }
    return null;
}`,
      highlightLines: [2, 3, 4],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.aspectj.weaver.loadtime.ClassPreProcessorAgentAdapter',
      methodName: 'defineClass',
      label: 'ClassPreProcessorAgentAdapter.defineClass()',
      description: '使用类加载器定义类，触发类加载和初始化。',
      codeSnippet: `protected Class<?> defineClass(String name, byte[] b) {
    return ClassLoader.defineClass(name, b, 0, b.length,
        this.getClass().getProtectionDomain());
}`,
      highlightLines: [2],
    },
    {
      id: 'node-6',
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
      description: 'ObjectInputStream 反序列化 SimpleCacheFactory',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '缓存初始化',
      description: 'readObject 完成后初始化缓存',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '存储读取',
      description: '缓存未命中，从存储后端读取',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '字节码处理',
      description: '读取字节码后准备类定义',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'reflection',
      label: '类加载',
      description: '调用 ClassLoader.defineClass 加载恶意类',
      animated: true,
    },
  ],
}
