import type { GadgetChain } from './types'

export const aspectJWeaver: GadgetChain = {
  metadata: {
    chainId: 'aspectj-weaver',
    name: 'AspectJWeaver',
    targetDependency: 'org.aspectj:aspectjweaver:1.9.2',
    description: '利用 AspectJ Weaver 的织入功能和 SimpleCache 机制。通过反序列化 SimpleCacheFactory 触发类加载器从指定目录加载恶意类文件，最终执行任意代码。',
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
      description: 'AspectJ Weaver 缓存工厂的反序列化方法，恢复时触发缓存初始化。',
      codeSnippet: `private void readObject(ObjectInputStream in)
    throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // 触发缓存初始化
    initializeCache();
}`,
      highlightLines: [4],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.aspectj.weaver.tools.cache.SimpleCacheFactory',
      methodName: 'initializeCache',
      label: 'SimpleCacheFactory.initializeCache()',
      description: '初始化缓存，创建 SimpleCache 实例。',
      codeSnippet: `private void initializeCache() {
    // 创建并配置 SimpleCache
    cache = new SimpleCache(directory, store);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.aspectj.weaver.tools.cache.SimpleCache',
      methodName: 'get',
      label: 'SimpleCache.get()',
      description: '从缓存中获取类字节码，如果不存在则从存储后端读取。',
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
      id: 'node-5',
      type: 'gadget',
      className: 'org.aspectj.weaver.tools.cache.SimpleCacheStore',
      methodName: 'get',
      label: 'SimpleCacheStore.get()',
      description: '从文件系统存储中读取类字节码数据。攻击者控制目录路径。',
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
      id: 'node-6',
      type: 'gadget',
      className: 'org.aspectj.weaver.loadtime.ClassPreProcessorAgentAdapter',
      methodName: 'preProcess',
      label: 'ClassPreProcessorAgentAdapter.preProcess()',
      description: '类预处理器适配器，准备从字节码定义类。',
      codeSnippet: `public byte[] preProcess(String className, byte[] bytes) {
    // 处理类字节码
    return weavingAdaptor.weaveClass(className, bytes);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'java.lang.ClassLoader',
      methodName: 'defineClass',
      label: 'ClassLoader.defineClass()',
      description: '使用类加载器从字节数组定义类。',
      codeSnippet: `protected Class<?> defineClass(String name, byte[] b,
    int off, int len, ProtectionDomain protectionDomain) {
    return ClassLoader.defineClass(name, b, 0, b.length,
        this.getClass().getProtectionDomain());
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-8',
      type: 'sink',
      className: 'java.lang.Class',
      methodName: 'newInstance',
      label: 'Class.newInstance()',
      description: '最终触发点：实例化加载的恶意类，执行构造方法和静态代码块中的任意代码。',
      codeSnippet: `public T newInstance()
    throws InstantiationException, IllegalAccessException {
    // ... 创建实例 ...
    return newInstance0();
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
      description: 'readObject 完成后调用 initializeCache 初始化缓存',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '获取缓存',
      description: '初始化过程中调用 SimpleCache.get()',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '存储读取',
      description: '缓存未命中，从 SimpleCacheStore 读取类文件',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '字节码处理',
      description: '读取字节码后交给 ClassPreProcessorAgentAdapter 处理',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'reflection',
      label: '类定义',
      description: '通过 ClassLoader.defineClass 定义类',
      animated: true,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '实例化',
      description: '类加载后调用 newInstance 执行静态代码块',
      animated: true,
    },
  ],
}
