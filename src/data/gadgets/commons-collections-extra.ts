import type { GadgetChain } from './types'

// CommonsCollections3 - 使用 InstantiateTransformer + TrAXFilter + TemplatesImpl
export const commonsCollections3: GadgetChain = {
  metadata: {
    chainId: 'commons-collections3',
    name: 'CommonsCollections3',
    targetDependency: 'commons-collections:commons-collections:3.1',
    description: '使用 InstantiateTransformer 实例化 TrAXFilter，通过 TrAXFilter 构造器调用 TemplatesImpl.newTransformer() 触发恶意字节码加载。绕过对 InvokerTransformer 的黑名单检测。',
    author: 'frohoff',
    complexity: 'High',
    cve: 'CVE-2015-4852',
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
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'source',
      className: 'sun.reflect.annotation.AnnotationInvocationHandler',
      methodName: 'readObject',
      label: 'AnnotationInvocationHandler.readObject()',
      description: 'JDK内部类，反序列化时会恢复memberValues映射。',
      codeSnippet: `private void readObject(ObjectInputStream s) throws ... {
    s.defaultReadObject();
    // ... 恢复注解状态 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'java.util.Map',
      methodName: 'entrySet',
      label: 'Map(Proxy).entrySet()',
      description: '动态代理对象的entrySet()方法调用，触发代理的invoke方法。',
      codeSnippet: `// 动态代理的Map对象
Map mapProxy = (Map) Proxy.newProxyInstance(
    Map.class.getClassLoader(),
    new Class[] { Map.class },
    annotationInvocationHandler
);
// 调用 entrySet() 触发 invoke`,
      highlightLines: [5],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'sun.reflect.annotation.AnnotationInvocationHandler',
      methodName: 'invoke',
      label: 'AnnotationInvocationHandler.invoke()',
      description: '当代理对象的方法被调用时触发，调用memberValues.get()。',
      codeSnippet: `public Object invoke(Object proxy, Method method, Object[] args) {
    String member = method.getName();
    // ... 处理特殊方法 ...
    // 关键：调用memberValues的方法
    Object result = memberValues.get(member);
    return result;
}`,
      highlightLines: [5],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.apache.commons.collections.map.LazyMap',
      methodName: 'get',
      label: 'LazyMap.get()',
      description: '当key不存在时，通过factory创建value。',
      codeSnippet: `public Object get(Object key) {
    if (!map.containsKey(key)) {
        Object value = factory.transform(key);
        map.put(key, value);
        return value;
    }
    return map.get(key);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.ChainedTransformer',
      methodName: 'transform',
      label: 'ChainedTransformer.transform()',
      description: '链式转换器，依次调用多个transformer。',
      codeSnippet: `public Object transform(Object object) {
    for (int i = 0; i < iTransformers.length; i++) {
        object = iTransformers[i].transform(object);
    }
    return object;
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.ConstantTransformer',
      methodName: 'transform',
      label: 'ConstantTransformer.transform()',
      description: '返回常量TrAXFilter.class，作为InstantiateTransformer的输入。',
      codeSnippet: `public Object transform(Object input) {
    return iConstant; // TrAXFilter.class
}`,
      highlightLines: [2],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.InstantiateTransformer',
      methodName: 'transform',
      label: 'InstantiateTransformer.transform()',
      description: '实例化TrAXFilter，传入恶意TemplatesImpl作为构造参数。',
      codeSnippet: `public Object transform(Object input) {
    Class cls = (Class) input; // TrAXFilter.class
    // iParamTypes = { Templates.class }
    // iArgs = { 恶意TemplatesImpl }
    return cls.getConstructor(iParamTypes).newInstance(iArgs);
}`,
      highlightLines: [5],
    },
    {
      id: 'node-9',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter',
      methodName: '<init>',
      label: 'TrAXFilter Constructor',
      description: 'TrAXFilter构造器中调用templates.newTransformer()。',
      codeSnippet: `public TrAXFilter(Templates templates) {
    this._templates = templates;
    this._transformer = this._templates.newTransformer();
}`,
      highlightLines: [3],
    },
    {
      id: 'node-10',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'newTransformer',
      label: 'TemplatesImpl.newTransformer()',
      description: '触发恶意字节码的加载和实例化。',
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
      id: 'node-11',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getTransletInstance',
      label: 'TemplatesImpl.getTransletInstance()',
      description: '获取Translet实例，如果未加载则调用defineTransletClasses()。',
      codeSnippet: `private Translet getTransletInstance() {
    if (_class == null) {
        defineTransletClasses();
    }
    // 实例化恶意类
    return (Translet) _class[_transletIndex].newInstance();
}`,
      highlightLines: [3, 6],
    },
    {
      id: 'node-12',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'defineTransletClasses',
      label: 'TemplatesImpl.defineTransletClasses()',
      description: '定义Translet类，通过TransletClassLoader加载字节码。',
      codeSnippet: `private void defineTransletClasses() {
    // ... 创建TransletClassLoader ...
    for (int i = 0; i < _bytecodes.length; i++) {
        _class[i] = loader.defineClass(_bytecodes[i]);
    }
}`,
      highlightLines: [4],
    },
    {
      id: 'node-13',
      type: 'sink',
      className: 'java.lang.ClassLoader',
      methodName: 'defineClass',
      label: 'TransletClassLoader.defineClass()',
      description: '加载恶意字节码，触发静态代码块执行。',
      codeSnippet: `Class defineClass(byte[] bytecode) {
    return defineClass(null, bytecode, 0, bytecode.length);
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
      description: 'ObjectInputStream反序列化AnnotationInvocationHandler',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'proxy',
      label: '代理恢复',
      description: '反序列化后代理对象可用，方法调用触发invoke',
      animated: true,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'proxy',
      label: '动态代理',
      description: 'Map.entrySet()调用触发AnnotationInvocationHandler.invoke()',
      animated: true,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: 'Map操作',
      description: 'AnnotationInvocationHandler调用LazyMap.get',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '工厂转换',
      description: 'LazyMap通过ChainedTransformer创建value',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '链式调用-1',
      description: 'ChainedTransformer第一个transformer: ConstantTransformer',
      animated: false,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '链式调用-2',
      description: 'ConstantTransformer返回TrAXFilter.class作为InstantiateTransformer输入',
      animated: false,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'reflection',
      label: '反射实例化',
      description: 'InstantiateTransformer反射实例化TrAXFilter',
      animated: true,
    },
    {
      id: 'edge-9',
      source: 'node-9',
      target: 'node-10',
      invocationType: 'direct',
      label: '构造器调用',
      description: 'TrAXFilter构造器中调用templates.newTransformer()',
      animated: false,
    },
    {
      id: 'edge-10',
      source: 'node-10',
      target: 'node-11',
      invocationType: 'direct',
      label: '获取实例',
      description: 'newTransformer()调用getTransletInstance()',
      animated: false,
    },
    {
      id: 'edge-11',
      source: 'node-11',
      target: 'node-12',
      invocationType: 'direct',
      label: '定义类',
      description: 'getTransletInstance()调用defineTransletClasses()',
      animated: false,
    },
    {
      id: 'edge-12',
      source: 'node-12',
      target: 'node-13',
      invocationType: 'direct',
      label: '加载字节码',
      description: 'defineTransletClasses()通过TransletClassLoader.defineClass()加载恶意字节码',
      animated: true,
    },
  ],
}

// CommonsCollections4
export const commonsCollections4: GadgetChain = {
  metadata: {
    chainId: 'commons-collections4',
    name: 'CommonsCollections4',
    targetDependency: 'org.apache.commons:commons-collections4:4.0',
    description: 'Commons Collections 4版本链，使用 InstantiateTransformer + TrAXFilter + TemplatesImpl。通过 PriorityQueue 和 TransformingComparator 触发 InstantiateTransformer 实例化 TrAXFilter，进而触发 TemplatesImpl 恶意字节码加载。',
    author: 'frohoff',
    complexity: 'High',
    cve: 'CVE-2015-4852',
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
      description: 'PriorityQueue反序列化时重建堆结构。',
      codeSnippet: `private void readObject(ObjectInputStream s)
    throws IOException, ClassNotFoundException {
    s.defaultReadObject();
    heapify();
}`,
      highlightLines: [4],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.apache.commons.collections4.comparators.TransformingComparator',
      methodName: 'compare',
      label: 'TransformingComparator.compare()',
      description: '比较前通过transformer转换对象。',
      codeSnippet: `public int compare(I obj1, I obj2) {
    O value1 = this.transformer.transform(obj1);
    O value2 = this.transformer.transform(obj2);
    return this.decorated.compare(value1, value2);
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.apache.commons.collections4.functors.InstantiateTransformer',
      methodName: 'transform',
      label: 'InstantiateTransformer.transform()',
      description: '实例化TrAXFilter，传入恶意TemplatesImpl作为构造参数。',
      codeSnippet: `public O transform(final I input) {
    Class cls = (Class) input; // TrAXFilter.class
    // iParamTypes = { Templates.class }
    // iArgs = { 恶意TemplatesImpl }
    return cls.getConstructor(iParamTypes).newInstance(iArgs);
}`,
      highlightLines: [3, 4, 5],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter',
      methodName: '<init>',
      label: 'TrAXFilter Constructor',
      description: 'TrAXFilter构造器中调用templates.newTransformer()。',
      codeSnippet: `public TrAXFilter(Templates templates) {
    this._templates = templates;
    this._transformer = this._templates.newTransformer();
}`,
      highlightLines: [3],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'newTransformer',
      label: 'TemplatesImpl.newTransformer()',
      description: '触发恶意字节码的加载和实例化。',
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
      id: 'node-7',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getTransletInstance',
      label: 'TemplatesImpl.getTransletInstance()',
      description: '获取Translet实例，如果未加载则调用defineTransletClasses()。',
      codeSnippet: `private Translet getTransletInstance() {
    if (_class == null) {
        defineTransletClasses();
    }
    // 实例化恶意类
    return (Translet) _class[_transletIndex].newInstance();
}`,
      highlightLines: [3, 6],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'defineTransletClasses',
      label: 'TemplatesImpl.defineTransletClasses()',
      description: '定义Translet类，通过TransletClassLoader加载字节码。',
      codeSnippet: `private void defineTransletClasses() {
    // ... 创建TransletClassLoader ...
    for (int i = 0; i < _bytecodes.length; i++) {
        _class[i] = loader.defineClass(_bytecodes[i]);
    }
}`,
      highlightLines: [4],
    },
    {
      id: 'node-9',
      type: 'sink',
      className: 'java.lang.ClassLoader',
      methodName: 'defineClass',
      label: 'TransletClassLoader.defineClass()',
      description: '加载恶意字节码，触发静态代码块执行。',
      codeSnippet: `Class defineClass(byte[] bytecode) {
    return defineClass(null, bytecode, 0, bytecode.length);
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
      description: 'ObjectInputStream反序列化PriorityQueue',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '比较器调用',
      description: 'PriorityQueue排序使用TransformingComparator',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '转换器链',
      description: 'TransformingComparator调用InstantiateTransformer',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'reflection',
      label: '反射实例化',
      description: 'InstantiateTransformer反射实例化TrAXFilter',
      animated: true,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '构造器调用',
      description: 'TrAXFilter构造器中调用templates.newTransformer()',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '获取实例',
      description: 'newTransformer()调用getTransletInstance()',
      animated: false,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '定义类',
      description: 'getTransletInstance()调用defineTransletClasses()',
      animated: false,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'direct',
      label: '加载字节码',
      description: 'defineTransletClasses()通过TransletClassLoader.defineClass()加载恶意字节码',
      animated: true,
    },
  ],
}

// CommonsCollections5
export const commonsCollections5: GadgetChain = {
  metadata: {
    chainId: 'commons-collections5',
    name: 'CommonsCollections5',
    targetDependency: 'commons-collections:commons-collections:3.1',
    description: '利用 BadAttributeValueExpException 触发 toString()。通过 TiedMapEntry 触发 LazyMap.get()，进而触发 InvokerTransformer 调用 Runtime.exec() 执行命令。不需要使用动态代理。',
    author: 'matthias_kaiser',
    complexity: 'Medium',
    cve: 'CVE-2015-4852',
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
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'source',
      className: 'javax.management.BadAttributeValueExpException',
      methodName: 'readObject',
      label: 'BadAttributeValueExpException.readObject()',
      description: '反序列化时触发 toString()。',
      codeSnippet: `private void readObject(ObjectInputStream ois) throws ... {
    ois.defaultReadObject();
    val = val.toString();
}`,
      highlightLines: [3],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.apache.commons.collections.keyvalue.TiedMapEntry',
      methodName: 'toString',
      label: 'TiedMapEntry.toString()',
      description: 'toString 调用 getValue()。',
      codeSnippet: `public String toString() {
    return getKey() + "=" + getValue();
}`,
      highlightLines: [2],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.apache.commons.collections.keyvalue.TiedMapEntry',
      methodName: 'getValue',
      label: 'TiedMapEntry.getValue()',
      description: '获取值时调用 Map.get()。',
      codeSnippet: `public Object getValue() {
    return map.get(key);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.apache.commons.collections.map.LazyMap',
      methodName: 'get',
      label: 'LazyMap.get()',
      description: '当key不存在时，通过factory创建value。',
      codeSnippet: `public Object get(Object key) {
    if (!map.containsKey(key)) {
        Object value = factory.transform(key);
        map.put(key, value);
        return value;
    }
    return map.get(key);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.ChainedTransformer',
      methodName: 'transform',
      label: 'ChainedTransformer.transform()',
      description: '链式转换器，依次调用多个transformer。',
      codeSnippet: `public Object transform(Object object) {
    for (int i = 0; i < iTransformers.length; i++) {
        object = iTransformers[i].transform(object);
    }
    return object;
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.ConstantTransformer',
      methodName: 'transform',
      label: 'ConstantTransformer.transform()',
      description: '返回常量 Runtime.class。',
      codeSnippet: `public Object transform(Object input) {
    return iConstant; // Runtime.class
}`,
      highlightLines: [2],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.InvokerTransformer',
      methodName: 'transform',
      label: 'InvokerTransformer.transform()',
      description: '通过反射调用 Runtime.getRuntime() 方法。',
      codeSnippet: `public Object transform(Object input) {
    Class cls = input.getClass();
    Method method = cls.getMethod(iMethodName, iParamTypes);
    return method.invoke(input, iArgs);
    // iMethodName="getRuntime", iArgs=[]
}`,
      highlightLines: [3],
    },
    {
      id: 'node-9',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.InvokerTransformer',
      methodName: 'transform',
      label: 'InvokerTransformer.transform()',
      description: '通过反射调用 Runtime.exec() 方法执行命令。',
      codeSnippet: `public Object transform(Object input) {
    Class cls = input.getClass();
    Method method = cls.getMethod(iMethodName, iParamTypes);
    return method.invoke(input, iArgs);
    // iMethodName="exec", iArgs=["calc.exe"]
}`,
      highlightLines: [3],
    },
    {
      id: 'node-10',
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
      description: 'ObjectInputStream反序列化BadAttributeValueExpException',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: 'toString触发',
      description: 'BadAttributeValueExpException调用val.toString()',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '获取值',
      description: 'TiedMapEntry.toString调用getValue()',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: 'Map操作',
      description: 'TiedMapEntry.getValue调用LazyMap.get',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '工厂转换',
      description: 'LazyMap通过ChainedTransformer创建value',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '链式调用-1',
      description: 'ChainedTransformer第一个transformer: ConstantTransformer返回Runtime.class',
      animated: false,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '链式调用-2',
      description: 'InvokerTransformer调用Runtime.getRuntime()',
      animated: false,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'direct',
      label: '链式调用-3',
      description: 'InvokerTransformer调用Runtime.exec()',
      animated: false,
    },
    {
      id: 'edge-9',
      source: 'node-9',
      target: 'node-10',
      invocationType: 'reflection',
      label: '命令执行',
      description: '最终调用Runtime.exec()执行系统命令',
      animated: true,
    },
  ],
}

// CommonsCollections6
export const commonsCollections6: GadgetChain = {
  metadata: {
    chainId: 'commons-collections6',
    name: 'CommonsCollections6',
    targetDependency: 'commons-collections:commons-collections:3.1',
    description: '使用 HashMap 和 TiedMapEntry。通过 HashMap.put() 触发 TiedMapEntry.hashCode()，进而触发 LazyMap.get()，最终通过 InvokerTransformer 调用 Runtime.exec() 执行命令。',
    author: 'matthias_kaiser',
    complexity: 'Medium',
    cve: 'CVE-2015-4852',
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
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'source',
      className: 'java.util.HashMap',
      methodName: 'readObject',
      label: 'HashMap.readObject()',
      description: 'HashMap反序列化时重组Map，计算Key的hash。',
      codeSnippet: `private void readObject(ObjectInputStream s)
    throws IOException, ClassNotFoundException {
    for (int i = 0; i < mappings; i++) {
        putVal(hash(key), key, value, false, false);
    }
}`,
      highlightLines: [4],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.apache.commons.collections.keyvalue.TiedMapEntry',
      methodName: 'hashCode',
      label: 'TiedMapEntry.hashCode()',
      description: '计算hash时调用 getValue()。',
      codeSnippet: `public int hashCode() {
    Object value = getValue();
    return (getKey() == null ? 0 : getKey().hashCode()) ^
           (value == null ? 0 : value.hashCode());
}`,
      highlightLines: [2],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.apache.commons.collections.keyvalue.TiedMapEntry',
      methodName: 'getValue',
      label: 'TiedMapEntry.getValue()',
      description: '获取值时调用 Map.get()。',
      codeSnippet: `public Object getValue() {
    return map.get(key);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.apache.commons.collections.map.LazyMap',
      methodName: 'get',
      label: 'LazyMap.get()',
      description: '当key不存在时，通过factory创建value。',
      codeSnippet: `public Object get(Object key) {
    if (!map.containsKey(key)) {
        Object value = factory.transform(key);
        map.put(key, value);
        return value;
    }
    return map.get(key);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.ChainedTransformer',
      methodName: 'transform',
      label: 'ChainedTransformer.transform()',
      description: '链式转换器，依次调用多个transformer。',
      codeSnippet: `public Object transform(Object object) {
    for (int i = 0; i < iTransformers.length; i++) {
        object = iTransformers[i].transform(object);
    }
    return object;
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.ConstantTransformer',
      methodName: 'transform',
      label: 'ConstantTransformer.transform()',
      description: '返回常量 Runtime.class。',
      codeSnippet: `public Object transform(Object input) {
    return iConstant; // Runtime.class
}`,
      highlightLines: [2],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.InvokerTransformer',
      methodName: 'transform',
      label: 'InvokerTransformer.transform()',
      description: '通过反射调用 Runtime.getRuntime() 方法。',
      codeSnippet: `public Object transform(Object input) {
    Class cls = input.getClass();
    Method method = cls.getMethod(iMethodName, iParamTypes);
    return method.invoke(input, iArgs);
    // iMethodName="getRuntime", iArgs=[]
}`,
      highlightLines: [3],
    },
    {
      id: 'node-9',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.InvokerTransformer',
      methodName: 'transform',
      label: 'InvokerTransformer.transform()',
      description: '通过反射调用 Runtime.exec() 方法执行命令。',
      codeSnippet: `public Object transform(Object input) {
    Class cls = input.getClass();
    Method method = cls.getMethod(iMethodName, iParamTypes);
    return method.invoke(input, iArgs);
    // iMethodName="exec", iArgs=["calc.exe"]
}`,
      highlightLines: [3],
    },
    {
      id: 'node-10',
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
      description: 'ObjectInputStream反序列化HashMap',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'override',
      label: 'hashCode调用',
      description: 'HashMap.hash调用TiedMapEntry.hashCode',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '获取值',
      description: 'TiedMapEntry.hashCode调用getValue()',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: 'Map操作',
      description: 'TiedMapEntry.getValue调用LazyMap.get',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '工厂转换',
      description: 'LazyMap通过ChainedTransformer创建value',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '链式调用-1',
      description: 'ChainedTransformer第一个transformer: ConstantTransformer返回Runtime.class',
      animated: false,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '链式调用-2',
      description: 'InvokerTransformer调用Runtime.getRuntime()',
      animated: false,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'direct',
      label: '链式调用-3',
      description: 'InvokerTransformer调用Runtime.exec()',
      animated: false,
    },
    {
      id: 'edge-9',
      source: 'node-9',
      target: 'node-10',
      invocationType: 'reflection',
      label: '命令执行',
      description: '最终调用Runtime.exec()执行系统命令',
      animated: true,
    },
  ],
}

// CommonsCollections7
export const commonsCollections7: GadgetChain = {
  metadata: {
    chainId: 'commons-collections7',
    name: 'CommonsCollections7',
    targetDependency: 'commons-collections:commons-collections:3.1',
    description: '利用 Hashtable 和 AbstractMap。通过 Hashtable.reconstitutionPut() 触发 AbstractMap.equals()，进而触发 LazyMap.get()，最终通过 InvokerTransformer 调用 Runtime.exec() 执行命令。',
    author: 'matthias_kaiser',
    complexity: 'High',
    cve: 'CVE-2015-4852',
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
    return obj;
}`,
      highlightLines: [1],
    },
    {
      id: 'node-2',
      type: 'source',
      className: 'java.util.Hashtable',
      methodName: 'readObject',
      label: 'Hashtable.readObject()',
      description: 'Hashtable反序列化时重组表结构。',
      codeSnippet: `private void readObject(ObjectInputStream s)
    throws IOException, ClassNotFoundException {
    s.defaultReadObject();
    reconstitutionPut(table, key, value);
}`,
      highlightLines: [4],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'java.util.Hashtable',
      methodName: 'reconstitutionPut',
      label: 'Hashtable.reconstitutionPut()',
      description: '重建表时检查key是否已存在。',
      codeSnippet: `private void reconstitutionPut(Entry[] tab, Object key, Object value)
    throws StreamCorruptedException {
    int hash = key.hashCode();
    int index = (hash & 0x7FFFFFFF) % tab.length;
    // ... 检查是否已存在 ...
}`,
      highlightLines: [3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'java.util.AbstractMap',
      methodName: 'equals',
      label: 'AbstractMap.equals()',
      description: '比较两个Map是否相等时调用 entrySet()。',
      codeSnippet: `public boolean equals(Object o) {
    if (o == this) return true;
    if (!(o instanceof Map)) return false;
    Map m = (Map) o;
    if (m.size() != size()) return false;
    // ... 比较entry ...
}`,
      highlightLines: [2],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.apache.commons.collections.map.LazyMap',
      methodName: 'get',
      label: 'LazyMap.get()',
      description: '当key不存在时，通过factory创建value。',
      codeSnippet: `public Object get(Object key) {
    if (!map.containsKey(key)) {
        Object value = factory.transform(key);
        map.put(key, value);
        return value;
    }
    return map.get(key);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.ChainedTransformer',
      methodName: 'transform',
      label: 'ChainedTransformer.transform()',
      description: '链式转换器，依次调用多个transformer。',
      codeSnippet: `public Object transform(Object object) {
    for (int i = 0; i < iTransformers.length; i++) {
        object = iTransformers[i].transform(object);
    }
    return object;
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.ConstantTransformer',
      methodName: 'transform',
      label: 'ConstantTransformer.transform()',
      description: '返回常量 Runtime.class。',
      codeSnippet: `public Object transform(Object input) {
    return iConstant; // Runtime.class
}`,
      highlightLines: [2],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.InvokerTransformer',
      methodName: 'transform',
      label: 'InvokerTransformer.transform()',
      description: '通过反射调用 Runtime.getRuntime() 方法。',
      codeSnippet: `public Object transform(Object input) {
    Class cls = input.getClass();
    Method method = cls.getMethod(iMethodName, iParamTypes);
    return method.invoke(input, iArgs);
    // iMethodName="getRuntime", iArgs=[]
}`,
      highlightLines: [3],
    },
    {
      id: 'node-9',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.InvokerTransformer',
      methodName: 'transform',
      label: 'InvokerTransformer.transform()',
      description: '通过反射调用 Runtime.exec() 方法执行命令。',
      codeSnippet: `public Object transform(Object input) {
    Class cls = input.getClass();
    Method method = cls.getMethod(iMethodName, iParamTypes);
    return method.invoke(input, iArgs);
    // iMethodName="exec", iArgs=["calc.exe"]
}`,
      highlightLines: [3],
    },
    {
      id: 'node-10',
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
      description: 'ObjectInputStream反序列化Hashtable',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '表重建',
      description: 'Hashtable.readObject调用reconstitutionPut',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'override',
      label: 'equals调用',
      description: 'reconstitutionPut中检查key相等性',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: 'Map操作',
      description: 'AbstractMap.equals调用entrySet()触发LazyMap.get',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '工厂转换',
      description: 'LazyMap通过ChainedTransformer创建value',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '链式调用-1',
      description: 'ChainedTransformer第一个transformer: ConstantTransformer返回Runtime.class',
      animated: false,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '链式调用-2',
      description: 'InvokerTransformer调用Runtime.getRuntime()',
      animated: false,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'direct',
      label: '链式调用-3',
      description: 'InvokerTransformer调用Runtime.exec()',
      animated: false,
    },
    {
      id: 'edge-9',
      source: 'node-9',
      target: 'node-10',
      invocationType: 'reflection',
      label: '命令执行',
      description: '最终调用Runtime.exec()执行系统命令',
      animated: true,
    },
  ],
}
