import type { GadgetChain } from './types'

export const commonsCollections2: GadgetChain = {
  metadata: {
    chainId: 'commons-collections2',
    name: 'CommonsCollections2',
    targetDependency: 'org.apache.commons:commons-collections4:4.0',
    description: '使用Apache Commons Collections 4的TransformingComparator和InvokerTransformer。通过PriorityQueue触发比较器链，最终执行任意命令。',
    author: 'frohoff',
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
      description: 'Java反序列化标准入口。读取序列化数据流并重建对象。',
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
      className: 'org.apache.commons.collections4.comparators.TransformingComparator',
      methodName: 'compare',
      label: 'TransformingComparator.compare()',
      description: '在比较两个元素之前，先通过transformer对它们进行转换。这是关键的跳板点。',
      codeSnippet: `public int compare(I obj1, I obj2) {
    O value1 = this.transformer.transform(obj1);
    O value2 = this.transformer.transform(obj2);
    return this.decorated.compare(value1, value2);
}`,
      highlightLines: [2, 3],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'org.apache.commons.collections4.functors.InvokerTransformer',
      methodName: 'transform',
      label: 'InvokerTransformer.transform()',
      description: '通过反射调用指定对象的指定方法。攻击者控制iMethodName为newTransformer，从而触发模板加载。',
      codeSnippet: `public O transform(final I input) {
    if (input == null) {
        return null;
    }
    try {
        final Class<?> cls = input.getClass();
        final Method method = cls.getMethod(iMethodName, iParamTypes);
        return (O) method.invoke(input, iArgs);
    } catch (final NoSuchMethodException ex) {
        throw new FunctorException(ex);
    }
}`,
      highlightLines: [6],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: 'java.lang.reflect.Method',
      methodName: 'invoke',
      label: 'Method.invoke()',
      description: 'Java反射的核心方法，用于动态调用方法。这里调用TemplatesImpl.newTransformer()。',
      codeSnippet: `@CallerSensitive
public Object invoke(Object obj, Object... args)
    throws IllegalAccessException,
           IllegalArgumentException,
           InvocationTargetException {
    // ... 反射调用 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-9',
      type: 'sink',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'newTransformer',
      label: 'TemplatesImpl.newTransformer()',
      description: '触发恶意字节码的加载和实例化，最终执行攻击者控制的类构造方法中的代码。',
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
      type: 'sink',
      className: 'java.lang.Runtime',
      methodName: 'exec',
      label: 'Runtime.exec()',
      description: '最终命令执行点。恶意类构造方法中调用Runtime.getRuntime().exec(command)执行任意命令。',
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
      description: '排序过程中使用TransformingComparator.compare()比较元素',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '转换器链',
      description: 'TransformingComparator调用InvokerTransformer.transform()',
      animated: false,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'reflection',
      label: '反射调用',
      description: 'InvokerTransformer通过反射调用方法',
      animated: true,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'reflection',
      label: '触发加载',
      description: '反射调用TemplatesImpl.newTransformer()',
      animated: true,
    },
    {
      id: 'edge-9',
      source: 'node-9',
      target: 'node-10',
      invocationType: 'direct',
      label: '代码执行',
      description: '恶意类加载后执行构造方法中的Runtime.exec()',
      animated: true,
    },
  ],
}

export const commonsCollections1: GadgetChain = {
  metadata: {
    chainId: 'commons-collections1',
    name: 'CommonsCollections1',
    targetDependency: 'commons-collections:commons-collections:3.1',
    description: '经典的Commons Collections反序列化链，使用AnnotationInvocationHandler作为入口，通过LazyMap和ChainedTransformer链触发命令执行。',
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
      description: 'Java反序列化标准入口。读取序列化数据流并重建对象。',
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
      className: 'sun.reflect.annotation.AnnotationInvocationHandler',
      methodName: 'readObject',
      label: 'AnnotationInvocationHandler.readObject()',
      description: 'JDK内部类，用于处理注解代理。反序列化时会恢复memberValues映射。',
      codeSnippet: `private void readObject(ObjectInputStream s) throws ... {
    // ... 读取注解类型和memberValues ...
    AnnotationType annotationType = null;
    try {
        annotationType = AnnotationType.getInstance(type);
    } catch (IllegalArgumentException e) {
        throw new InvalidObjectException(...);
    }
    // ...
}`,
      highlightLines: [2],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'java.util.Map',
      methodName: 'entrySet',
      label: 'Map(Proxy).entrySet()',
      description: '动态代理对象的entrySet()方法调用。在反序列化后或被调用时触发代理的invoke方法。',
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
      description: '当代理对象的方法被调用时，invoke方法处理。entrySet()会触发memberValues.entrySet()。',
      codeSnippet: `public Object invoke(Object proxy, Method method, Object[] args) {
    String member = method.getName();
    Class<?>[] paramTypes = method.getParameterTypes();

    if (member.equals("equals") && paramTypes.length == 1 ...)
        return equalsImpl(args[0]);

    if (member.equals("toString"))
        return toStringImpl();

    if (member.equals("hashCode"))
        return hashCodeImpl();

    if (member.equals("annotationType"))
        return type;

    // 关键：调用memberValues的方法
    Object result = memberValues.get(member);
    // ...
}`,
      highlightLines: [17],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.apache.commons.collections.map.LazyMap',
      methodName: 'get',
      label: 'LazyMap.get()',
      description: '装饰器模式的Map实现。当key不存在时，通过factory创建value。这是关键的跳板点。',
      codeSnippet: `public Object get(Object key) {
    // create value for key if key is not currently in the map
    if (map.containsKey(key) == false) {
        Object value = factory.transform(key);
        map.put(key, value);
        return value;
    }
    return map.get(key);
}`,
      highlightLines: [4],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.ChainedTransformer',
      methodName: 'transform',
      label: 'ChainedTransformer.transform()',
      description: '链式转换器，依次调用多个transformer，前一个的输出作为后一个的输入。',
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
      description: '返回常量值，用于链的开始，提供Runtime.class作为初始输入。',
      codeSnippet: `public Object transform(Object input) {
    return iConstant;
}`,
      highlightLines: [2],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.InvokerTransformer',
      methodName: 'transform',
      label: 'InvokerTransformer[0].transform() → getMethod',
      description: '第一个InvokerTransformer，通过反射调用Class.getMethod("getRuntime")获取Method对象。',
      codeSnippet: `public Object transform(Object input) {
    if (input == null) {
        return null;
    }
    try {
        Class cls = input.getClass();
        // iMethodName = "getMethod"
        // iArgs = "getRuntime"
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);
    } catch (...) {
        throw new FunctorException(...);
    }
}`,
      highlightLines: [7],
    },
    {
      id: 'node-9',
      type: 'gadget',
      className: 'java.lang.Class',
      methodName: 'getMethod',
      label: 'Class.getMethod()',
      description: '获取Runtime类的getRuntime静态方法。',
      codeSnippet: `public Method getMethod(String name, Class<?>... parameterTypes)
    throws NoSuchMethodException, SecurityException {
    return getMethod0(name, parameterTypes, true);
}`,
      highlightLines: [1],
    },
    {
      id: 'node-10',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.InvokerTransformer',
      methodName: 'transform',
      label: 'InvokerTransformer[1].transform() → invoke',
      description: '第二个InvokerTransformer，调用Method.invoke()执行getRuntime方法，返回Runtime实例。',
      codeSnippet: `public Object transform(Object input) {
    if (input == null) {
        return null;
    }
    try {
        Class cls = input.getClass();
        // iMethodName = "invoke"
        // input = Method对象 (getRuntime)
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);
    } catch (...) {
        throw new FunctorException(...);
    }
}`,
      highlightLines: [7],
    },
    {
      id: 'node-11',
      type: 'gadget',
      className: 'java.lang.reflect.Method',
      methodName: 'invoke',
      label: 'Method.invoke() → getRuntime',
      description: '调用getRuntime()静态方法，返回Runtime实例。',
      codeSnippet: `public Object invoke(Object obj, Object... args)
    throws IllegalAccessException, IllegalArgumentException,
           InvocationTargetException {
    // ... 反射调用getRuntime() ...
    return Runtime.getRuntime();
}`,
      highlightLines: [1],
    },
    {
      id: 'node-12',
      type: 'gadget',
      className: 'org.apache.commons.collections.functors.InvokerTransformer',
      methodName: 'transform',
      label: 'InvokerTransformer[2].transform() → exec',
      description: '第三个InvokerTransformer，调用Runtime.exec()执行任意命令。',
      codeSnippet: `public Object transform(Object input) {
    if (input == null) {
        return null;
    }
    try {
        Class cls = input.getClass();
        // iMethodName = "exec"
        // input = Runtime实例
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);
    } catch (...) {
        throw new FunctorException(...);
    }
}`,
      highlightLines: [7],
    },
    {
      id: 'node-13',
      type: 'sink',
      className: 'java.lang.Runtime',
      methodName: 'exec',
      label: 'Runtime.exec()',
      description: '最终命令执行点。执行任意系统命令。',
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
      description: 'ObjectInputStream反序列化AnnotationInvocationHandler对象',
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
      description: 'AnnotationInvocationHandler调用LazyMap的get方法',
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
      description: 'ChainedTransformer链的第一个transformer: ConstantTransformer',
      animated: false,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '链式调用-2',
      description: 'ConstantTransformer返回Runtime.class作为InvokerTransformer[0]输入',
      animated: false,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'reflection',
      label: '反射获取方法',
      description: 'InvokerTransformer[0]通过反射调用Class.getMethod()',
      animated: true,
    },
    {
      id: 'edge-9',
      source: 'node-9',
      target: 'node-10',
      invocationType: 'direct',
      label: '链式调用-3',
      description: 'getMethod返回的Method对象作为InvokerTransformer[1]输入',
      animated: false,
    },
    {
      id: 'edge-10',
      source: 'node-10',
      target: 'node-11',
      invocationType: 'reflection',
      label: '反射调用方法',
      description: 'InvokerTransformer[1]通过反射调用Method.invoke()执行getRuntime',
      animated: true,
    },
    {
      id: 'edge-11',
      source: 'node-11',
      target: 'node-12',
      invocationType: 'direct',
      label: '链式调用-4',
      description: 'getRuntime返回Runtime实例作为InvokerTransformer[2]输入',
      animated: false,
    },
    {
      id: 'edge-12',
      source: 'node-12',
      target: 'node-13',
      invocationType: 'reflection',
      label: '反射执行命令',
      description: 'InvokerTransformer[2]通过反射调用Runtime.exec()',
      animated: true,
    },
  ],
}
