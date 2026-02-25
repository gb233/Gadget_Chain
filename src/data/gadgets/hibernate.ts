import type { GadgetChain } from './types'

export const hibernate1: GadgetChain = {
  metadata: {
    chainId: 'hibernate1',
    name: 'Hibernate1',
    targetDependency: 'org.hibernate:hibernate-core:4.3.11.Final',
    description: '利用 Hibernate 的 TypedValue 和 ComponentType，通过 hashCode 计算触发 Getter 方法调用，最终执行 TemplatesImpl.newTransformer() 加载恶意字节码。',
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
      type: 'source',
      className: 'java.util.HashMap',
      methodName: 'readObject',
      label: 'HashMap.readObject()',
      description: 'HashMap反序列化时恢复哈希表结构，计算key的hashCode。',
      codeSnippet: `private void readObject(ObjectInputStream s) {
    // ... 恢复table ...
    for (int i = 0; i < mappings; i++) {
        putForCreate(key, value); // 触发hashCode
    }
}`,
      highlightLines: [4, 5],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.hibernate.engine.spi.TypedValue',
      methodName: 'hashCode',
      label: 'TypedValue.hashCode()',
      description: 'TypedValue计算hashCode时触发类型哈希计算。',
      codeSnippet: `public int hashCode() {
    return (Integer) this.hashcode.getValue();
}

// hashcode是ValueHolder，初始化时：
// type.getHashCode(value) 被延迟调用`,
      highlightLines: [1, 2, 5],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.hibernate.type.ComponentType',
      methodName: 'getHashCode',
      label: 'ComponentType.getHashCode()',
      description: '组件类型计算哈希值，获取组件属性值。',
      codeSnippet: `public int getHashCode(Object x, SessionFactoryImplementor factory) {
    Object[] values = getPropertyValues(x, entityMode);
    // ... 计算hash ...
}`,
      highlightLines: [2],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.hibernate.tuple.component.AbstractComponentTuplizer',
      methodName: 'getPropertyValue',
      label: 'AbstractComponentTuplizer.getPropertyValue()',
      description: '获取组件属性值时调用 Getter。',
      codeSnippet: `public Object getPropertyValue(Object component, int i)
    throws HibernateException {
    return getters[i].get(component);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.hibernate.property.BasicPropertyAccessor$BasicGetter',
      methodName: 'get',
      label: 'BasicGetter.get()',
      description: 'Hibernate 属性访问器，通过反射调用 getter 方法。',
      codeSnippet: `public Object get(Object target) {
    return method.invoke(target);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getOutputProperties',
      label: 'TemplatesImpl.getOutputProperties()',
      description: '被调用的 getter 方法，内部调用 newTransformer()。',
      codeSnippet: `public Properties getOutputProperties() {
    return newTransformer().getOutputProperties();
}`,
      highlightLines: [2],
    },
    {
      id: 'node-8',
      type: 'sink',
      className: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',
      methodName: 'getTransletInstance',
      label: 'TemplatesImpl.getTransletInstance()',
      description: '最终触发点：加载恶意 Translet 类并实例化，执行静态代码块中的命令。',
      codeSnippet: `private Translet getTransletInstance() {
    if (_class == null) defineTransletClasses();
    return (Translet) _class[_transletIndex].newInstance();
}`,
      highlightLines: [2, 3],
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
      invocationType: 'direct',
      label: 'hashCode计算',
      description: 'HashMap计算key的hashCode',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '类型哈希',
      description: 'TypedValue调用ComponentType.getHashCode',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '获取属性值',
      description: 'ComponentType获取组件属性值',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'reflection',
      label: 'Getter调用',
      description: 'AbstractComponentTuplizer调用Getter',
      animated: true,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'reflection',
      label: '反射调用',
      description: 'BasicGetter反射调用getOutputProperties',
      animated: true,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '类加载',
      description: 'TemplatesImpl加载恶意字节码',
      animated: true,
    },
  ],
}

export const hibernate2: GadgetChain = {
  metadata: {
    chainId: 'hibernate2',
    name: 'Hibernate2',
    targetDependency: 'org.hibernate:hibernate-core:4.3.11.Final',
    description: '利用 Hibernate 的 TypedValue 和 ComponentType 触发 JdbcRowSetImpl.getDatabaseMetaData()，通过 JNDI 查找加载远程类，实现分阶段攻击。',
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
      type: 'source',
      className: 'java.util.HashMap',
      methodName: 'readObject',
      label: 'HashMap.readObject()',
      description: 'HashMap反序列化时恢复哈希表结构，计算key的hashCode。',
      codeSnippet: `private void readObject(ObjectInputStream s) {
    // ... 恢复table ...
    for (int i = 0; i < mappings; i++) {
        putForCreate(key, value); // 触发hashCode
    }
}`,
      highlightLines: [4, 5],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.hibernate.engine.spi.TypedValue',
      methodName: 'hashCode',
      label: 'TypedValue.hashCode()',
      description: 'TypedValue计算hashCode时触发类型哈希计算。',
      codeSnippet: `public int hashCode() {
    return (Integer) this.hashcode.getValue();
}

// hashcode是ValueHolder，初始化时：
// type.getHashCode(value) 被延迟调用`,
      highlightLines: [1, 2, 5],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.hibernate.type.ComponentType',
      methodName: 'getHashCode',
      label: 'ComponentType.getHashCode()',
      description: '组件类型计算哈希值，获取组件属性值。',
      codeSnippet: `public int getHashCode(Object x, SessionFactoryImplementor factory) {
    Object[] values = getPropertyValues(x, entityMode);
    // ... 计算hash ...
}`,
      highlightLines: [2],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.hibernate.tuple.component.AbstractComponentTuplizer',
      methodName: 'getPropertyValue',
      label: 'AbstractComponentTuplizer.getPropertyValue()',
      description: '获取组件属性值时调用 Getter。',
      codeSnippet: `public Object getPropertyValue(Object component, int i)
    throws HibernateException {
    return getters[i].get(component);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.hibernate.property.BasicPropertyAccessor$BasicGetter',
      methodName: 'get',
      label: 'BasicGetter.get()',
      description: 'Hibernate 属性访问器，通过反射调用 getter 方法。',
      codeSnippet: `public Object get(Object target) {
    return method.invoke(target);
}`,
      highlightLines: [2],
    },
    {
      id: 'node-7',
      type: 'gadget',
      className: 'com.sun.rowset.JdbcRowSetImpl',
      methodName: 'getDatabaseMetaData',
      label: 'JdbcRowSetImpl.getDatabaseMetaData()',
      description: '被调用的 getter 方法，内部调用 connect() 建立数据库连接。',
      codeSnippet: `public DatabaseMetaData getDatabaseMetaData() throws SQLException {
    return this.connect().getMetaData();
}`,
      highlightLines: [2],
    },
    {
      id: 'node-8',
      type: 'gadget',
      className: 'com.sun.rowset.JdbcRowSetImpl',
      methodName: 'connect',
      label: 'JdbcRowSetImpl.connect()',
      description: '建立数据库连接时触发 JNDI 查找。',
      codeSnippet: `private Connection connect() throws SQLException {
    if (this.getDataSourceName() != null) {
        InitialContext var1 = new InitialContext();
        return ((DataSource)var1.lookup(this.getDataSourceName())).getConnection();
    }
    // ...
}`,
      highlightLines: [3, 4],
    },
    {
      id: 'node-9',
      type: 'sink',
      className: 'javax.naming.InitialContext',
      methodName: 'lookup',
      label: 'InitialContext.lookup()',
      description: '最终触发点：JNDI 查找加载远程类，执行恶意代码（分阶段攻击）。',
      codeSnippet: `public Object lookup(String name) throws NamingException {
    return getURLOrDefaultInitCtx(name).lookup(name);
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
      description: 'ObjectInputStream反序列化HashMap',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: 'hashCode计算',
      description: 'HashMap计算key的hashCode',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '类型哈希',
      description: 'TypedValue调用ComponentType.getHashCode',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '获取属性值',
      description: 'ComponentType获取组件属性值',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'reflection',
      label: 'Getter调用',
      description: 'AbstractComponentTuplizer调用Getter',
      animated: true,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'reflection',
      label: '反射调用',
      description: 'BasicGetter反射调用getDatabaseMetaData',
      animated: true,
    },
    {
      id: 'edge-7',
      source: 'node-7',
      target: 'node-8',
      invocationType: 'direct',
      label: '连接数据库',
      description: 'getDatabaseMetaData调用connect()',
      animated: false,
    },
    {
      id: 'edge-8',
      source: 'node-8',
      target: 'node-9',
      invocationType: 'direct',
      label: 'JNDI注入',
      description: 'JdbcRowSetImpl触发JNDI查找',
      animated: true,
    },
  ],
}
