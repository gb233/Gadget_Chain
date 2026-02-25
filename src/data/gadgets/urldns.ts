import type { GadgetChain } from './types'

export const urldns: GadgetChain = {
  metadata: {
    chainId: 'urldns',
    name: 'URLDNS',
    targetDependency: 'Built-in (Java RT)',
    description: '利用Java内置类发起DNS解析请求。通常用于无回显情况下的反序列化漏洞探测。使用HashMap作为入口，通过URL对象的hashCode触发DNS查询。',
    author: 'gebl',
    complexity: 'Low',
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
      description: '反序列化入口。HashMap在反序列化时会重组Map，从而计算Key的hash。',
      codeSnippet: `private void readObject(java.io.ObjectInputStream s)
    throws IOException, ClassNotFoundException {
    // ... 略去部分代码 ...
    for (int i = 0; i < mappings; i++) {
        K key = (K) s.readObject();
        V value = (V) s.readObject();
        putVal(hash(key), key, value, false, false);
    }
}`,
      highlightLines: [7],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'java.util.HashMap',
      methodName: 'hash',
      label: 'HashMap.hash()',
      description: '对传入的Key（此处为精心构造的URL对象）调用其hashCode()方法。',
      codeSnippet: `static final int hash(Object key) {
    int h;
    return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'java.net.URL',
      methodName: 'hashCode',
      label: 'URL.hashCode()',
      description: 'URL类的hashCode方法。如果hashCode属性为-1（初始值），则会触发handler进行计算，从而导致DNS查询。',
      codeSnippet: `public synchronized int hashCode() {
    if (hashCode != -1)
        return hashCode;

    hashCode = handler.hashCode(this);
    return hashCode;
}`,
      highlightLines: [5],
    },
    {
      id: 'node-5',
      type: 'sink',
      className: 'java.net.URLStreamHandler',
      methodName: 'getHostAddress',
      label: 'URLStreamHandler.getHostAddress()',
      description: '最终触发点：解析URL中的主机名，产生一次真正的DNS请求。攻击者可通过DNS日志接收请求，确认目标存在反序列化漏洞。',
      codeSnippet: `protected synchronized InetAddress getHostAddress(URL u) {
    if (u.hostAddress != null)
        return u.hostAddress;

    try {
        u.hostAddress = InetAddress.getByName(u.getHost());
    } catch (UnknownHostException ex) {
        return null;
    }
    return u.hostAddress;
}`,
      highlightLines: [6],
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
      label: '内部方法调用',
      description: 'HashMap恢复数据时内部调用hash()方法计算键的哈希值',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'override',
      label: '多态调用',
      description: '由于传入的Key是URL对象，实际调用的是java.net.URL.hashCode()',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '触发DNS请求',
      description: 'URL对象委托URLStreamHandler进行hash计算，最终触发getHostAddress',
      animated: true,
    },
  ],
}
