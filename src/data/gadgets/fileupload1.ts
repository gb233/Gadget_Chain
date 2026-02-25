import type { GadgetChain } from './types'

export const fileUpload1: GadgetChain = {
  metadata: {
    chainId: 'fileupload1',
    name: 'FileUpload1',
    targetDependency: 'commons-fileupload:commons-fileupload:1.3.1',
    description: '利用 Apache Commons FileUpload 的 DiskFileItem，通过反序列化触发文件写入操作。控制repository和fileName参数可写入任意位置文件（webshell）。',
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
      className: 'org.apache.commons.fileupload.disk.DiskFileItem',
      methodName: 'readObject',
      label: 'DiskFileItem.readObject()',
      description: 'DiskFileItem反序列化时恢复文件上传状态。',
      codeSnippet: `private void readObject(ObjectInputStream in)
    throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // ... 恢复临时文件状态 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.apache.commons.fileupload.disk.DiskFileItem',
      methodName: 'getOutputStream',
      label: 'DiskFileItem.getOutputStream()',
      description: '获取输出流写入上传文件内容。如果dfos为null则创建临时文件。',
      codeSnippet: `public OutputStream getOutputStream()
    throws IOException {
    if (dfos == null) {
        File outputFile = getTempFile();
        dfos = new DeferredFileOutputStream(...);
    }
    return dfos;
}`,
      highlightLines: [3, 4, 5],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.apache.commons.fileupload.disk.DiskFileItem',
      methodName: 'getTempFile',
      label: 'DiskFileItem.getTempFile()',
      description: '获取临时文件。攻击者通过控制repository和fileName参数可指定任意文件路径。',
      codeSnippet: `protected File getTempFile() {
    File tempDir = repository;
    if (tempDir == null) {
        tempDir = new File(System.getProperty("java.io.tmpdir"));
    }
    return new File(tempDir, fileName);
}`,
      highlightLines: [6],
    },
    {
      id: 'node-5',
      type: 'gadget',
      className: 'org.apache.commons.io.output.DeferredFileOutputStream',
      methodName: 'write',
      label: 'DeferredFileOutputStream.write()',
      description: '将数据写入文件输出流。',
      codeSnippet: `public void write(byte[] b, int off, int len)
    throws IOException {
    // ... 写入数据到文件 ...
    super.write(b, off, len);
}`,
      highlightLines: [4],
    },
    {
      id: 'node-6',
      type: 'gadget',
      className: 'org.apache.commons.io.output.ThresholdingOutputStream',
      methodName: 'write',
      label: 'ThresholdingOutputStream.write()',
      description: '带阈值的输出流，超过阈值后写入文件。',
      codeSnippet: `public void write(byte[] b, int off, int len)
    throws IOException {
    // ... 检查阈值并写入 ...
    getStream().write(b, off, len);
}`,
      highlightLines: [4],
    },
    {
      id: 'node-7',
      type: 'sink',
      className: 'java.io.FileOutputStream',
      methodName: 'write',
      label: 'FileOutputStream.write()',
      description: '最终触发点：将数据写入文件系统。攻击者可通过构造特定的repository（如webapp目录）和fileName（如shell.jsp）写入webshell。',
      codeSnippet: `public void write(byte b[], int off, int len)
    throws IOException {
    // ... 写入文件 ...
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
      description: 'ObjectInputStream反序列化DiskFileItem',
      animated: false,
    },
    {
      id: 'edge-2',
      source: 'node-2',
      target: 'node-3',
      invocationType: 'direct',
      label: '获取流',
      description: 'DiskFileItem获取输出流',
      animated: false,
    },
    {
      id: 'edge-3',
      source: 'node-3',
      target: 'node-4',
      invocationType: 'direct',
      label: '创建文件',
      description: 'getOutputStream调用getTempFile创建文件',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-3',
      target: 'node-5',
      invocationType: 'direct',
      label: '写入缓冲',
      description: 'DeferredFileOutputStream处理写入',
      animated: false,
    },
    {
      id: 'edge-5',
      source: 'node-5',
      target: 'node-6',
      invocationType: 'direct',
      label: '阈值检查',
      description: 'ThresholdingOutputStream检查并写入',
      animated: false,
    },
    {
      id: 'edge-6',
      source: 'node-6',
      target: 'node-7',
      invocationType: 'direct',
      label: '文件写入',
      description: '最终写入文件系统',
      animated: true,
    },
  ],
}
