import type { GadgetChain } from './types'

export const fileUpload1: GadgetChain = {
  metadata: {
    chainId: 'fileupload1',
    name: 'FileUpload1',
    targetDependency: 'commons-fileupload:commons-fileupload:1.3.1',
    description: '利用 Apache Commons FileUpload 的 DiskFileItem，通过反序列化触发文件写入操作，可写入 webshell 或任意文件。',
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
    // ... 恢复临时文件 ...
}`,
      highlightLines: [1],
    },
    {
      id: 'node-3',
      type: 'gadget',
      className: 'org.apache.commons.fileupload.disk.DiskFileItem',
      methodName: 'getOutputStream',
      label: 'DiskFileItem.getOutputStream()',
      description: '获取输出流写入上传文件内容。',
      codeSnippet: `public OutputStream getOutputStream()
    throws IOException {
    if (dfos == null) {
        File outputFile = getTempFile();
        dfos = new DeferredFileOutputStream(...);
    }
    return dfos;
}`,
      highlightLines: [4],
    },
    {
      id: 'node-4',
      type: 'gadget',
      className: 'org.apache.commons.io.output.DeferredFileOutputStream',
      methodName: 'write',
      label: 'DeferredFileOutputStream.write()',
      description: '将数据写入临时文件。',
      codeSnippet: `public void write(byte[] b, int off, int len)
    throws IOException {
    // ... 写入数据到文件 ...
    super.write(b, off, len);
}`,
      highlightLines: [3],
    },
    {
      id: 'node-5',
      type: 'sink',
      className: 'java.io.FileOutputStream',
      methodName: 'write',
      label: 'FileOutputStream.write()',
      description: '最终触发点：将数据写入文件系统，可写入任意位置（通过控制repository路径）。',
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
      label: '写入缓冲',
      description: 'DeferredFileOutputStream处理写入',
      animated: false,
    },
    {
      id: 'edge-4',
      source: 'node-4',
      target: 'node-5',
      invocationType: 'direct',
      label: '文件写入',
      description: '最终写入文件系统',
      animated: true,
    },
  ],
}
