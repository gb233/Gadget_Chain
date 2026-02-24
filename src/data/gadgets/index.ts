import type { GadgetChain } from './types'
import { urldns } from './urldns'
import { commonsCollections1, commonsCollections2 } from './commons-collections'
import { commonsCollections3, commonsCollections4, commonsCollections5, commonsCollections6, commonsCollections7 } from './commons-collections-extra'
import { aspectJWeaver } from './aspectj-weaver'
import { beanShell1 } from './beanshell'
import { c3p0 } from './c3p0'
import { click1 } from './click1'
import { clojure } from './clojure'
import { commonsBeanutils1 } from './commons-beanutils'
import { fileUpload1 } from './fileupload1'
import { groovy1 } from './groovy1'
import { hibernate1, hibernate2 } from './hibernate'
import { jBossInterceptors1, jrmpClient, jrmpListener } from './jboss'
import { javassistWeld1, jdk7u21, jython1 } from './more-payloads'
import { mozillaRhino1, mozillaRhino2 } from './mozilla-rhino'
import { myfaces1, myfaces2 } from './myfaces'
import { rome } from './rome'
import { spring1, spring2 } from './spring'
import { json1 } from './json1'
import { vaadin1 } from './vaadin1'
import { wicket1 } from './wicket1'

export * from './types'

// 导出所有payload
export {
  // URLDNS - 纯JDK链
  urldns,

  // Commons Collections 系列
  commonsCollections1,
  commonsCollections2,
  commonsCollections3,
  commonsCollections4,
  commonsCollections5,
  commonsCollections6,
  commonsCollections7,

  // BeanUtils
  commonsBeanutils1,

  // Spring 系列
  spring1,
  spring2,

  // Hibernate 系列
  hibernate1,
  hibernate2,

  // ROME
  rome,

  // JBoss/JRMP
  jBossInterceptors1,
  jrmpClient,
  jrmpListener,

  // Jdk7u21
  jdk7u21,

  // 其他独立payload
  aspectJWeaver,
  beanShell1,
  c3p0,
  click1,
  clojure,
  fileUpload1,
  groovy1,
  javassistWeld1,
  jython1,
  mozillaRhino1,
  mozillaRhino2,
  myfaces1,
  myfaces2,
  json1,
  vaadin1,
  wicket1,
}

// 所有gadget chain的索引（按ysoserial原始顺序）
export const allGadgetChains: GadgetChain[] = [
  urldns,
  aspectJWeaver,
  beanShell1,
  c3p0,
  click1,
  clojure,
  commonsBeanutils1,
  commonsCollections1,
  commonsCollections2,
  commonsCollections3,
  commonsCollections4,
  commonsCollections5,
  commonsCollections6,
  commonsCollections7,
  fileUpload1,
  groovy1,
  hibernate1,
  hibernate2,
  jBossInterceptors1,
  jrmpClient,
  jrmpListener,
  json1,
  javassistWeld1,
  jdk7u21,
  jython1,
  mozillaRhino1,
  mozillaRhino2,
  myfaces1,
  myfaces2,
  rome,
  spring1,
  spring2,
  vaadin1,
  wicket1,
]

// 按名称获取gadget chain
export function getGadgetChainById(id: string): GadgetChain | undefined {
  return allGadgetChains.find(chain => chain.metadata.chainId === id)
}

// 搜索gadget chains
export function searchGadgetChains(query: string): GadgetChain[] {
  const lowerQuery = query.toLowerCase()
  return allGadgetChains.filter(chain =>
    chain.metadata.name.toLowerCase().includes(lowerQuery) ||
    chain.metadata.description.toLowerCase().includes(lowerQuery) ||
    chain.metadata.targetDependency.toLowerCase().includes(lowerQuery)
  )
}

// 按复杂度筛选
export function filterByComplexity(complexity: 'Low' | 'Medium' | 'High'): GadgetChain[] {
  return allGadgetChains.filter(chain => chain.metadata.complexity === complexity)
}

// 按依赖库分类
export const chainsByCategory = {
  'Pure JDK': [urldns, jdk7u21],
  'Commons Collections': [commonsCollections1, commonsCollections2, commonsCollections3, commonsCollections4, commonsCollections5, commonsCollections6, commonsCollections7],
  'Spring': [spring1, spring2],
  'Hibernate': [hibernate1, hibernate2],
  'JBoss': [jBossInterceptors1, jrmpClient, jrmpListener],
  'Scripting': [beanShell1, clojure, groovy1, jython1, mozillaRhino1, mozillaRhino2],
  'Web Frameworks': [click1, myfaces1, myfaces2, vaadin1, wicket1],
  'Others': [aspectJWeaver, c3p0, commonsBeanutils1, fileUpload1, javassistWeld1, json1, rome],
}
