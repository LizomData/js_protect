# Cocos2d Playable Ad 一键加密保护 CLI

## 前提

- 只需要安装 Node.js，不需要 npm install 任何东西
- 把 `protect/` 整个文件夹拷到任意位置即可使用

## 快速使用

```bash
node protect.js 你的游戏.html
```

输出 `你的游戏.protected.html`，默认全开：
- 资源加密（deflate + XXTEA + 文件名 hash + 蜜罐）
- 解密器 VMP 强混淆 + 交叉合并（与游戏代码物理融合）
- 链接跳转保护（自动提取商店链接，10% 替换概率）
- JS 全混淆（轻度）

## 指定输出路径

```bash
node protect.js 游戏.html output.html
```

## 选项

| 选项 | 说明 | 默认 |
|---|---|---|
| `--no-vmp` | 关闭解密器 VMP | 开启 |
| `--no-redirect` | 关闭链接跳转保护 | 开启 |
| `--no-obf` | 关闭 JS 混淆 | 开启 |
| `--redirect-url <URL>` | 手动指定保护链接 | 自动从游戏中提取 |
| `--redirect-rate <0-100>` | 跳转替换概率 | 10 |
| `--obf-preset <low\|medium\|high>` | 混淆强度 | low |

## 示例

```bash
# 全默认（推荐）
node protect.js game.html

# 只加密，不混淆不保护跳转
node protect.js game.html --no-obf --no-redirect

# 中等混淆 + 50% 跳转替换
node protect.js game.html --obf-preset medium --redirect-rate 50

# 手动指定保护链接
node protect.js game.html --redirect-url "https://play.google.com/store/apps/details?id=com.my.app"

# 关闭 VMP（加快处理速度，但解密器容易被 AI 分析）
node protect.js game.html --no-vmp
```

## 建议配置

| 场景 | 命令 |
|---|---|
| **日常投放** | `node protect.js game.html` |
| 快速测试 | `node protect.js game.html --no-vmp --no-obf` |
| 高价值素材 | `node protect.js game.html --obf-preset medium` |
| 最强保护 | `node protect.js game.html --obf-preset high --redirect-rate 100` |

## 处理流程

```
步骤 1: 加密 Cocos2d 资源
  - 解压 ZIP → 拆解 __res → 逐文件 deflate + XXTEA 加密
  - 文件名 hash（隐藏目录结构和文件类型）
  - 插入蜜罐 trap 文件（遍历 dump → OOM 崩溃）
  - 生成 Proxy 解密器 → VMP high 强混淆（可选）
  - 解密器交叉合并进游戏 super_load 脚本块（物理不可分离）
  - 注入 pako_inflate（独立 vendor 块）

步骤 2: 链接跳转保护
  - 自动从 HTML + ZIP 中提取商店链接
  - 拦截 window.open / location.href / mraid.open 等全部跳转 API
  - 非预设链接按概率替换为保护链接

步骤 3: JS 全混淆
  - 遍历所有 <script> 逐个混淆
  - 自动跳过 pako vendor 库
  - 合并块（解密器 + 游戏代码）统一混淆 → 变量名共享，深度纠缠
```

## 交叉合并说明

解密器不是独立的 `<script>` 标签，而是**合并进包含 super_load 的游戏脚本块**：

```
<script>
  [解密器 VMP 代码 ~200KB]  ← 先 high 预设 VMP
  ;
  [游戏 super_load/boot 代码 + ZIP 数据 ~2-4MB]
</script>
```

步骤 3 的 JS 混淆对这个合并块做统一处理：
- 解密器变量和游戏变量共享命名空间
- 删除解密器部分 → 游戏变量引用断裂 → 崩溃
- 攻击者无法通过删 `<script>` 标签移除解密器

## 防护层级总览

| 层级 | 措施 | 效果 |
|---|---|---|
| 资源加密 | XXTEA + deflate + 每文件独立密钥 | 资源内容不可读 |
| 文件名混淆 | 64-bit hash + 目录铺平 | 无法推断文件类型和结构 |
| __res 拆解 | JSON 内联资源拆成独立加密文件 | 消除明文资源入口 |
| 蜜罐 trap | 3-5 个假文件，访问即 OOM | 遍历 dump 崩溃 |
| hash 直访拦截 | 用 hash key 访问返回密文不解密 | 攻击者从 keys 拿不到明文 |
| 栈帧白名单 | 非 super_eval/getRes 调用返回密文 | 控制台读取无效 |
| 解密器 VMP | high 预设（rc4 + 控制流 + 死代码 + 反调试） | AI 难以分析解密逻辑 |
| 交叉合并 | 解密器 + 游戏代码同一 script 块 | 不可按标签分离 |
| 统一混淆 | low/medium/high 统一处理合并块 | 变量共享命名，深度纠缠 |
| 跳转保护 | 拦截所有跳转 API + 概率替换 | 防止篡改商店链接 |
| 字符串 XOR | 所有关键字符串 charCode XOR 编码 | 源码搜索不到关键词 |
| 密钥 XOR | 全局密钥 XOR 编码嵌入 | 密钥不以明文出现 |

## 混淆强度说明

| 预设 | 内容 | 体积影响 | 速度影响 |
|---|---|---|---|
| **low**（默认） | 变量重命名 + 压缩 | 小 | 快 |
| **medium** | + 字符串 RC4 + 反调试 + 控制流平坦化 | 中 | 中 |
| **high** | + 死代码注入 + Unicode 转义 + 全部开启 | 大 | 慢 |

> 混淆程度越高，游戏启动越慢、体积越大。日常用 low 就够了。
> VMP 只影响解密器（~7KB 代码 → VMP 后 ~200KB），不影响游戏本身体积和速度，强烈建议保持开启。

## 文件说明

```
protect/
├── protect.js                  主程序
├── jszip.min.js                ZIP 处理
├── pako_inflate.min.js         解压库（注入到输出 HTML）
└── javascript-obfuscator.js    JS 混淆引擎（魔改版，含域名锁定 patch）
```

所有依赖已打包在目录内，不需要 node_modules。
