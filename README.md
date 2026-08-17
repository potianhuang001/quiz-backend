# 激活码后端 · 一键部署包

这是「激活码 = 给登录账号的一次性激活」的后端服务（零依赖 Node，仅用内置 crypto + 内置 tweetnacl 验签）。

- 买家登录（邮箱 / 微信）→ 粘贴激活码 → 码绑死他的账号
- 别人用同码登自己号 → 被拒（想白嫖只能把账号交出去）
- 资料也按账号锁定，仅已激活账号可见

## 文件说明
- `server.js`：服务主程序，监听 `PORT`（Render 自动注入），提供 `/auth/...`、`/redeem`、`/materials`、`/me` 等接口
- `nacl.js`：Ed25519 验签（与前端同源公钥）
- `materials.json`：资料条目（部署后可通过 `/admin/materials` 用管理员码增改）
- `accounts.json` / `ledger.json` / `sessions.json` / `revoked.json`：运行期数据，初始化为空
- `render.yaml` / `Procfile` / `package.json`：部署配置（免费层）

## 部署到 Render（免费，不用信用卡）
1. 打开 https://render.com  →  Sign Up → 选 **GitHub** 登录（会顺带建好 GitHub 账号）。
2. 在 GitHub 新建一个仓库（随便起名，如 `quiz-backend`），**公开(Public)**。
3. 把这个文件夹里**所有文件**上传到该仓库（仓库页 → Add file → Upload files → 把文件夹拖进去 → Commit）。
4. 回到 Render → New → **Blueprint** → 连接刚才的仓库 → Render 自动读取 `render.yaml` → 点 **Deploy**。
5. 等 1~2 分钟，状态变绿后，点服务名进入 → 复制 **URL**（形如 `https://quiz-redemption.onrender.com`）。
6. 把这条 URL 发给帮你部署的人（或填进前端的 `BACKEND_URL`）。

> 免费层说明：长时间无人访问会自动休眠，首次访问需等 ~30 秒冷启动，正常。
> 微信登录需在小程序后台配置合法域名；如暂时不用微信登录，可忽略 `WX_APPID/WX_SECRET`。

## 本地自测（可选）
```bash
node server.js            # 默认 3000 端口
curl http://localhost:3000/health
```
