# Zr4NF 的个人博客

为 GitHub Pages 准备的 Jekyll 博客。深色界面、Markdown 文章、归档、关于页面与移动端布局，无外部字体、统计脚本或前端构建依赖。

## 首次发布

1. 在 GitHub 个人账号 `Zr4NF` 下创建公开仓库 `Zr4NF.github.io`。创建前检查是否已有同名仓库，避免覆盖既有网站。
2. 将此目录内容放入仓库的 `main` 分支根目录，保留 `_layouts`、`_posts`、`assets` 与 `_config.yml` 等目录和文件。
3. 仓库 Settings → Pages，Source 选择 Deploy from a branch，Branch 选择 main，目录选择 / (root)，保存。
4. 等待 Pages 构建完成。预期地址：https://zr4nf.github.io 。地址实际可用情况以 Pages 部署状态为准。

## 写文章

在 `_posts/` 新建 `YYYY-MM-DD-slug.md`：

```markdown
---
title: 文章标题
description: 用一句话介绍本文。
tags: [合约安全, EVM]
---

## 问题

在这里写正文。
```

文章日期按北京时间。提交到 main 后由 GitHub Pages 自动更新。修改 `about.md` 更新个人介绍，修改 `_config.yml` 更新站点名称和简介。初始随笔可以删除或替换。

## 本地预览

安装 Ruby / Bundler 后执行 `bundle install`，再运行 `bundle exec jekyll serve`，打开终端给出的本地地址。

当前交付包含源码静态检查；尚未在本地运行 Jekyll 构建。最终构建以 GitHub Pages 的部署日志为准。
