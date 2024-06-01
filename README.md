# GoBinderFile

## 简介

一款使用 Go Lang 语言编写的文件捆绑器实现，生成exe后自动释放并运行正常文件以及木马程序。

**免责声明：** 本项目仅用于学习研究使用，禁止任何人或单位非法使用，造成一切后果均由自己承担！



## 参数说明

```go
  -h 查看帮助信息
  -f string
        [ExeFilePath] 请输入要捆绑的木马文件！
  -t string
        [TargetFilePath] 请输入要捆绑的目标文件！
```



## 注意事项

1. `go.mod` 以及 `go.sum` 不要删除！

2. 使用前 先 `go mod tidy` 下载本项目环境依赖！
