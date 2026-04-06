@echo off
REM HTTP/2 隧道服务端启动脚本
REM 默认从 server_config.json 读取配置，也可通过命令行参数覆盖
REM 用法: run.bat [可选: 配置文件路径]

if "%~1"=="" (
    .\server.exe -config server_config.json
) else (
    .\server.exe -config %~1
)