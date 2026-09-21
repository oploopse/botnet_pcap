@echo off
chcp 65001 >nul
title [HUCE] DUNG LAB MO PHONG BOTNET NIDS
cls
echo =======================================================================
echo    DỪNG TOÀN BỘ CÁC MÁY ẢO DOCKER LAB BOTNET
echo =======================================================================
echo.

cd /d "%~dp0simulation_lab"
echo Đang tắt 3 máy ảo container...
docker compose down

echo.
echo =======================================================================
echo    ĐÃ DỪNG VÀ GIẢI PHÓNG TÀI NGUYÊN HỆ THỐNG XONG!
echo =======================================================================
echo.
pause
