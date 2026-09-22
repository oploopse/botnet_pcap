@echo off
chcp 65001 >nul
title [HUCE] KHOI CHAY LAB MO PHONG BOTNET NIDS
cls
echo =======================================================================
echo    TRƯỜNG ĐẠI HỌC XÂY DỰNG HÀ NỘI - KHOA CÔNG NGHỆ THÔNG TIN
echo    HỆ THỐNG GIÁM SÁT & PHÁT HIỆN BOTNET THỜI GIAN THỰC (NIDS)
echo =======================================================================
echo.

echo [1/3] Đang kiểm tra Docker Desktop...
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [CANH BAO] Docker Desktop chua khoi chay!
    echo Dang khoi dong Docker Desktop...
    start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    echo Vui long doi Docker san sang trong 15-20 giay...
    timeout /t 15 >nul
)

echo [2/3] Đang khởi chạy 6 máy ảo Docker (c2-server P0, ids-gateway, victim-f0, victim-f1-1, victim-f1-2, victim-f1-3)...
cd /d "%~dp0simulation_lab"
docker compose up -d

echo.
echo [3/3] Đang mở Giao diện Điều khiển (Dashboard) trên trình duyệt...
timeout /t 3 >nul
start http://localhost:8501

echo.
echo =======================================================================
echo    LAB ĐÃ SẴN SÀNG! (READY 100%%)
echo    - Giao diện Dashboard: http://localhost:8501
echo    - Để dừng lab khi dùng xong, hãy chạy file: DUNG_LAB_SIMULATION.bat
echo =======================================================================
echo.
pause
