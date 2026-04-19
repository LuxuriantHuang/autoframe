#!/bin/bash
set -euo pipefail

# 从 benchmarks/*/build.sh 动态获取 AFL 命令
# 或者通过环境变量 AFL_CMD 传入

if [ -z "${AFL_CMD:-}" ]; then
    echo "[INFO] AFL_CMD not set, looking for build.sh in benchmarks..."
    BUILD_SCRIPT=$(find /app/benchmarks -name "build.sh" -type f 2>/dev/null | head -1)
    if [ -n "$BUILD_SCRIPT" ]; then
        echo "[INFO] Found build.sh: $BUILD_SCRIPT"
        # 假设 build.sh 里有 AFL 相关命令，这里需要根据实际情况调整
        # 临时跳过 AFL，只跑 Python
        echo "[WARN] No AFL_CMD specified, running Python only"
    fi
fi

# 后台启动 AFL（输出到文件，不显示控制台）
if [ -n "${AFL_CMD:-}" ]; then
    echo "[INFO] Starting AFL in background..."
    mkdir -p /tmp/afl-output
    eval "$AFL_CMD" > /tmp/afl.log 2>&1 &
    AFL_PID=$!
    echo "[INFO] AFL PID: $AFL_PID"
fi

# 启动 Python main.py（前台，输出到控制台）
echo "[INFO] Starting Python main.py..."
cd /app
python main.py
PY_EXIT_CODE=$?

# Python 退出，清理 AFL 并退出
if [ -n "${AFL_PID:-}" ]; then
    echo "[INFO] Python exited with code $PY_EXIT_CODE, stopping AFL (PID: $AFL_PID)..."
    kill $AFL_PID 2>/dev/null || true
    wait $AFL_PID 2>/dev/null || true
fi

exit $PY_EXIT_CODE
