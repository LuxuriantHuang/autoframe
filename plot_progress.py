import os
import time

import matplotlib.pyplot as plt
import pandas as pd

from config import PLOT_PATH

# 文件名
CSV_FILE = PLOT_PATH
# 绘图间隔（秒）
INTERVAL = 30  # 5分钟


def plot_graph(df):
    plt.figure(figsize=(12, 6))
    plt.plot(df['# relative_time'], df[' edges_found'], marker='o', linestyle='-')
    plt.xlabel('Relative Time (s)')
    plt.ylabel('Edges Found')
    plt.title('Fuzzer Progress: Relative Time vs Edges Found')
    plt.grid(True)
    plt.tight_layout()
    plt.show()
    print(f"Graph displayed successfully.")


def main():
    print("Starting monitoring and plotting...")
    while True:
        if os.path.exists(CSV_FILE):
            try:
                df = pd.read_csv(CSV_FILE)
                if '# relative_time' in df.columns and ' edges_found' in df.columns:
                    plot_graph(df)
                else:
                    print(f"Columns not found. Columns present: {df.columns.tolist()}")
            except Exception as e:
                print(f"Error reading or plotting: {e}")
        else:
            print(f"File {CSV_FILE} not found.")

        print(f"Sleeping for {INTERVAL} seconds...")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
