import matplotlib.pyplot as plt
import numpy as np

# Sample data - replace with your actual data
plot_titles = ["Page Load Time Comparison (1024 500B Images)", "Page Load Time Comparison (64 500B Images)", "Page Load Time Comparison (64 10KB Images)"]

# Sample data array [3 plots][4 columns]
data = [
    [5880, 752, 5107, 1069],   # First histogram data
    [683, 74, 433, 323],  # Second histogram data
    [769, 419, 461, 550]      # Third histogram data
]

# Column labels (split into 2 lines)
columns = [
    "HTTP/1.1 over\nraw socket TCP\n(6 connections)",
    "HTTP/1.1 over\nraw socket MS-TCP\n(32 streams)", 
    "HTTP/1.1 over OS TCP\n(6 connections)",
    "HTTP/3 over QUIC"
]

# Colors for each column (from default palette)
colors = plt.cm.tab10.colors[:4]

# Generate each histogram as separate plot
for i in range(3):
    plt.figure(figsize=(10, 6))
    x_pos = np.arange(len(columns))
    
    bars = plt.bar(x_pos, data[i], color=colors)
    plt.title(plot_titles[i])
    plt.ylabel('Total download time [ms]')
    plt.xticks(x_pos, columns, ha='center')
    
    # Add value labels on bars
    for j, bar in enumerate(bars):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{data[i][j]} ms', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.show()