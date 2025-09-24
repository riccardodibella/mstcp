import matplotlib.pyplot as plt

# Data for the histogram
x_values = list(range(10))  # 0 to 9 (included)
y_values = [111, 13, 114, 112, 111, 107, 109, 110, 109, 104]

# Create the histogram
plt.figure(figsize=(10, 6))
bars = plt.bar(x_values, y_values)

# Add value labels on top of each bar
plt.bar_label(bars)

# Add horizontal dashed line at height 100
plt.axhline(y=100, color='C1', linestyle='--', linewidth=2, label='average')

# Customize the plot
plt.xlabel('Stream ID')
plt.ylabel('Number of requests')
plt.title('Distribution of Requests With Stream-Selective Segment Dropping')
plt.xticks(x_values)
plt.grid(True, alpha=0.3)
plt.legend()

# Show the plot
plt.tight_layout()
plt.show()