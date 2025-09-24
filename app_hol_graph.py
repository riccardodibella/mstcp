import matplotlib.pyplot as plt
import numpy as np

values = [28141, 117101, 27781, 127468, 8241, 24071, 5955, 23693, 4506, 5648]

# Extract data for plotting
baseline_values = [values[0], values[2], values[4], values[6], values[8]]  # All baseline values
delayed_values = [values[1], values[3], values[5], values[7], values[9]]   # All delayed values

# Set up the plot
fig, ax = plt.subplots(figsize=(12, 6))

# Define positions for bars with gaps after positions 1 and 3
group_positions = [0, 1, 2.5, 3.5, 5]
width = 0.35

# Create bars
bars_baseline = ax.bar(np.array(group_positions) - width/2, baseline_values, 
                      width, label='Baseline')
bars_delayed = ax.bar(np.array(group_positions) + width/2, delayed_values, 
                     width, label='Delayed')

# Add value labels on bars
plt.bar_label(bars_baseline)
plt.bar_label(bars_delayed)

# Add vertical separators
ax.axvline(x=1.75, color='lightgray', linestyle='-', alpha=0.7, linewidth=1)
ax.axvline(x=4.25, color='lightgray', linestyle='-', alpha=0.7, linewidth=1)

# Set x-axis labels
ax.set_xticks(group_positions)
ax.set_xticklabels(['TCP', 'MS-TCP', 'TCP', 'MS-TCP', 'MS-TCP'])

# Add configuration type labels below
fig.text(0.21, 0.05, '1 connection/stream', ha='center', fontsize=10)
fig.text(0.59, 0.05, '6 connections/stream', ha='center', fontsize=10)
fig.text(0.89, 0.05, '32 streams', ha='center', fontsize=10)

# Adjust layout with extra space for the title
plt.tight_layout()
plt.subplots_adjust(top=0.94, bottom=0.12)  # Increase top margin

plt.title("Completion Times for 1000 Delayed Requests vs Baseline", fontsize=14)

ax.legend()
plt.show()
