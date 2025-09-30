import matplotlib.pyplot as plt
import numpy as np

baseline_values = [24397, 7051, 4455]
delayed_values  = [125779, 24692, 5315]

group_positions = np.arange(3)
width = 0.4

plt.figure(figsize=(7, 6))

bars_baseline = plt.bar(group_positions - width/2, baseline_values, width, label='Baseline')
bars_delayed  = plt.bar(group_positions + width/2, delayed_values, width, label='Delayed')

plt.bar_label(bars_baseline)
plt.bar_label(bars_delayed)

plt.xticks(group_positions, [
    'TCP\n1 connection',
    'TCP\n6 connections',
    'MS-TCP\n32 streams, 1 channel'
])

plt.ylabel("Total time [ms]")

plt.title("Total Completion Time for 1000 Delayed Requests vs Baseline")
plt.legend()

plt.tight_layout()
plt.show()
