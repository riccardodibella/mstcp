import json
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib
matplotlib.use('TkAgg')  # Ensures GUI backend

FILENAME = "log_client.json"

full_logs = []
with open(FILENAME) as f:
    full_log = json.load(f)

start_ts_us = full_log[0].get("timestamp_us")
print(f"start_ts_us {start_ts_us}")

cng = [row for row in full_log if row.get('type') == 'CNG']

df = pd.DataFrame(cng)

# State label and color mapping
state_labels = {
    0: "Slow Start",
    1: "Congestion Avoidance",
    2: "Fast Recovery"
}
color_map = {
    0: 'red',
    1: 'blue',
    2: 'green'
}




colors = df['state'].map(color_map)

cng_ts = (df['timestamp_us'] - start_ts_us)/1E6
plt.figure()
plt.scatter(cng_ts, df['cgwin'], c=colors, marker='o')
plt.xlabel('Timestamp [s]')
plt.ylabel('cgwin')
plt.title("Congestion Window")

# Legend with string labels
legend_patches = [
    mpatches.Patch(color=color_map[state], label=state_labels[state])
    for state in sorted(state_labels)
]
plt.legend(handles=legend_patches, title="TCP State", loc='best')

plt.tight_layout()
plt.show()