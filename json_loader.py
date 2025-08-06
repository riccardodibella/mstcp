import json
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib
matplotlib.use('TkAgg')  # Ensures GUI backend

#FILENAME = "log_client.json"
FILENAME = "log_server.json"


full_log = []
with open(FILENAME) as f:
    full_log = json.load(f)

start_ts_us = full_log[0].get("timestamp_us")

cng = [row for row in full_log if row.get('type') == 'CNG']
cng_df = pd.DataFrame(cng)
cng_ts = (cng_df['timestamp_us'] - start_ts_us)/1E6

scb = [row for row in full_log if row.get('type') == 'SCB']
scb = [row for row in scb if row.get('sid') == 0]
scb_df = pd.DataFrame(scb)
scb_ts = (scb_df['timestamp_us'] - start_ts_us)/1E6

rtt = [row for row in full_log if row.get('type') == 'RTT']
rtt_df = pd.DataFrame(rtt)
rtt_ts = (rtt_df['timestamp_us'] - start_ts_us)/1E6

rto = [row for row in full_log if row.get('type') == 'RTO']
rto_df = pd.DataFrame(rto)
rto_ts = (rto_df['timestamp_us'] - start_ts_us)/1E6

# Filter for outgoing packets to get their sequence numbers
pkt_out = [row for row in full_log if row.get('type') == 'PKT' and row.get('direction') == 'OUT']
pkt_out_df = pd.DataFrame(pkt_out)
pkt_out_ts = (pkt_out_df['timestamp_us'] - start_ts_us) / 1E6
# Filter for incoming packets to get their acknowledgement numbers
pkt_in = [row for row in full_log if row.get('type') == 'PKT' and row.get('direction') == 'IN']
pkt_in_df = pd.DataFrame(pkt_in)
pkt_in_ts = (pkt_in_df['timestamp_us'] - start_ts_us) / 1E6

# State label and color mapping
state_labels_cng = {
    0: "Slow Start",
    1: "Congestion Avoidance",
    2: "Fast Recovery"
}
state_labels_scb = {
    0: "Available",
    1: "Flow control",
    2: "Congestion Control"
}
color_map = {
    0: 'red',
    1: 'blue',
    2: 'green'
}





plt.figure()
colors_cng = cng_df['state'].map(color_map)
plt.scatter(cng_ts, cng_df['cgwin'], c=colors_cng, marker='x', s = 5)
plt.xlabel('Timestamp [s]')
plt.ylabel('cgwin')
plt.title("Congestion Window")
# Legend with string labels
legend_patches_cng = [
    mpatches.Patch(color=color_map[state], label=state_labels_cng[state])
    for state in sorted(state_labels_cng)
]
plt.legend(handles=legend_patches_cng, title="TCP State", loc='best')
plt.tight_layout()






# https://claude.ai/share/21b3c3f8-26fa-402d-87ff-dde21b6489c7
plt.figure()
# Plot the three baseline values with more distinct styling
plt.scatter(scb_ts, scb_df['av'], c='orange', marker='o', s=2, alpha=0.7, label='Available')
plt.scatter(scb_ts, scb_df['flow'], c='purple', marker='s', s=2, alpha=0.7, label='Flow Control')
plt.scatter(scb_ts, scb_df['cng'], c='cyan', marker='^', s=2, alpha=0.7, label='Congestion Control')
# Plot the minimum (limiting factor) with colored markers based on cause
colors_scb = scb_df['cause'].map(color_map)
plt.scatter(scb_ts, scb_df['min'], c=colors_scb, marker='+', s=3, label='Limiting Factor')
plt.xlabel('Timestamp [s]')
plt.ylabel('Bytes')
plt.title("Scheduler bytes")
# Create combined legend
# First, the baseline lines
baseline_handles = [
    plt.scatter([], [], c='orange', marker='o', s=20, alpha=0.7, label='Available'),
    plt.scatter([], [], c='purple', marker='s', s=20, alpha=0.7, label='Flow Control'),
    plt.scatter([], [], c='cyan', marker='^', s=20, alpha=0.7, label='Congestion Control')
]
# Then, the limiting factor legend
legend_patches_scb = [
    mpatches.Patch(color=color_map[state], label=f"Limiting: {state_labels_scb[state]}")
    for state in sorted(state_labels_scb)
]
# Combine all legend elements
all_handles = [h for h in baseline_handles] + legend_patches_scb
plt.legend(handles=all_handles, loc='best')
plt.tight_layout()






plt.figure()
plt.scatter(rtt_ts, rtt_df['value_s'], marker='x', label='RTT', s = 5)
plt.scatter(rto_ts, rto_df['value_s'], marker='+', label='RTO', s = 5)
plt.xlabel('Timestamp [s]')
plt.ylabel('Value [s]')
plt.legend(loc='best')
plt.title("RTT / RTO")
plt.tight_layout()

plt.figure()
plt.scatter(pkt_out_ts, pkt_out_df['sequence_number'], marker='x', s=5, label='Sequence Number (OUT)')
plt.scatter(pkt_in_ts, pkt_in_df['ack_number'], marker='+', s=5, label='Ack Number (IN)')
plt.xlabel('Timestamp [s]')
plt.ylabel('seq/ack')
plt.title('OUT seq / IN ack')
plt.legend(loc='best')
plt.grid(True)
plt.tight_layout()

plt.figure()
plt.scatter(pkt_in_ts, pkt_in_df['sequence_number'], marker='x', s=5, label='Sequence Number (IN)')
plt.scatter(pkt_out_ts, pkt_out_df['ack_number'], marker='+', s=5, label='Ack Number (OUT)')
plt.xlabel('Timestamp [s]')
plt.ylabel('seq/ack')
plt.title('IN seq / OUT ack')
plt.legend(loc='best')
plt.grid(True)
plt.tight_layout()











pkt_out_streams_df = pd.DataFrame([
    row for row in full_log if row.get('type') == 'PKT' and row.get('direction') == 'OUT'
])
pkt_out_streams_df.dropna(subset=['sid', 'ssn'], inplace=True)
pkt_out_streams_df['sid'] = pkt_out_streams_df['sid'].astype(int)
unique_sids = sorted(pkt_out_streams_df['sid'].unique())

plt.figure()
max_sid_val = max(unique_sids)
colors = plt.get_cmap('nipy_spectral', max_sid_val + 1)
for sid in unique_sids:
    stream_df = pkt_out_streams_df[pkt_out_streams_df['sid'] == sid]
    stream_ts = (stream_df['timestamp_us'] - start_ts_us) / 1E6
    plt.scatter( stream_ts, stream_df['ssn'], label=f'SID {sid}', color=colors(sid), s=5, marker="x")
plt.xlabel('Timestamp [s]')
plt.ylabel('SSN')
plt.title('SSN Progression per Stream (Direction: OUT)')
plt.grid(True)
plt.legend(title="SID", loc='best', ncol=2 if len(unique_sids) > 10 else 1)
plt.tight_layout()




pkt_in_streams_df = pd.DataFrame([
    row for row in full_log if row.get('type') == 'PKT' and row.get('direction') == 'IN'
])
pkt_in_streams_df.dropna(subset=['sid', 'ssn'], inplace=True)
pkt_in_streams_df['sid'] = pkt_in_streams_df['sid'].astype(int)
unique_sids_in = sorted(pkt_in_streams_df['sid'].unique())

plt.figure()
max_sid_val_in = max(unique_sids_in)
colors_in = plt.get_cmap('nipy_spectral', max_sid_val_in + 1)
for sid in unique_sids_in:
    stream_df = pkt_in_streams_df[pkt_in_streams_df['sid'] == sid]
    stream_ts = (stream_df['timestamp_us'] - start_ts_us) / 1E6
    plt.scatter(stream_ts, stream_df['ssn'], label=f'SID {sid}', color=colors_in(sid), s=5, marker="+")
plt.xlabel('Timestamp [s]')
plt.ylabel('SSN')
plt.title('SSN Progression per Stream (Direction: IN)')
plt.grid(True)
plt.legend(title="SID", loc='best', ncol=2 if len(unique_sids_in) > 10 else 1)
plt.tight_layout()



plt.show()