file_name = "serial_test_200KB_sequence.csv"

import pandas as pd
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import filedialog
import numpy as np

import matplotlib
matplotlib.use('TkAgg')  # Ensures GUI backend
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL) # https://stackoverflow.com/a/75864329


def identify_sequences(group):
    """
    Identify complete sequences in the data based on consecutive request values.
    Returns a list of sequence identifiers for each row.
    """
    # Sort by requests to identify sequences
    group_sorted = group.sort_values('requests').reset_index(drop=True)
    
    # Get unique request values
    unique_requests = sorted(group['requests'].unique())
    
    # Group rows by their index to identify sequences
    # Assuming sequences are consecutive rows in the original data
    sequences = []
    current_sequence = 0
    
    # Simple approach: assume each row belongs to a different sequence
    # unless we can identify patterns
    
    # More sophisticated approach: group by some sequence identifier
    # For now, let's assume we need to identify sequences based on row groupings
    
    # If there's a natural grouping (like multiple measurements per request count)
    # we can identify sequences by looking at how many times each request value appears
    request_counts = group['requests'].value_counts().sort_index()
    
    sequence_id = 0
    for _, row in group.iterrows():
        sequences.append(sequence_id)
        # Simple increment - you might need more sophisticated logic here
        # depending on how your sequences are structured
        if len(sequences) % len(unique_requests) == 0:
            sequence_id += 1
    
    return sequences


def get_best_sequence_data(group):
    """
    Find the sequence with the best performance (lowest time for target requests)
    and return all points from that sequence.
    
    Assumes sequences are consecutive blocks in the data where each block
    contains measurements for all request values (1, 2, 3, ..., max_requests).
    """
    SKIP_FIRST_N_SEQUENCES = 0  # Change this number as needed
    # Toggle: True for minimum first value, False for minimum last value
    USE_MINIMUM_FIRST_VALUE = True  # Change this to False to use last value
    
    if len(group) == 0:
        return pd.DataFrame()
    
    # Get unique request values and sort them
    unique_requests = sorted(group['requests'].unique())
    num_request_values = len(unique_requests)
    
    # Determine target requests based on toggle
    if USE_MINIMUM_FIRST_VALUE:
        target_requests = min(unique_requests)
        comparison_label = "first"
    else:
        target_requests = max(unique_requests)
        comparison_label = "last"
    
    # Reset index to work with consecutive rows
    group_reset = group.reset_index(drop=True)
    
    # Identify sequences by looking for consecutive blocks
    # Each sequence should contain all request values in order
    sequences = []
    current_sequence = []
    expected_request = unique_requests[0]  # Start with the first request value
    
    for idx, row in group_reset.iterrows():
        if row['requests'] == expected_request:
            # This is the expected next request in the sequence
            current_sequence.append(idx)
            
            # Move to next expected request
            current_req_idx = unique_requests.index(expected_request)
            if current_req_idx + 1 < len(unique_requests):
                expected_request = unique_requests[current_req_idx + 1]
            else:
                # Completed a full sequence
                sequences.append(current_sequence)
                current_sequence = []
                expected_request = unique_requests[0]  # Reset for next sequence
        else:
            # Unexpected request value - this might indicate a new sequence starting
            # or corrupted data. Let's try to restart from this point
            if row['requests'] == unique_requests[0]:
                # This looks like the start of a new sequence
                if current_sequence:
                    # Save incomplete sequence if it has some data
                    sequences.append(current_sequence)
                current_sequence = [idx]
                expected_request = unique_requests[1] if len(unique_requests) > 1 else unique_requests[0]
            else:
                # Skip this row as it doesn't fit the expected pattern
                continue
    
    # Don't forget the last sequence if it wasn't completed
    if current_sequence:
        sequences.append(current_sequence)
    
    print(f"  Found {len(sequences)} sequences with lengths: {[len(seq) for seq in sequences]}")
    
    # Now find the best sequence (one with lowest time at target requests)
    # Only consider complete sequences that have all request values
    best_sequence_data = None
    best_target_time = float('inf')
    best_sequence_id = None
    
    for seq_id, sequence_indices in enumerate(sequences):
        # Skip the first N sequences
        if seq_id < SKIP_FIRST_N_SEQUENCES:
            print(f"    Sequence {seq_id}: skipped (first {SKIP_FIRST_N_SEQUENCES} sequences ignored)")
            continue

        # Get the data for this sequence
        sequence_data = group_reset.iloc[sequence_indices]
        
        # Check if this sequence is complete (has all request values)
        sequence_requests = set(sequence_data['requests'].unique())
        expected_requests = set(unique_requests)
        
        if sequence_requests == expected_requests:
            # Complete sequence - get the target time (first or last)
            target_req_rows = sequence_data[sequence_data['requests'] == target_requests]
            if not target_req_rows.empty:
                target_time = target_req_rows['time_ms'].iloc[0]
                print(f"    Sequence {seq_id}: complete, {comparison_label} time = {target_time:.2f}ms")
                
                if target_time < best_target_time:
                    best_target_time = target_time
                    best_sequence_data = sequence_data
                    best_sequence_id = seq_id
        else:
            missing_requests = expected_requests - sequence_requests
            print(f"    Sequence {seq_id}: incomplete (missing requests: {sorted(missing_requests)})")
    
    # If no complete sequence found, fall back to original method
    if best_sequence_data is None or best_sequence_data.empty:
        print(f"  Warning: No complete sequences found, falling back to minimum selection per request count")
        exit()
        
        if result_data:
            best_sequence_data = pd.DataFrame(result_data)
    else:
        print(f"  Selected sequence {best_sequence_id} with {comparison_label} time: {best_target_time:.2f}ms")
    
    return best_sequence_data


def create_dynamic_performance_plot():
    """
    Allows user to select a CSV, then dynamically plots performance data
    adapting to the unique values in 'payload_size' and 'requests' columns.
    Selects the sequence that ends earliest (lowest time for maximum requests).
    """
    # 1. Let the user choose a CSV file
    root = tk.Tk()
    root.withdraw()  # Hide the main tkinter window


    # Load the selected file as a pandas DataFrame
    try:
        df = pd.read_csv(file_name, delimiter=';')
        print("File loaded successfully. Here's a preview of the data:")
        print(df.head())
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        return

    # 2. Process the data
    # Check for essential columns
    required_cols = {'MS_ENABLED', 'payload_size', 'requests', 'time_ms'}
    if not required_cols.issubset(df.columns):
        print(f"Error: The CSV must contain the following columns: {required_cols}")
        return

    # Check if time_hs_ms column exists
    has_time_hs_ms = 'time_hs_ms' in df.columns
    if not has_time_hs_ms:
        print("Warning: 'time_hs_ms' column not found. Only time_ms will be plotted.")

    if df.empty:
        print("\nThe CSV file is empty. Cannot generate a plot.")
        return

    # Group and get best sequence data
    print("\n--- Processing sequences for each configuration ---")
    filtered_groups = []
    
    for (ms_enabled, payload_size), group in df.groupby(['MS_ENABLED', 'payload_size']):
        print(f"Processing MS_ENABLED={ms_enabled}, payload_size={payload_size}")
        best_sequence = get_best_sequence_data(group)
        
        if not best_sequence.empty:
            # Add the grouping columns back
            best_sequence = best_sequence.copy()
            best_sequence['MS_ENABLED'] = ms_enabled
            best_sequence['payload_size'] = payload_size
            filtered_groups.append(best_sequence)
    
    if not filtered_groups:
        print("No valid sequences found!")
        return
    
    # Combine all best sequences
    final_data = pd.concat(filtered_groups, ignore_index=True)
    
    print("\n--- Selected Sequence Data Summary ---")
    print(final_data[['MS_ENABLED', 'payload_size', 'requests', 'time_ms']])
    print("--------------------\n")

    # 3. Create all plots
    def create_plot(plot_type="combined"):
        """Create a single plot of specified type"""
        fig, ax = plt.subplots(figsize=(9, 6))

        # --- DYNAMIC STYLING ---
        # Define colors for the MS_ENABLED families
        colors = {0: 'royalblue', 1: 'darkorange'}
        
        # Define a list of line styles to cycle through for payload sizes
        line_styles_list = [
            'solid',        # same as '-'
            'dashed',       # same as '--'
            'dotted',       # same as ':'
            'dashdot',      # same as '-.'
            (0, (1, 1)),    # densely dotted
            (0, (5, 5)),    # loosely dashed
            (0, (3, 5, 1, 5)),  # dash-dot
            (0, (5, 10)),   # long dash
            (0, (3, 1, 1, 1)),  # dash-dot-dotted
            (0, (2, 4, 6, 4))   # mixed long/short dashes
        ]
        
        # Discover unique payload sizes from the data and assign a style to each
        unique_payloads = sorted(final_data['payload_size'].unique())
        payload_to_linestyle = {
            payload: line_styles_list[i % len(line_styles_list)] 
            for i, payload in enumerate(unique_payloads)
        }

        # Keep track of which labels have been added to avoid duplicates
        added_labels = set()

        # Iterate through each MS_ENABLED family
        for ms_enabled_value, family_group in final_data.groupby('MS_ENABLED'):
            # Iterate through each payload_size within the family
            for payload_value, line_group in family_group.groupby('payload_size'):
                line_group = line_group.sort_values('requests')
                
                # Create base label
                base_label = "MS-TCP" if ms_enabled_value else "TCP"
                
                # Plot based on type
                if plot_type in ["combined", "time_ms"]:
                    # Plot time_ms (solid lines with circles)
                    if plot_type == "combined":
                        time_ms_label = f"{base_label} (Handshake + App Traffic)" if f"{base_label} (Handshake + App Traffic)" not in added_labels else None
                    else:
                        time_ms_label = f"{base_label} (Handshake + App Traffic)" if base_label not in added_labels else None
                    if time_ms_label:
                        added_labels.add(base_label)
                    
                    linestyle = 'solid' if plot_type == "time_ms" else payload_to_linestyle[payload_value]
                    ax.plot(line_group['requests'], line_group['time_ms'],
                            label=time_ms_label,
                            color=colors.get(ms_enabled_value, 'gray'),
                            linestyle=linestyle,
                            marker='o',
                            markersize=5)
                
                if plot_type in ["combined", "time_hs_ms"] and has_time_hs_ms and 'time_hs_ms' in line_group.columns:
                    # Plot time_hs_ms (dashed lines with squares for combined, solid for separate)
                    valid_hs_data = line_group.dropna(subset=['time_hs_ms'])
                    if not valid_hs_data.empty:
                        hs_label_suffix = " (Handshake)" if plot_type == "combined" else ""
                        hs_label = f"{base_label}{hs_label_suffix}" if f"{base_label}{hs_label_suffix}" not in added_labels else None
                        if hs_label:
                            added_labels.add(f"{base_label}{hs_label_suffix}")
                        
                        linestyle = 'dashed' if plot_type == "combined" else payload_to_linestyle[payload_value]
                        marker = 's' if plot_type == "combined" else 'o'
                        ax.plot(valid_hs_data['requests'], valid_hs_data['time_hs_ms'],
                                label=hs_label,
                                color=colors.get(ms_enabled_value, 'gray'),
                                linestyle=linestyle,
                                marker=marker,
                                markersize=4,
                                alpha=0.7)
                
                if plot_type in ["combined", "difference"] and has_time_hs_ms and 'time_hs_ms' in line_group.columns:
                    # Plot time difference (dotted lines with triangles for combined, solid for separate)
                    line_group_copy = line_group.copy()
                    line_group_copy['time_difference'] = line_group_copy['time_ms'] - line_group_copy['time_hs_ms']
                    
                    valid_diff_data = line_group_copy.dropna(subset=['time_difference'])
                    if not valid_diff_data.empty:
                        diff_label_suffix = " (App Traffic)" if plot_type == "combined" else ""
                        diff_label = f"{base_label}{diff_label_suffix}" if f"{base_label}{diff_label_suffix}" not in added_labels else None
                        if diff_label:
                            added_labels.add(f"{base_label}{diff_label_suffix}")
                        
                        linestyle = 'dotted' if plot_type == "combined" else payload_to_linestyle[payload_value]
                        marker = '^' if plot_type == "combined" else 'o'
                        ax.plot(valid_diff_data['requests'], valid_diff_data['time_difference'],
                                label=diff_label,
                                color=colors.get(ms_enabled_value, 'gray'),
                                linestyle=linestyle,
                                marker=marker,
                                markersize=4,
                                alpha=0.8)

                        # --- Trend line ONLY for MS-TCP and ONLY on the App-Time-only plot ---
                        if plot_type == "difference" and ms_enabled_value == 1:
                            sorted_diff = valid_diff_data.sort_values('requests')
                            if len(sorted_diff) >= 2:
                                x1 = sorted_diff['requests'].iloc[0]
                                y1 = sorted_diff['time_difference'].iloc[0]
                                x2 = sorted_diff['requests'].iloc[1]
                                y2 = sorted_diff['time_difference'].iloc[1]
                                if x2 != x1:
                                    m = (y2 - y1) / (x2 - x1)
                                    x_min = sorted_diff['requests'].min()
                                    x_max = sorted_diff['requests'].max()
                                    y_min = m * (x_min - x1) + y1
                                    y_max = m * (x_max - x1) + y1

                                    trend_label = "Reference linear trend"
                                    # add legend entry only once total
                                    if "TREND_MS_ONLY" in added_labels:
                                        trend_label = None
                                    else:
                                        added_labels.add("TREND_MS_ONLY")

                                    ax.plot([x_min, x_max], [y_min, y_max],
                                            color=colors.get(ms_enabled_value, 'gray'),
                                            linestyle='--',
                                            linewidth=1.0,
                                            alpha=0.7,
                                            label=trend_label)

        # --- DYNAMIC AXIS CONFIGURATION ---
        request_ticks = sorted(final_data['requests'].unique())
        ax.set_xticks(request_ticks)
        
        # Configure the plot's appearance based on type
        ax.set_xlabel("Number of Requests")
        
        if plot_type == "combined":
            title = f"Full Performance Comparison - Serial 200KB Requests"
            #if has_time_hs_ms:
                #title += "\n(Solid: time_ms, Dashed: time_hs_ms, Dotted: difference)"
        elif plot_type == "time_ms":
            title = f"Total Time (Handshake + Application Traffic) - Serial 200KB Requests"
        elif plot_type == "time_hs_ms":
            title = f"Handshake Time - Serial 200KB Requests"
        elif plot_type == "difference":
            title = f"Application Traffic Time - Serial 200KB Requests"
        ax.set_ylabel("Time [ms]")
        
        ax.set_title(title)
        ax.grid(True, which='both', linestyle='--', linewidth=0.5)
        ax.legend(title="Configuration")
        
        # Set y-axis to start from 0
        ax.set_ylim(bottom=0)

        plt.tight_layout()
        plt.show()

    # Create all plots
    print("Generating plots...")
    
    # Plot 1: Combined (all three line types)
    create_plot("combined")
    
    # Plot 2: time_ms only
    create_plot("time_ms")
    
    # Plot 3: time_hs_ms only (if available)
    if has_time_hs_ms:
        create_plot("time_hs_ms")
    
    # Plot 4: difference only (if available)  
    if has_time_hs_ms:
        create_plot("difference")

# Run the main function
if __name__ == "__main__":
    create_dynamic_performance_plot()