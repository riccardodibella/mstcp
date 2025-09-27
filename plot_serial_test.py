size_str = "2KB - 60 Requests"

import pandas as pd
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import filedialog

import matplotlib
matplotlib.use('TkAgg')  # Ensures GUI backend
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL) # https://stackoverflow.com/a/75864329


def filter_outliers(values: pd.Series) -> pd.Series:
   # return values
   """Remove outliers using IQR method, only if outliers are detected."""
   if len(values) < 4:
       return values
   
   Q1 = values.quantile(0.25)
   Q3 = values.quantile(0.75)
   IQR = Q3 - Q1
   
   # If IQR is 0 (all values very similar), no outliers to remove
   if IQR == 0:
       return values
   
   lower_bound = Q1 - 1.5 * IQR
   upper_bound = Q3 + 1.5 * IQR
   
   # Only filter if there are actual outliers
   outliers_exist = (values < lower_bound).any() or (values > upper_bound).any()
   if not outliers_exist:
       return values
   
   return values[(values >= lower_bound) & (values <= upper_bound)]

def get_min_time_data(group):
    """Get the row with minimum time_ms and return time_ms, time_hs_ms, and their difference."""
    if len(group) == 0:
        return pd.Series({'min_time_ms': None, 'corresponding_time_hs_ms': None, 'time_difference': None, 'count': 0})
    
    # First filter outliers from the time_ms column
    filtered_time_ms = filter_outliers(group['time_ms'])
    
    # If no data remains after filtering, return the original minimum
    if len(filtered_time_ms) == 0:
        min_idx = group['time_ms'].idxmin()
    else:
        # Find the index of the minimum value in the filtered data
        min_idx = filtered_time_ms.idxmin()
    
    min_row = group.loc[min_idx]
    time_ms_val = min_row['time_ms']
    time_hs_ms_val = min_row.get('time_hs_ms', None)
    
    # Calculate the difference if both values are available
    time_difference = None
    if time_hs_ms_val is not None:
        time_difference = time_ms_val - time_hs_ms_val
    
    return pd.Series({
        'min_time_ms': time_ms_val,
        'corresponding_time_hs_ms': time_hs_ms_val,
        'time_difference': time_difference,
        'count': len(filtered_time_ms) if len(filtered_time_ms) > 0 else len(group)
    })

def create_dynamic_performance_plot():
    """
    Allows user to select a CSV, then dynamically plots performance data
    adapting to the unique values in 'payload_size' and 'requests' columns.
    Also plots corresponding time_hs_ms values with dashed lines.
    """
    # 1. Let the user choose a CSV file
    root = tk.Tk()
    root.withdraw()  # Hide the main tkinter window

    file_path = filedialog.askopenfilename(
        title="Select the CSV data file",
        filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
    )

    if not file_path:
        print("No file selected. The program will now exit.")
        return

    # Load the selected file as a pandas DataFrame
    try:
        df = pd.read_csv(file_path, delimiter=';')
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

    # Group and get min time data (outlier filtering is now handled within get_min_time_data)
    filtered_groups = df.groupby(['MS_ENABLED', 'payload_size', 'requests']).apply(
        get_min_time_data
    ).reset_index()

    print("\n--- Data Summary ---")
    print(filtered_groups)
    print("--------------------\n")

    # 3. Plot the data dynamically
    fig, ax = plt.subplots(figsize=(12, 8))

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
    unique_payloads = sorted(filtered_groups['payload_size'].unique())
    payload_to_linestyle = {
        payload: line_styles_list[i % len(line_styles_list)] 
        for i, payload in enumerate(unique_payloads)
    }
    
    print("Dynamically assigned line styles:")
    for payload, style in payload_to_linestyle.items():
        print(f"  - Payload Size {payload}: '{style}'")
    print("-" * 20)

    # Keep track of which labels have been added to avoid duplicates
    added_labels = set()

    # Iterate through each MS_ENABLED family
    for ms_enabled_value, family_group in filtered_groups.groupby('MS_ENABLED'):
        # Iterate through each payload_size within the family
        for payload_value, line_group in family_group.groupby('payload_size'):
            line_group = line_group.sort_values('requests')
            
            # Create base label
            base_label = "MS-TCP" if ms_enabled_value else "TCP"
            
            # Plot time_ms (solid lines with circles)
            time_ms_label = base_label if base_label not in added_labels else None
            if time_ms_label:
                added_labels.add(base_label)
            
            ax.plot(line_group['requests'], line_group['min_time_ms'],
                    label=time_ms_label,
                    color=colors.get(ms_enabled_value, 'gray'),
                    linestyle=payload_to_linestyle[payload_value],
                    marker='o',
                    markersize=5)
            
            # Plot time_hs_ms if available (dashed lines with squares)
            if has_time_hs_ms and 'corresponding_time_hs_ms' in line_group.columns:
                # Filter out None/NaN values
                valid_hs_data = line_group.dropna(subset=['corresponding_time_hs_ms'])
                if not valid_hs_data.empty:
                    hs_label = f"{base_label} (HS)" if f"{base_label} (HS)" not in added_labels else None
                    if hs_label:
                        added_labels.add(f"{base_label} (HS)")
                    
                    ax.plot(valid_hs_data['requests'], valid_hs_data['corresponding_time_hs_ms'],
                            label=hs_label,
                            color=colors.get(ms_enabled_value, 'gray'),
                            linestyle='dashed',  # Always dashed for time_hs_ms
                            marker='s',  # Square markers
                            markersize=4,
                            alpha=0.7)
            
            # Plot time difference if available (dotted lines with triangles)
            if has_time_hs_ms and 'time_difference' in line_group.columns:
                # Filter out None/NaN values
                valid_diff_data = line_group.dropna(subset=['time_difference'])
                if not valid_diff_data.empty:
                    diff_label = f"{base_label} (Diff)" if f"{base_label} (Diff)" not in added_labels else None
                    if diff_label:
                        added_labels.add(f"{base_label} (Diff)")
                    
                    ax.plot(valid_diff_data['requests'], valid_diff_data['time_difference'],
                            label=diff_label,
                            color=colors.get(ms_enabled_value, 'gray'),
                            linestyle='dotted',  # Always dotted for difference
                            marker='^',  # Triangle markers
                            markersize=4,
                            alpha=0.8)

    # --- DYNAMIC AXIS CONFIGURATION ---
    # Set x-axis ticks to only the values present in the 'requests' column
    request_ticks = sorted(filtered_groups['requests'].unique())
    ax.set_xticks(request_ticks)
    
    # Configure the plot's appearance
    ax.set_xlabel("Number of Requests")
    ax.set_ylabel("Time [ms]")
    title = f"Time vs. Requests {size_str}"
    if has_time_hs_ms:
        title += " (Solid: time_ms, Dashed: time_hs_ms, Dotted: difference)"
    ax.set_title(title)
    ax.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax.legend(title="Configuration")

    plt.tight_layout()
    plt.show()

# Run the main function
if __name__ == "__main__":
    create_dynamic_performance_plot()