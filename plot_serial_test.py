import pandas as pd
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import filedialog

import matplotlib
matplotlib.use('TkAgg')  # Ensures GUI backend
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL) # https://stackoverflow.com/a/75864329

def create_dynamic_performance_plot():
    """
    Allows user to select a CSV, then dynamically plots performance data
    adapting to the unique values in 'payload_size' and 'requests' columns.
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

    if df.empty:
        print("\nThe CSV file is empty. Cannot generate a plot.")
        return

    # Group and aggregate data
    processed_df = df.groupby(['MS_ENABLED', 'payload_size', 'requests'])['time_ms'].agg(['mean', 'count']).reset_index()
    processed_df.rename(columns={'mean': 'avg_time_ms'}, inplace=True)

    print("\n--- Data Summary ---")
    print(processed_df)
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
    unique_payloads = sorted(processed_df['payload_size'].unique())
    payload_to_linestyle = {
        payload: line_styles_list[i % len(line_styles_list)] 
        for i, payload in enumerate(unique_payloads)
    }
    
    print("Dynamically assigned line styles:")
    for payload, style in payload_to_linestyle.items():
        print(f"  - Payload Size {payload}: '{style}'")
    print("-" * 20)

    # Iterate through each MS_ENABLED family
    for ms_enabled_value, family_group in processed_df.groupby('MS_ENABLED'):
        # Iterate through each payload_size within the family
        for payload_value, line_group in family_group.groupby('payload_size'):
            line_group = line_group.sort_values('requests')
            
            ax.plot(line_group['requests'], line_group['avg_time_ms'],
                    label=f'MS_ENABLED={ms_enabled_value}, payload={payload_value}',
                    color=colors.get(ms_enabled_value, 'gray'), # Default to gray if value is not 0 or 1
                    linestyle=payload_to_linestyle[payload_value],
                    marker='o',
                    markersize=5)

    # --- DYNAMIC AXIS CONFIGURATION ---
    # Set x-axis ticks to only the values present in the 'requests' column
    request_ticks = sorted(processed_df['requests'].unique())
    ax.set_xticks(request_ticks)
    
    # Configure the plot's appearance
    ax.set_xlabel("Number of Requests")
    ax.set_ylabel("Average time_ms")
    ax.set_title("Average Time vs. Requests by Payload Size")
    ax.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax.legend(title="Configuration")

    plt.tight_layout()
    plt.show()

# Run the main function
if __name__ == "__main__":
    create_dynamic_performance_plot()