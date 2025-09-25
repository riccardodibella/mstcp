import pandas as pd
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import filedialog

import matplotlib
matplotlib.use('TkAgg')  # Ensures GUI backend
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL) # https://stackoverflow.com/a/75864329


def filter_outliers(values: pd.Series) -> pd.Series:
   return values
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

def plot_data(processed_df, title_suffix="", x_scale="log", payload_lower_bound=None):
    """
    Create a plot with the specified configuration.
    
    Args:
        processed_df: DataFrame with processed data
        title_suffix: Additional text for plot title
        x_scale: 'log' or 'linear' for x-axis scale
        payload_lower_bound: Minimum payload size to include (None for no filtering)
    """
    # Filter data based on lower bound if specified
    plot_df = processed_df.copy()
    plot_df = plot_df[plot_df['num_clients'] <= 24]
    if payload_lower_bound is not None:
        plot_df = plot_df[plot_df['payload_size'] >= payload_lower_bound]
        if plot_df.empty:
            print(f"No data points with payload_size >= {payload_lower_bound}")
            return
    
    fig, ax = plt.subplots(figsize=(12, 8))

    # --- DYNAMIC STYLING ---
    # Define colors for the MS_ENABLED families
    colors = {0: 'royalblue', 1: 'darkorange'}
    
    # Define a list of line styles to cycle through for num_clients
    line_styles_list = [
        'solid',        # same as '-'
        'dashdot',      # same as '-.'
        (0, (1, 1)),    # densely dotted
        (0, (5, 10)),   # long dash
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
    
    # Discover unique num_clients from the filtered data and assign a style to each
    unique_clients = sorted(plot_df['num_clients'].unique())
    clients_to_linestyle = {
        clients: line_styles_list[i % len(line_styles_list)] 
        for i, clients in enumerate(unique_clients)
    }

    # Iterate through each MS_ENABLED family
    for ms_enabled_value, family_group in plot_df.groupby('MS_ENABLED'):
        # Iterate through each num_clients within the family
        for clients_value, line_group in family_group.groupby('num_clients'):
            line_group = line_group.sort_values('payload_size')
            
            ax.plot(line_group['payload_size'], line_group['max_throughput_kbps'],
                    label=f'{"MS-TCP" if ms_enabled_value else "TCP"} - {clients_value} clients',
                    color=colors.get(ms_enabled_value, 'gray'), # Default to gray if value is not 0 or 1
                    linestyle=clients_to_linestyle[clients_value],
                    marker='o',
                    markersize=3)

    # --- AXIS CONFIGURATION ---
    # Set x-axis scale
    ax.set_xscale(x_scale)
    
    payload_ticks = sorted(plot_df['payload_size'].unique())
    if x_scale == 'log':
        print(payload_ticks)
        payload_ticks = [1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000, 400000, 600000]
    ax.set_xticks(payload_ticks)
    
    if x_scale == 'log':
        ax.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
        ax.get_xaxis().set_minor_formatter(matplotlib.ticker.NullFormatter())
    
    # Configure the plot's appearance
    ax.set_xlabel("Payload Size")
    ax.set_ylabel("Maximum Throughput (KB/s)")
    
    # Dynamic title based on configuration
    base_title = "Maximum Throughput vs. Payload Size"
    if title_suffix:
        base_title += f" - {title_suffix}"
    ax.set_title(base_title)
    
    ax.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax.legend(title="Configuration")

    plt.tight_layout()
    plt.show()

def create_dynamic_performance_plot():
    """
    Allows user to select a CSV, then dynamically plots performance data
    adapting to the unique values in 'MS_ENABLED' and 'num_clients' columns.
    Shows both logarithmic and linear scale plots with optional filtering.
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
    # Check for essential columns (now including dl_bytes for throughput calculation)
    required_cols = {'MS_ENABLED', 'payload_size', 'num_clients', 'time_ms', 'dl_bytes'}
    if not required_cols.issubset(df.columns):
        print(f"Error: The CSV must contain the following columns: {required_cols}")
        return

    if df.empty:
        print("\nThe CSV file is empty. Cannot generate a plot.")
        return

    # Calculate throughput in KB/s
    df['throughput_kbps'] = (df['dl_bytes'] / df['time_ms'])

    # Group and aggregate data using throughput instead of time_ms
    filtered_groups = df.groupby(['MS_ENABLED', 'payload_size', 'num_clients'])['throughput_kbps'].apply(filter_outliers)
    processed_df = filtered_groups.groupby(['MS_ENABLED', 'payload_size', 'num_clients']).agg(['max', 'count']).reset_index()
    processed_df.rename(columns={'max': 'max_throughput_kbps'}, inplace=True)

    print("\n--- Data Summary ---")
    print(processed_df)
    print("--------------------\n")

    # Configure lower bound for linear plot (set to None for no filtering)
    linear_plot_lower_bound = 100000
    
    # Show available payload sizes for reference
    payload_sizes = sorted(processed_df['payload_size'].unique())
    print(f"Available payload sizes: {payload_sizes}")
    if linear_plot_lower_bound is not None:
        print(f"Linear plot will show payload sizes >= {linear_plot_lower_bound}")

    # 3. Create plots
    # Original logarithmic plot
    plot_data(processed_df, "Logarithmic Scale", "log")
    
    # New linear plot with optional filtering
    plot_data(processed_df, "Linear Scale", "linear", linear_plot_lower_bound)

    # Load second CSV file
    print("\n" + "="*50)
    print("Now select the second CSV file...")

    file_path2 = filedialog.askopenfilename(
        title="Select the second CSV data file",
        filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
    )

    if file_path2:
        try:
            df2 = pd.read_csv(file_path2, delimiter=';')
            print("Second file loaded successfully.")
            
            # Process second file the same way
            df2['throughput_kbps'] = (df2['dl_bytes'] / df2['time_ms'])
            filtered_groups2 = df2.groupby(['MS_ENABLED', 'payload_size', 'num_clients'])['throughput_kbps'].apply(filter_outliers)
            processed_df2 = filtered_groups2.groupby(['MS_ENABLED', 'payload_size', 'num_clients']).agg(['max', 'count']).reset_index()
            processed_df2.rename(columns={'max': 'max_throughput_kbps'}, inplace=True)
            
            # Plot only log scale for second file
            plot_data(processed_df2, "6/12/18/24 clients - Logarithmic Scale", "log")
            
        except Exception as e:
            print(f"Error reading second file: {e}")
    else:
        print("No second file selected.")

# Run the main function
if __name__ == "__main__":
    create_dynamic_performance_plot()