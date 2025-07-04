import pandas as pd
import numpy as np
import pickle,os
# Basic preprocessing before getting started on labelling.
# Deletes rows with "Infinity" and NaNs, converts "Timestamp" to Pandas Datetime, and converts all necessary columns to numeric values
# Int_64 Columns (Attempted-Category) not considered.

print_index = False
def format_csv_for_labeling(df):
    df = df.replace('Infinity', np.nan)
    # Clean the Timestamp strings to always include microseconds (append .0 if missing)
    if 'Timestamp' in df.columns:
        df['Timestamp'] = pd.to_datetime(
            df['Timestamp'].apply(
                lambda x: x if '.' in x.split()[-1] else f"{x}.0"  # Split into date/time and check time part
            ),
            format='%Y-%m-%d %H:%M:%S.%f'  # Parse with microseconds
        )
    for column in df.columns:
        if column not in ['Flow ID' , 'Timestamp', 'Src IP', 'Dst IP', 'Label','Attack','TransactionID','TargetIP']:
            df[column] = pd.to_numeric(df[column], errors='coerce')
    df.dropna()
    return df.dropna()

def merge_datasets(_dataset_dir):
    """
        create dataframes from the directories then return the merged (concatenated) dataframe 
    """
    # take two columns (attack logs ) or four columns (attacker logs)    
    merged_new_df = format_csv_for_labeling(pd.read_csv(_dataset_dir[0], encoding='cp1252'))
    for _dir in _dataset_dir[1:] :
        merged_new_df = pd.concat([format_csv_for_labeling(pd.read_csv(_dir, encoding='cp1252')),merged_new_df],join="inner")
    return merged_new_df
    
def find_unique_values(dataset_directories):
    """find all unique values for label and protocol columns across all CSV files in dataset_directories
        make them ready for fitting the one-hot encodes."""
    # example use :
    ### unique_values =find_unique_values(modbus.dataset["attack_dataset_dir"]["total"])
    ### print(unique_values)
    label_values = []
    protocol_values = []
    label_column = "Label"
    protocol_column = "Protocol"
    for file in dataset_directories:
        df = pd.read_csv(file, usecols=["Label", "Protocol"], encoding='cp1252')
        label_values.extend(df[label_column].unique())
        protocol_values.extend(df[protocol_column].unique())

    return(list(set(label_values)),list(set(protocol_values)))
    

def load_scalers(scaler_dir='fitted_scalers'):
    """
    Loads fitted scaler models from disk.

    Args:
        scaler_dir (str, optional): The directory where scalers are saved. Defaults to 'fitted_scalers'.

    Returns:
        dict: A dictionary containing the loaded scalers, organized by subdirectory.
              Returns an empty dictionary if the directory doesn't exist.
    """
    loaded_scalers = {}
    if not os.path.exists(scaler_dir):
        print(f"Scaler directory '{scaler_dir}' not found.")
        return loaded_scalers

    for subdir_name in os.listdir(scaler_dir):
        subdir_path = os.path.join(scaler_dir, subdir_name)
        if os.path.isdir(subdir_path):
            try:
                min_max_path = os.path.join(subdir_path, 'min_max_scalers.pkl')
                standard_path = os.path.join(subdir_path, 'standard_scalers.pkl')

                if os.path.exists(min_max_path) and os.path.exists(standard_path):
                    # In the load_scalers function, replace joblib.load() with:
                    with open(min_max_path, 'rb') as f:
                        min_max_scalers = pickle.load(f)
                    with open(standard_path, 'rb') as f:
                        standard_scalers = pickle.load(f)
                    loaded_scalers[subdir_name] = {
                        'min_max_scalers': min_max_scalers,
                        'standard_scalers': standard_scalers
                    }
                    print(f"Successfully loaded scalers for '{subdir_name}'")
            except Exception as e:
                print(f"Could not load scalers for '{subdir_name}'. Error: {e}")
                
    return loaded_scalers
