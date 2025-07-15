import os
import json 
import numpy as np
import pandas as pd 
from typing import List,Tuple
from torch.utils.data import Dataset
import random
from sklearn.preprocessing import OneHotEncoder , LabelEncoder
from torch import Tensor,empty,tensor,float32,int32,randperm
import warnings
from sklearn.base import OneToOneFeatureMixin
import subprocess
from sklearn.utils import column_or_1d

class ModbusDataset():

    """
This class organizes the CICModbus 2023 dataset by scanning its hierarchical directory structure,
helping in extracting and labeling data flows from CSV files, incorporating metadata such as file paths and directory details,
and preparing the data for efficient batch processing with PyTorch's DataLoader, with an optional filter argument to search directory paths.
    """
    def __init__(self, _root_dir = "./ModbusDataset",filter = "output"):
        self.root_dir = _root_dir
        self.filter=filter
        datasets_dir = self.find_csv_in_folder(self.root_dir,self.filter)
        benign_datasets_dir = self.find_csv_in_list(datasets_dir,"benign")
        attack_dataset_dir = self.find_csv_in_list(datasets_dir,"attack")
        ext_attack_dataset_dir = self.find_csv_in_list(attack_dataset_dir,"external")
        comp_ied_attack_dataset_dir = self.find_csv_in_list(attack_dataset_dir,"compromised-ied")
        comp_scada_attack_dataset_dir =self.find_csv_in_list(attack_dataset_dir,"compromised-scada")
        attack_logs_dir = self.find_csv_in_folder(self.root_dir,"attack logs")
        attack_logs_dir.extend(self.find_csv_in_folder(self.root_dir,"attacker logs"))
        ## Corrupted TimeStamp (more detail in ./ModbusDataset/Readme.md)
        corr_path =self.root_dir +"/attack/compromised-scada/attack logs/03-21-2023/03-21-2023-1-original.csv"
        if os.path.exists(corr_path ):
            attack_logs_dir.remove(corr_path)
        ext_attack_log_dir = self.find_csv_in_list(attack_logs_dir,"external")
        comp_ied_attack_log_dir = self.find_csv_in_list(attack_logs_dir,"compromised-ied")
        comp_scada_attack_log_dir =self.find_csv_in_list(attack_logs_dir,"compromised-scada")
        self.dataset ={
            "metadata":{
                "info":""" The CIC Modbus Dataset contains network (pcap) captures and attack logs from a simulated substation network.
                The dataset is categorized into two groups: an attack dataset and a benign dataset
                The attack dataset includes network traffic captures that simulate various types of Modbus protocol attacks in a substation environment.
                The attacks are reconnaissance, query flooding, loading payloads, delay response, modify length parameters, false data injection, stacking Modbus frames, brute force write and baseline replay.
                These attacks are based of some techniques in the MITRE ICS ATT&CK framework.
                On the other hand, the benign dataset consists of normal network traffic captures representing legitimate Modbus communication within the substation network.
                The purpose of this dataset is to facilitate research, analysis, and development of intrusion detection systems, anomaly detection algorithms and other security mechanisms for substation networks using the Modbus protocol.
                https://www.unb.ca/cic/datasets/modbus-2023.html
                In my custom PyTorch Dataset class,
                I utilize the Enhanced CICflowMeter and the Attack logs correlation to extract and label sequential data flows,
                preparing them for batch processing with the DataLoader, which is crucial for AI model training.
                https://github.com/hamid-rd/FLBased-ICS-NIDS/tree/main

                """,
                "founded_files_num":{
                    "total_dataset_num":len(datasets_dir),"benign_dataset_num":len(benign_datasets_dir),"attack_dataset_num":{
                    "total_num":len(attack_dataset_dir),
                    "external_num":len(ext_attack_dataset_dir),
                    "compromised-ied_num":len(comp_ied_attack_dataset_dir),
                    "compromised-scada_num":len(comp_scada_attack_dataset_dir),
                    },"attack_logs_num":{
                        "total_num":len(attack_logs_dir),
                        "external_num":(ext_attack_log_dir),
                        "compromised-ied_num":len(comp_ied_attack_log_dir),
                        "compromised-scada_num":len(comp_scada_attack_log_dir),
                    }
                }
            },
            "total_dataset_dir" :datasets_dir,
            "benign_dataset_dir":benign_datasets_dir,
            "attack_dataset_dir":{"total":attack_dataset_dir,
                                  "external":ext_attack_dataset_dir,
                                  "compromised-ied":comp_ied_attack_dataset_dir,
                                  "compromised-scada":comp_scada_attack_dataset_dir}
            ,
            "attack_log_dir":{"total":attack_logs_dir,
                            "external":ext_attack_log_dir,
                            "compromised-ied":comp_ied_attack_log_dir,
                            "compromised-scada":comp_scada_attack_log_dir}}
    

    def convert_list_of_dataframes_to_numpy(self,list_of_dfs):
        numpy_arrays = [df.to_numpy() for df in list_of_dfs]
        combined_array = np.concatenate(numpy_arrays, axis=0)
        return combined_array

    def find_csv_in_folder(self,_start_path,_folder_name):
        csv_files = []
        for root, _, files in os.walk(_start_path):
            if _folder_name in root.split(os.sep) :
                csv_files.extend([os.path.join(root, f) for f in files if f.endswith('.csv')])
        return csv_files

    def find_csv_in_list(self,_datasets_dir,_folder_name):
        return  [ds for ds in _datasets_dir  if ds.find(_folder_name)!=(-1)]
    
    def summary_print(self):
        print(self.dataset["metadata"]["info"])
        print("csv files  in the dataset directory founded with the filter: ",self.filter)
        print(json.dumps(self.dataset["metadata"]["founded_files_num"],indent=4))

    def print_csv(datasets_dir_list,replace_dir):
        for i,dataset in enumerate(datasets_dir_list) :
            print(i+1,dataset.replace(replace_dir,""))

class ModbusFlowStream(Dataset):
    def __init__(
        self,
        csv_files: List[str],
        chunk_size: int = 5,
        batch_size: int = 64, 
        scalers: dict = None,  #accept a dictionary of scalers
        shuffle=True,
        unuseful_features:List[str]  = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Timestamp','end_time',
            'Fwd URG Flags', 'Bwd URG Flags', 'URG Flag Count', 'CWR Flag Count', 'ECE Flag Count', 'Fwd Bytes/Bulk Avg', 'Fwd Packet/Bulk Avg',
            'Fwd Bulk Rate Avg', 'Bwd Bytes/Bulk Avg', 'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg', 'ICMP Code', 'ICMP Type'],
        window_size: int = 1,   # window size for RNN sequences
    ):
    
        """
        Custom PyTorch Dataset for reading multiple CSV files in chunks with preprocessing and scaling.

        Args:
            csv_files: List of paths to CSV files
            chunk_size: Number of files to process in one chunk (default: 5)
            scalers: Dictionary of fitted scalers (MinMaxScaler or StandardScaler) for each numeric feature column.
            shuffle: shuffle indices of rows in each chunk (internal handling) (default:True)
            window_size: return samples (default:1) or sequences with window_size (each file) for the RNN models 

        """

        self.csv_files = csv_files
        self.csv_files_len = len(csv_files)
        self.chunk_size = chunk_size
        self.batch_size = batch_size  
        self.label_column = 'Label'
        self.protocol_column = 'Protocol'
        self.scalers = scalers 
        if shuffle and window_size!=1:
            warnings.warn("when dealing with time_series/sequences shuffling is prohibited")
        self.file_order_indices = list(range(self.csv_files_len))
        self.shuffle = shuffle
        self.window_size=window_size

        self.current_file_idx = 0 

        self.current_chunk_data = None
        self.current_chunk_labels = None
        self.current_row_in_chunk_idx = 0 # Index within the currently loaded chunk

        self.unuseful_features = unuseful_features
        
        # Determine numeric columns for scaling once during initialization
        self.numeric_cols_to_scale =[]
        self.determine_numeric_cul()
        class MyLabelEncoder(LabelEncoder):
            def fit(self, y):
                y = column_or_1d(y, warn=True)
                # instead of np.unique to bypass sorting alphabetically
                self.classes_ = pd.Series(y).unique()
                return self
        self.label_encoder = MyLabelEncoder()
        self.protocol_encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
        self._fit_encoders()

        self.total_batches = self._calculate_total_rows()

    def determine_numeric_cul(self):    
        if self.csv_files_len > 0:
            # call once in __init__ function
            # assumes the column structure and data types are consistent across all CSVs.
            try:
                temp_df = pd.read_csv(self.csv_files[0], encoding='cp1252', nrows=100, low_memory=False)
                
                relevant_cols = [col for col in temp_df.columns if col not in self.unuseful_features]
                
                # Filter for numeric types and exclude label/protocol columns
                self.numeric_cols_to_scale = [
                    col for col in relevant_cols
                    if pd.api.types.is_numeric_dtype(temp_df[col]) and col not in [self.label_column, self.protocol_column]
                ]
            except Exception as e:
                print(f"Warning: Could not infer numeric columns from first CSV file. Error: {e}")
                print("Proceeding without pre-calculated numeric columns for scaling, this may lead to slower preprocessing.")

    def _fit_encoders(self):
        """
        Fit LabelEncoders for 'Label' and OneHotEncoder for 'Protocol' based on known unique values.
        """
        label_values = ['BENIGN','BRUTE FORCE','BASELINE REPLAY', 'PAYLOAD INJECTION', 'FRAME STACKING', 'QUERY FLOODING', 'RECON'
                        ,'LENGTH MANIPULATION', 'DELAY RESPONSE',]
        # OneHotEncoder expects a 2D array, even for a single feature
        protocol_values = np.array([17, 2, 6]).reshape(-1, 1)
        self.label_encoder.fit(label_values)
        self.protocol_encoder.fit(protocol_values)

    def _preprocess_chunk(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply scaling to numeric columns using the provided dictionary of scalers.
        Args:
            df (pd.DataFrame): The DataFrame chunk to preprocess.

        Returns:
            pd.DataFrame: The preprocessed DataFrame.
        """
        if  not (self.scalers):
            return df
        if isinstance(list(self.scalers.values())[0],OneToOneFeatureMixin):
            for col in self.numeric_cols_to_scale:
                if col in self.scalers: # Ensure a scaler exists for the current column
                    # Apply the specific scaler for this column
                    # .transform expects a 2D array, hence df[[col]]
                    df[col] = self.scalers[col].transform(df[[col]].values)
        else:
            warnings.warn("given scalers dictionary doesn't contain values that inherit from OneToOneFeatureMixin base library (MinMaxScaler/StandardScaler)")
        return df

    def _load_next_chunk(self):
        """
        Loads the next chunk of CSV files into memory ,
        preprocesses, encodes, and converts data to PyTorch Tensors.
        Handles reshuffling of  indices within each file
        """
        # If all files from the current order have been processed
        if self.current_file_idx >= self.csv_files_len:
            self.current_file_idx = 0 

        start_idx_in_order = self.current_file_idx
        end_idx_in_order = min(start_idx_in_order + self.chunk_size, self.csv_files_len)

        chunk_file_paths = [self.csv_files[self.file_order_indices[i]] for i in range(start_idx_in_order, end_idx_in_order)]

        if chunk_file_paths:

            # Concat CSV files, dropping unuseful features
            if chunk_file_paths ==1 :
                chunk_df = pd.read_csv(chunk_file_paths, encoding='cp1252',
                                                usecols=self.numeric_cols_to_scale.extend(self.label_column), low_memory=False) 
            else :
                chunk_df = pd.concat([pd.read_csv(file, encoding='cp1252',
                                                usecols=lambda column: column not in self.unuseful_features, low_memory=False) for file in chunk_file_paths],
                                                ignore_index=True)

            if self.shuffle:
                chunk_df = chunk_df.sample(frac=1).reset_index(drop=True)
            ####### new code
            # chunk_df.drop_duplicates(inplace = True)

            ######
            chunk_df[self.label_column] = self.label_encoder.transform(chunk_df[self.label_column])
            protocol_encoded_array = self.protocol_encoder.transform(chunk_df[[self.protocol_column]].values)
            chunk_df.drop(columns=[self.protocol_column], inplace=True)
            chunk_df[[f'Protocol_{int(cat)}' for cat in self.protocol_encoder.categories_[0]]] = protocol_encoded_array

            chunk_df = self._preprocess_chunk(chunk_df)
            features_np = chunk_df.drop(columns=[self.label_column]).values
            labels_np = chunk_df[self.label_column].values

            if self.window_size != 1: #RNN sequences
                sequences = []
                seq_labels = []
                for i in range(len(features_np) - self.window_size + 1):
                    sequences.append(features_np[i:i + self.window_size])
                    # binary classification (normal/anormaly)
                    # if one flow is anomaly (label number greater than zero), then the total seq is anomaly
                    seq_labels.append(np.max(labels_np[i + self.window_size - 1]))
                if not sequences: 
                    self.current_chunk_data = empty(0)
                    self.current_chunk_labels = empty(0)
                else:
                    self.current_chunk_data = tensor(np.array(sequences), dtype=float32)
                    self.current_chunk_labels = tensor(np.array(seq_labels), dtype=int32)
            
            else: # window_size ==1 , AutoEncoder samples 
                self.current_chunk_data = tensor(features_np, dtype=float32)
                self.current_chunk_labels = tensor(labels_np, dtype=int32)
            
            self.current_len_chunk_data = len(self.current_chunk_data)
            self.current_file_idx = end_idx_in_order
            self.current_row_in_chunk_idx = 0  # Reset row index within the new chunk
        else:
            self.current_chunk_data = None
            self.current_chunk_labels = None

    def _calculate_total_rows(self) -> int:
        """
        Calculates the total number of samples across all CSV files.
        This is called once during initialization.
        """
        def count_rows(file_path):
            result = subprocess.run(['wc', '-l', file_path], capture_output=True, text=True)
            return int(result.stdout.split()[0]) - 1  # Subtract 1 for header
        if not (isinstance(self.csv_files,list)):
            try:
                self.csv_files = list(self.csv_files)
            except:
                print(self.csv_files,f"with type {type(self.csv_files)}","not convertable to python list")
        total_rows = sum(int(np.ceil((count_rows(file)-self.window_size+1)/self.batch_size)) for file in self.csv_files)            
        return total_rows

    def __len__(self) -> int:

        """
        Returns the total number of batches available for a DataLoader(suppose window_size=1).
        This value is precalculated in the __init__ method.
        """
        return self.total_batches

    def __getitem__(self, idx: int) -> Tuple[Tensor, Tensor]:
        """
        This method internally manages loading fixed-size batches (self.batch_size=64) from chunks.
        The `idx` parameter from DataLoader is used by DataLoader for tracking progress,
        but not directly for selecting data within this Dataset's internal logic.

        Args:
            idx (int): Index provided by the DataLoader.

        Returns:
            Tuple[Tensor, Tensor]: A tuple containing (features_tensor, labels_tensor) for the batch.
        """

        if self.current_chunk_data is None:
            #initial 
            self._load_next_chunk()
        if self.chunk_size>=self.csv_files_len and self.batch_size==1:
            ## In this manner, treat like a normal custom dataset wraps all csv files in a tensor 
            # no chunk-chunk read of hard disk files is needed.
            #use this if your memory is enough 
            return self.current_chunk_data[idx],self.current_chunk_labels[idx]

        if self.current_row_in_chunk_idx >= self.current_len_chunk_data:
            self._load_next_chunk()
        end_idx = min(self.current_row_in_chunk_idx + self.batch_size, self.current_len_chunk_data)
        # Slice the data and labels directly from the pre-converted tensors
        features = self.current_chunk_data[self.current_row_in_chunk_idx:end_idx]
        labels = self.current_chunk_labels[self.current_row_in_chunk_idx:end_idx]
        self.current_row_in_chunk_idx = end_idx
        return features, labels