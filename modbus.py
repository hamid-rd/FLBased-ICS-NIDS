
import os
import json 
from torch.utils.data import Dataset
import numpy as np
import pandas as pd 

class ModbusDataset(Dataset):
    """
This class organizes the CICModbus 2023 dataset by scanning its hierarchical directory structure,
helping in extracting and labeling data flows from CSV files, incorporating metadata such as file paths and directory details,
and preparing the data for efficient batch processing with PyTorch's DataLoader, with an optional filter argument to search directory paths.
    """
    def __init__(self, _root_dir = "./ModbusDataset",filter = "output",batch_size=5):
        self.root_dir = _root_dir
        self.batch_size = batch_size
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
        
    def __len__(self):
        return int(np.ceil(self.dataset["metadata"]["founded_files_num"]["total_dataset_num"] / float(self.batch_size)))   # Number of chunks.
    
    def __getitem__(self, idx): 
        #return batch_size number of csv files in numpy matrix format
        batch_x = self.dataset["total_dataset_dir"][idx * self.batch_size : (idx + 1) * self.batch_size] 
        dataset_df_list = []
        label_df_list = []
        for file in batch_x:
            temp =pd.read_csv(file,encoding='cp1252')

            # Remove unuseful features
            numeric_cols = temp.drop(columns=['Flow ID','Src IP','Src Port','Dst IP','Dst Port','Timestamp']).select_dtypes(include=['number']).columns
            # Process features
            features = df[self.numeric_columns].copy()
            for col in self.numeric_columns:
                # Min-max scaling with zero-division guard
                col_range = self.feature_max[col] - self.feature_min[col]
                if col_range == 0:
                    features[col] = 0.5  # Handle constant columns
                else:
                    features[col] = (features[col] - self.feature_min[col]) / col_range
            
            # Process labels
            one_hot = np.zeros((len(df), len(self.unique_labels)), dtype=np.float32)
            for i, label in enumerate(df['Label']):
                if label in self.unique_labels:
                    one_hot[i, self.unique_labels.index(label)] = 1

            dataset_df_list.append(temp[numeric_cols])
            label_df_list.append(temp['Label'])
        data = self.convert_list_of_dataframes_to_numpy(dataset_df_list)
        labels = self.convert_list_of_dataframes_to_numpy(label_df_list)

        # The following condition is actually needed in Pytorch. Otherwise, for our particular example, the iterator will be an infinite loop.
        # Readers can verify this by removing this condition.
        if idx == self.__len__():  
            raise IndexError

        return data, labels

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

