# Federated learning based Modbus/TCP Intrusion Detection


- [Introduction](#introduction)
- [CICModbus2023](#cicmodbus2023)
  - [Attacks](#attacks)
  - [Architecture](#architecture)
  - [Feature Extraction pipeline](#feature-extraction-pipeline)
- [Preprocessing](#preprocessing)
  - [Requirments](#resources)
  - [Labeling](#labeling)
  - [Visualization](#visualization)
## Introduction

In this repo, a federated framework for Anomaly-based Netowrk Intrusion Detection through VAE-LSTM Network implemented.

## CICModbus2023

The CIC Modbus Dataset contains network (pcap) captures and attack logs from a simulated substation network.
```md
[Download Link](https://www.unb.ca/cic/datasets/modbus-2023.html)
```
### Attacks

The dataset covers attacks conducted in three different scenarios:
attacks from devices external to the network, attacks from compromised IEDs and attacks from compromised Human-Machine Interfaces (HMIs).
Each scenario generated specific logs capturing the corresponding attack activity.

<table>
<tr>
<th>Attacks Mapped To MITRE ICS ATT&CK Framework</th>
</tr>
<tr>
  
<td>

| Tactic | Technique | Attack |
|--|--|--|
| Collection | Automated Collection | Reconnaissance <br/> Scan addresses |
| Inhibit Response Function | Denial of Service | Query flooding <br/> Load malicious payloads <br/> Delay response <br/> Modify length parameters <br/> False injection <br/> Stack modbus frames |
| Impair process control | Brute Force I/O |  I/O Write to all coils |
| Evasion | Spoof |  Reporting Message Baseline replay |

</td></tr> </table>

[more details](./ModbusDataset)

### Architecture

![image](https://github.com/user-attachments/assets/f395a413-b035-48d5-adcb-f23c43f1632b)

##### Secure IEDs
- IED1A – 185.175.0.4
- IED4C – 185.175.0.8
##### Normal IEDs
- IED1B – 185.175.0.5
##### Secure SCADA HMI – 185.175.0.2
##### Normal SCADA HMI – 185.175.0.3
##### Central Agent – 185.175.0.6
##### Attacker – 185.175.0.7


### Feature Extraction pipeline

![image](https://github.com/user-attachments/assets/9387415a-d5c5-4c6a-8508-b74b9636955e)


Make sure you downloaded the dataset and extracted in the ./ModbusDataset directory.
Then for getting started, Install pre-required tools (pcapfix,reordercap,enhanced CICFlowMeter,) with the help of the 0useful links  

### useful links

```md

[Fed-ANIDS: : Federated learning for anomaly-based network intrusion detection systems](https://doi.org/10.1016/j.eswa.2023.121000)
[pcapfix](https://github.com/Rup0rt/pcapfix)
[reordercap](https://www.wireshark.org/docs/man-pages/reordercap.html)
[flowExtraction](https://github.com/GintsEngelen/CICFlowMeter)
[labeling](https://github.com/GintsEngelen/CNS2022_Code)

```

#### pipeline script
Ensure the above programms downloaded ,installed and added to the path successfully in Ubuntu 20 or higher / WSL2.
Ensure Docker is running.
download and extract the ModbusDataset2023 in ./ModbusDataset directory.
> ModbusDataset
>> benign
>
>> attack

```md
# fix corrupted packets,reorder by timestamp then create input directory alongside the .pcap files and save in it.
./pcapFixReorder.sh
# run docker container of modified CICFlowMeter to extract .csv flows from .pcap save in output directory
./flowExtract.sh
# handle TimeStamp of compromised scada 21/3 attack log (has no year-month-day-hour)
./fixScadaAttackLog.sh
```

## Preprocessing

We will label the CSV files in the output directories and compress them into a zip file, making them ready for data analysis and AI research.


### Requirments

Create python (3.10.12) virtual environment and install prerequires (WSL-Win11-nvidia). 
The list of requirement packages is enough for this part and the next parts, but you don't have to use it exactly as provided; you can create your own.

```md
python -m venv vnv
source ./vnv/bin/activate
pip install -r requirements.txt
pip3 install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

### Labeling 

Label [ pipeline script ](#feature-extraction-pipeline) by correlating them with the Timestamp and IP columns from the Attack Logs. Fallow the guidelines of Labeling.ipynb results in the Labeld_CICMODBUS2023.zip. 

### Visualization

Dataset statiscal charactristics (like mean,min,max,...) analyzed. Label Distribution for each node in diverse attack scenarios 
plotted (huge unbalanaed). Classification performance of several machine learning models (SVM,LR,Gaussian Naive Bayes ,...) is tested. 
Some feature Engineering techniques (like underSampling,MinMax Scaling,feature selection,...) is implemented to improve the performance.

