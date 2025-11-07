# [VateX – eXtend the Edge](https://github.com/lastime1650/VateX)

<div align="center">
  <img
    src="https://github.com/lastime1650/VateX/blob/main/images/VATEX.png"
    alt="VATEX LOGO"
    width="500"
  />
</div>

---

# VateX EVIDENTIA EDR

<div align="center">
  <img
    src="https://github.com/lastime1650/VateX/blob/mainv2/images/VATEX_EDR_RENDERED.png"
    alt="VATEX EDR"
    width="400"
  />
</div>

> **EVIDENTIA** is Latin for *clarity* and *evidence*.

Our Endpoint Detection and Response (EDR) solution provides crystal-clear visibility into endpoint activities. We empower you to rapidly detect, investigate, and respond to threats at the device level, ensuring your infrastructure remains secure and resilient. 🛡️💻

---

## Architecture Overview

VateX EVIDENTIA EDR consists of two key components that work in tandem to protect your endpoints.

1.  **Kernel Access Agent** `(C/C++)`: A high-performance agent deployed on endpoints to collect deep, kernel-level event data.
2.  **EDR Server** `(C/C++)`: A centralized server that ingests, analyzes, and correlates data from all agents to detect threats.

> [!IMPORTANT]
> **Prerequisite: Apache Kafka**
> The Kernel Agent sends all collected events to an Apache Kafka cluster. Please ensure Kafka is installed and running before deploying the EDR server.
>
> **Data Flow:** `Kernel Agent` → `Apache Kafka` → `EVIDENTIA EDR Server`

---

## Core Detection Technologies

Our EDR leverages a multi-layered approach to threat detection, combining advanced AI with proven intelligence techniques.

### 1. AI-Powered Behavioral Analysis

Our core detection engine uses machine learning to analyze and predict threats based on process behavior. The agent collects entire process tree sessions, which are then processed through our sophisticated AI pipeline.

#### AI Detection Pipeline

**Step 1: 3D Process Session Modeling**
We begin by modeling each process tree session as a 3-dimensional data structure to capture its full context, including parent-child relationships, execution sequence, and call depth over time.

![initial](https://github.com/lastime1650/VATEX_EVIDENTIA_EDR/blob/master/EDR_ML_INTRODUCE_1.PNG)

<br>

**Step 2: Flattening to a 2D Representation**
To prepare the data for machine learning, the 3D model is flattened into a 2D representation by ordering all events chronologically, creating a sequential "surface" of the session's activity.

![initial](https://github.com/lastime1650/VATEX_EVIDENTIA_EDR/blob/master/EDR_ML_INTRODUCE_2.PNG)

<br>

**Step 3: Feature Extraction**
From the 2D data, we extract key features to build a feature vector (`X` data). This includes:
- **Session Metadata:** Core attributes of the process session.
- **Behavioral Analytics (XBA):** Detections from our rule-based engine.
- **Threat Intelligence:** Enrichment data from our **VateX INTELLINA** platform.

![initial](https://github.com/lastime1650/VATEX_EVIDENTIA_EDR/blob/master/EDR_ML_INTRODUCE_3.PNG)

<br>

**Step 4: Creating a Single Data Sample**
These combined features form a single, comprehensive data sample that numerically represents the entire process session.

![initial](https://github.com/lastime1650/VATEX_EVIDENTIA_EDR/blob/master/EDR_ML_INTRODUCE_4.PNG)

<br>

**Step 5: Building the Dataset**
By repeating this process for thousands of sessions, we construct a rich dataset of `X` samples ready for model training.

![initial](https://github.com/lastime1650/VATEX_EVIDENTIA_EDR/blob/master/EDR_ML_INTRODUCE_5.PNG)

<br>

**Step 6: Model Application**
This dataset is fed into various machine learning models for:
- **Classification:** Labeling sessions as benign or malicious.
- **Regression:** Assigning a dynamic risk score.
- **Clustering:** Identifying novel and unknown attack patterns.

![initial](https://github.com/lastime1650/VATEX_EVIDENTIA_EDR/blob/master/EDR_ML_INTRODUCE_6.PNG)

<br>

**Step 7: Defining the Target Variable (y)**
For supervised learning (Classification, Regression), a corresponding target variable (`y` data) is required for each sample. The nature of `y` depends on the model's goal (e.g., a "malicious" label or a risk score). For unsupervised learning like Clustering, `y` is not needed, as the model discovers patterns on its own.

![initial](https://github.com/lastime1650/VATEX_EVIDENTIA_EDR/blob/master/EDR_ML_INTRODUCE_7.PNG)

<br>

### 2. Threat Intelligence & Utilities


![initial](https://github.com/lastime1650/VateX/blob/mainv2/images/VATEX_INTELLINA.png)

Combining with [**VATEX INTELINA**](https://github.com/lastime1650/VATEX_INTELLINA_INTELLIGENCE), we collect very rich latest threat intelligence and metadata information.

---

## Supported Platforms

Our Kernel Agent is designed for modern operating systems:

-   **[Windows](https://github.com/lastime1650/VATEX_EVIDENTIA_EDR/tree/Windows)**: WDK-based driver `(supports 22H2 or newer)`
-   **[Linux](https://github.com/lastime1650/VATEX_EVIDENTIA_EDR/tree/Linux)**: eBPF-based instrumentation `(requires Kernel 6.10 or newer)`

---

## Future Roadmap

We are committed to continuous improvement. Our current focus is on expanding detection capabilities through advanced research and performing extensive testing to ensure the solution is robust, stable, and effective against emerging threats.