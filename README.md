# Counting Flows, Not Transitions

A forecastability audit of kill-chain stage prediction, and the streaming intrusion-detection
pipeline that led to it. DSN4091 capstone.

## What is here

- `webapp/`: Streamlit website that presents the findings and runs the audits live (`streamlit run webapp/Home.py`)
- `research/`: scripts behind every number in the paper
- `streaming/`: Kafka producer and scoring service

## Datasets (not included)

CIC-IDS2017 (corrected, Engelen et al. 2021), DAPT2020 (Myneni et al. 2020), Unraveled (Myneni et al. 2023,
streamed by `research/unraveled_extract.py`), and the Ghafir et al. APT alert dataset (downloaded by
`research/ghafir_audit.py`).

## Run the website

    python -m venv .venv && source .venv/bin/activate
    pip install -r webapp/requirements.txt
    python -m streamlit run webapp/Home.py

## Authors

anvitvermaa
