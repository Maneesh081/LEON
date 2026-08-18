# LEON Development Plan

## Project Vision

**LEON (Learning and Explaining Offensive-Network Patterns)** is a
Real-Time Explainable AI Intrusion Detection and Prevention System
(XAI-IDPS). It captures live network traffic, converts packets into
network flows, extracts machine-learning features, detects attacks,
explains every prediction using SHAP, makes intelligent security
decisions, and optionally blocks malicious traffic using Windows
Firewall.

------------------------------------------------------------------------

# Final Architecture

    Internet
        │
        ▼
    Packet Capture
        │
        ▼
    Flow Builder
        │
        ▼
    Feature Extraction
        │
        ▼
    Feature Normalization
        │
        ▼
    Machine Learning
        │
        ▼
    SHAP Explainability
        │
        ▼
    NGFW Decision Engine
        │
        ▼
    IPS Blocking
        │
        ▼
    Dashboard + Logging

------------------------------------------------------------------------

# Key Design Changes

## 1. Build Flows Instead of Classifying Individual Packets

Packets are grouped into flows using the 5-tuple:

-   Source IP
-   Destination IP
-   Source Port
-   Destination Port
-   Protocol

Each flow is summarized into statistics before being classified.

------------------------------------------------------------------------

## 2. Match Live Features to the Training Data

Instead of trying to imitate every CICIDS2017 feature in real time:

1.  Design LEON's own flow feature set.
2.  Extract the same features from live traffic.
3.  Preprocess CICIDS2017 so it contains only those same features.
4.  Train the ML model on the processed dataset.

This guarantees the training and live feature vectors match.

------------------------------------------------------------------------

## 3. Suggested Feature Set

-   Flow Duration
-   Protocol
-   Destination Port
-   Total Forward Packets
-   Total Backward Packets
-   Total Forward Bytes
-   Total Backward Bytes
-   Packets per Second
-   Bytes per Second
-   Average Packet Size
-   Packet Length Mean
-   Packet Length Standard Deviation
-   SYN Count
-   ACK Count
-   FIN Count
-   RST Count
-   Flow Inter-arrival Time

------------------------------------------------------------------------

## 4. Machine Learning

Primary Model: - Random Forest

Comparison: - XGBoost

Optional: - Isolation Forest (future)

Outputs: - Attack Type - Confidence Score

------------------------------------------------------------------------

## 5. Explainable AI

Use SHAP as the primary explainability framework.

For every prediction display: - Most important features - Feature
contribution - Confidence score

LIME can be discussed in the report as future work or comparison.

------------------------------------------------------------------------

## 6. NGFW Decision Layer

Decision inputs: - Predicted attack - Confidence threshold - Whitelist -
Future: attack history - Future: internal/external host

Actions: - Allow - Alert - Block

------------------------------------------------------------------------

## 7. IPS

If blocking is selected:

-   Create Windows Firewall rule
-   Block attacker IP
-   Record event
-   Continue monitoring

------------------------------------------------------------------------

## 8. Dashboard

Display:

-   Live packets
-   Active flows
-   Flow statistics
-   ML prediction
-   SHAP explanation
-   Confidence score
-   NGFW decision
-   Blocked IPs
-   Attack timeline
-   Logs

------------------------------------------------------------------------

# Suggested Development Order

1.  Packet Capture
2.  Flow Builder
3.  Feature Extraction
4.  Feature Normalization
5.  Preprocess CICIDS2017
6.  Train Random Forest
7.  Test Model Offline
8.  Live Detection
9.  SHAP Integration
10. NGFW Decision Engine
11. IPS Blocking
12. Dashboard
13. Final Testing

------------------------------------------------------------------------

# Testing Plan

## Stage 1 --- Packet Capture

Verify packets are captured correctly.

## Stage 2 --- Flow Builder

Ensure packets are grouped into correct flows.

## Stage 3 --- Feature Extraction

Compare generated features with expected values.

## Stage 4 --- Offline ML

Run processed CICIDS2017 samples through the trained model.

Verify: - Accuracy - Precision - Recall - F1-score

## Stage 5 --- Live Detection

Run LEON while generating normal traffic in a controlled lab and verify
predictions.

## Stage 6 --- Controlled Attack Demonstration

Use only systems you own or have permission to test.

Examples: - SYN flood simulation - UDP flood simulation - Port scan -
High-volume HTTP requests to your lab web server

Verify: - Attack detected - Confidence displayed - SHAP explanation
generated - Dashboard updated - Logs written

## Stage 7 --- IPS

Enable IPS.

Verify: - Decision engine recommends blocking - Firewall rule is
created - Subsequent traffic from the blocked source is prevented

------------------------------------------------------------------------

# Expected End-to-End Workflow

    Traffic
        ↓
    Packet Capture
        ↓
    Flow Builder
        ↓
    Feature Extraction
        ↓
    Feature Normalization
        ↓
    Random Forest
        ↓
    SHAP
        ↓
    NGFW Decision
        ↓
    Allow / Alert / Block
        ↓
    Dashboard + Logs

------------------------------------------------------------------------

# Goal

Create a professional, modular, explainable IDS/IPS that demonstrates
real-time network monitoring, machine-learning-based attack detection,
explainable AI, intelligent decision making, and automated prevention in
a controlled laboratory environment.
