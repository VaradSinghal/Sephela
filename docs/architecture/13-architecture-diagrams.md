# Sephela: Comprehensive Architecture & Flow Diagrams

This document contains detailed architectural diagrams visualizing how Sephela ingests APKs, distributes work across analytical engines, and leverages a LangGraph-powered Multi-Agent GenAI system to generate cyber-risk reports.

## 1. High-Level System Architecture

This diagram illustrates the macro-level dependencies between the core components of the platform: the Frontend, Backend API, Message Queues, Databases, and the Asynchronous Celery Workers processing the APKs.

```mermaid
graph TB
    subgraph Client Layer
        UI[React / Next.js Dashboard]
        CLI[External API Clients]
    end

    subgraph API Layer
        FastAPI[FastAPI Backend Server]
    end

    subgraph Data & Message Broker
        PG[(PostgreSQL\nJob State & Results)]
        Redis[(Redis\nTask Queue & Broker)]
        S3[(Storage\nAPKs & Artifacts)]
    end

    subgraph Worker Layer [Celery Worker Pool]
        Worker1[Worker Node]
        Worker2[Worker Node]
        Worker1 -.-> Pipeline[Analysis Pipeline]
    end

    subgraph External Dependencies
        OR[OpenRouter / Nemotron LLM]
        OSINT[Threat Intel APIs\nVirusTotal, AbuseIPDB, URLhaus]
    end

    %% Connections
    UI -- Uploads APK / Polls Status --> FastAPI
    CLI --> FastAPI
    FastAPI -- Stores Metadata --> PG
    FastAPI -- Saves File --> S3
    FastAPI -- Enqueues Job --> Redis
    
    Redis -- Dispatches Job --> Worker1
    Worker1 -- Reads File --> S3
    Worker1 -- Updates State --> PG
    
    Pipeline -- Multi-Agent Reasoning --> OR
    Pipeline -- Enriches IOCs --> OSINT
```

---

## 2. End-to-End Pipeline Data Flow

This outlines the chronological lifecycle of an APK analysis job. Each stage produces specific evidence that acts as input for the next stage.

```mermaid
sequenceDiagram
    participant User
    participant API as FastAPI
    participant Celery
    participant Engines as Static/Dynamic/Code
    participant Threat as Threat Intel Engine
    participant Orchestrator as LangGraph AI Orchestrator
    participant Scoring as Risk Scoring
    participant DB as Postgres

    User->>API: Upload APK
    API->>DB: Create Job (Status: Pending)
    API->>Celery: Dispatch Task
    API-->>User: Return Job ID
    
    Celery->>DB: Update Status (Running)
    
    Note over Celery,Engines: Phase 1: Artifact Extraction
    Celery->>Engines: Trigger Static Analysis (JADX)
    Engines-->>Celery: JADX Tree, Manifest, Strings, Secrets
    
    Celery->>Engines: Trigger Code Intelligence
    Engines-->>Celery: Filtered AST, High-Signal Patterns
    
    Celery->>Engines: Trigger Dynamic Analysis (KVM)
    Engines-->>Celery: Network PCAPs, IPC calls, File changes
    
    Note over Celery,Threat: Phase 2: Enrichment
    Celery->>Threat: Feed all Extracted IPs, Domains, URLs
    Threat->>Threat: Round-Robin Load Balance to Providers
    Threat-->>Celery: IOC Reputation & Malicious Flags
    
    Note over Celery,Orchestrator: Phase 3: AI Reasoning
    Celery->>Orchestrator: Send all Evidence to AI
    Orchestrator->>Orchestrator: Execute 6 Parallel Agents
    Orchestrator-->>Celery: Correlated Narrative & Validated Findings
    
    Note over Celery,Scoring: Phase 4: Scoring & Reporting
    Celery->>Scoring: Feed Evidence & AI Findings
    Scoring-->>Celery: Deterministic 0-100 Risk Score
    
    Celery->>Celery: Generate Report (HTML, JSON, Markdown, SARIF)
    Celery->>DB: Update Status (Completed) & Store Results
    
    User->>API: Fetch Report
    API->>User: Download Report Files
```

---

## 3. LangGraph Multi-Agent Orchestration

Sephela uses **LangGraph** to manage a complex multi-agent reasoning workflow. Instead of using one massive prompt, the system spins up 6 specialized LLM agents that run **in parallel**. They independently evaluate their specific domain before the pipeline converges.

```mermaid
stateDiagram-v2
    [*] --> StartNode

    state "Data Injection" as StartNode {
        direction LR
        GatherEvidence : Collect outputs from Static, Code, Dynamic, Threat Intel
    }

    StartNode --> ParallelExecution : Dispatch Evidence

    state "Parallel Agent Execution (LangGraph)" as ParallelExecution {
        direction TB
        
        state "Manifest Agent" as Manifest
        state "Permission Agent" as Permission
        state "Code Pattern Agent" as Code
        state "API Analysis Agent" as API
        state "Network / C2 Agent" as Network
        state "Threat Intel Agent" as Threat

        Manifest : Evaluates components, intents, hidden entrypoints
        Permission : Analyzes over-privileged requests & abuse potential
        Code : Looks for evasion, packers, cryptography, dynamic loading
        API : Reviews dangerous Android API calls (SMS, Contacts, etc.)
        Network : Correlates PCAPs with known bad infrastructure
        Threat : Explains OSINT findings and IOC verdicts
    }

    ParallelExecution --> PydanticValidation : Agent Responses

    state "Validation Layer" as PydanticValidation {
        direction LR
        SchemaCheck : Validate Schema
        Repair : Auto-Repair JSON
        ProvenanceCheck : Ensure findings cite actual evidence (No Hallucinations)
    }
    
    PydanticValidation --> Convergence : Validated Findings

    state "Convergence & Scoring" as Convergence {
        direction LR
        Aggregate : Merge all Agent Findings
        Score : Calculate Final 0-100 Risk Score
    }

    Convergence --> ReportNode

    state "Reporting Agent" as ReportNode {
        direction LR
        Draft : Generate Executive Summary
        Format : Compile Markdown & Export
    }

    ReportNode --> [*]

    %% Styles for emphasis
    classDef llm fill:#4a148c,stroke:#ab47bc,stroke-width:2px,color:#fff;
    class Manifest,Permission,Code,API,Network,Threat,ReportNode llm;
```

---

## 4. Threat Intel Engine: Data Flow & Load Balancing

This diagram details the inner workings of the Threat Intel engine, specifically highlighting the custom round-robin load balancer implemented to distribute indicators across OSINT APIs and bypass rate limits.

```mermaid
graph TD
    A[Input: Raw Indicators from Static & Dynamic] --> B[Deduplication & Expansion]
    
    B -->|URLs, IPs, Domains, Hashes| C{Indicator Router / Load Balancer}
    
    C -- Random Assignment --> D[VirusTotal Engine]
    C -- Random Assignment --> E[AbuseIPDB Engine]
    C -- Random Assignment --> F[URLHaus Engine]
    
    D --> |URLs, IPs, Domains, Hashes| G{OSINT APIs}
    E --> |IPs only| G
    F --> |URLs, Domains, IPs| G
    
    G --> H[Consolidate Responses]
    
    H --> I[Reconciliation & Scoring]
    I -->|Calculate Malicious Ratio| J[Determine IOC Verdicts: Benign, Suspicious, Malicious]
    
    J --> K[Format Envelope]
    K --> L[Force Status.ok]
    L --> M[Output: Threat Intel Evidence to AI]
    
    %% Colors
    classDef engine fill:#004d40,stroke:#80cbc4,stroke-width:2px,color:#fff;
    class D,E,F engine;
```

---

## 5. Dependency Diagram

A structural view of the libraries and technologies driving the platform.

```mermaid
graph LR
    subgraph Frontend
        React
        NextJS
        TailwindCSS
    end

    subgraph Backend Core
        FastAPI
        Celery
        SQLAlchemy
        Pydantic
    end
    
    subgraph AI Subsystem
        LangGraph
        LangChain
        OpenRouter[OpenRouter API]
        Nemotron[Nvidia Nemotron Model]
    end
    
    subgraph Analysis Engines
        JADX[JADX Decompiler]
        Androguard[Androguard]
        Weasyprint[Weasyprint PDF]
    end
    
    subgraph Infrastructure
        Postgres[(Postgres 16)]
        Redis[(Redis 7)]
        Prometheus[Prometheus Metrics]
        Grafana[Grafana Dashboards]
    end
    
    Backend Core --> AI Subsystem
    Backend Core --> Analysis Engines
    Backend Core --> Infrastructure
    Frontend --> Backend Core
    
    LangGraph --> LangChain
    LangChain --> OpenRouter
    OpenRouter --> Nemotron
```
