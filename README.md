# [VateX – eXtend the Edge](https://github.com/lastime1650/VateX)

<div align="center">
  <img
    src="https://github.com/lastime1650/VateX/blob/main/images/VATEX.png"
    alt="VATEX LOGO"
    width="500"
  />
</div>

---

# VateX Series - VateX EVIDENTIA EDR

<div align="center">
  <img
    src="https://github.com/lastime1650/VateX/blob/mainv2/images/VATEX_EDR_RENDERED.png"
    alt="VATEX EDR"
    width="400"
  />
</div>

---

**EVIDENTIA** means *clarity* or *evidence* in Latin.
Our Endpoint Detection and Response (EDR) solution delivers crystal-clear visibility into endpoint activities, rapidly detecting and responding to threats at the device level to keep your infrastructure secure. 🛡️💻

---

## Key Components

1. **Kernel Access Agent** `(C/C++)`
2. **EDR Server** `(Python)`

> [!Note]
> ⚠️ Events collected by the Agent are sent to a `Kafka` server, so please ensure the Kafka platform is installed and running beforehand.
> **Data Flow:** Agent → Kafka → EDR

---

## Core Analysis Techniques

1. **AI & Deep Learning**
   The agent collects process tree sessions, which are analyzed and predicted using advanced deep learning techniques.

2. **Threat Intelligence & Utilities**
   Enhance detection capabilities by leveraging:

   * **Yara** (free)
   * **VirusTotal** (fee-based license)
   * **WindowsCertChecker** (free)
   * Additional intelligence and utility tools to enrich event data

---

## Supported Platforms

1. [**Windows**](https://github.com/lastime1650/VATEX_EVIDENTIA_EDR/tree/Windows) `[WDK-based 22H2 or newer]`
2. [**Linux**](https://github.com/lastime1650/VATEX_EVIDENTIA_EDR/tree/Linux) `[eBPF-based, Kernel 6.10 or newer]`

---

## Future Plans & Improvements

We continuously strive to enhance detection capabilities and are performing extensive testing to make the solution more robust.

