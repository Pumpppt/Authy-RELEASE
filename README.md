#  Authy

<div align="center">

[![Status](https://img.shields.io/badge/Status-RELEASED-brightgreen?style=for-the-badge)]()
[![Platform](https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge)]()
[![Game](https://img.shields.io/badge/Game-Fortnite-orange?style=for-the-badge)]()

**A universal DLL auth redirect tool for Fortnite.**

</div>

---

##  Overview

**Authy** is a universal DLL authentication redirect utility designed for Fortnite. It intercepts and redirects authentication routines seamlessly across different version ranges using advanced pattern scanning and byte scanning techniques.

---

##  Features

* **Legacy Support (v1.7.2 – v31.41):** Relies on robust `FCurl` pattern scanning.
* **Modern Support (v31.41 – Latest):** Utilizes `curl_easy_setopt` combined with byte scanning—fully capable of operating even on builds with encrypted strings.
* **Universal Compatibility:** Built to handle diverse Fortnite client versions without breaking underlying auth logic flows.

---

##  Building & Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Pumpppt/Authy-RELEASE.git](https://github.com/Pumpppt/Authy-RELEASE.git)
