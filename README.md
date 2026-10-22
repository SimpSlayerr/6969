<div align="center">

# 🛡️ CloakBox - VM Detection Bypass

**Bypass virtual machine detection using a custom VirtualBox fork**

[![GitHub all releases](https://img.shields.io/github/downloads/Batlez/CloakBox/total?style=for-the-badge&color=0078D4)](https://github.com/Batlez/CloakBox/releases)
[![Works in 2026](https://img.shields.io/badge/Status-Works%20in%202026!-success?style=for-the-badge&color=2ea44f)](https://github.com/Batlez/CloakBox)
[![Setup Time](https://img.shields.io/badge/Setup%20Time-~30%20Mins-orange?style=for-the-badge)](https://github.com/Batlez/CloakBox)

**Created by Vektor T13 • Maintained by Batlez**

---

### 💬 Need Help?
> **⚠️ For support questions, please contact `Batlez` on Discord.**

---

### 📥 Downloads & Verification
[**📦 Download Latest Release (GitHub)**](https://github.com/Batlez/CloakBox/releases) &nbsp;|&nbsp; [**🛡️ VirusTotal Scan**](https://www.virustotal.com/gui/file/17ba6063ba20eba0ffc6538609d0cd216e015efd146e6e82e7de33e743cd8905/detection)

---

### 🎯 Verified Detection Bypass
`✅ Examity` &nbsp;•&nbsp; `✅ Respondus` &nbsp;•&nbsp; `✅ Safe Exam Browser` &nbsp;•&nbsp; `✅ ProctorU`  
`✅ Pearson VUE` &nbsp;•&nbsp; `✅ Lockdown Browser` &nbsp;•&nbsp; `✅ Honorlock` &nbsp;•&nbsp; `✅ And More!`

---

### 📸 Proof & Detection Bypass Screenshots

<details>
  <summary><b>Click to expand screenshots</b></summary>
  <br>

![image](https://github.com/Batlez/HiddenVM/assets/63690709/51e1df60-4338-4da9-b5a3-ffe61c054797)
![image](https://github.com/Batlez/HiddenVM/assets/63690709/9f3ae77a-2bea-4824-bf3f-24556fb54045)
![image](https://github.com/Batlez/HiddenVM/assets/63690709/438c960f-f712-4016-8f92-0ad2c731a8bc)
![image](https://github.com/Batlez/HiddenVM/assets/63690709/17213a48-d6f3-4f82-87ac-2cb2f6f197f4)
![image](https://github.com/Batlez/HiddenVM/assets/63690709/47acefba-842b-4493-ad16-4709b9039dbc)

</details>

---

</div>

## ⚡ Quick Start

1. **Download & Unzip CloakBox**
   - Unzip to a folder such as `C:\CloakBox`.

2. **Install CloakBox & Extension Pack**
   - Go to `CloakBox\Install Cloakbox`.
   - Run `CloakBox.exe` (as Administrator).
   - Double-click and install `Oracle_VirtualBox_Extension_Pack-7.2.4.vbox-extpack`.
   > **ℹ️ Note on "License Suspended":** The program window may show `"License Suspended"` in the title bar — don't worry! It is 100% safe to use and all features remain fully functional using the included PowerShell scripts.

3. **Configure Host & Create Your VM**
   - Open `CloakBox\Powershell Scripts\Outside-VM`.
   - Right-click `Enable PS Scripts.bat` and **Run as Administrator** (if scripts are restricted).
   - Run `Run-Outside-VM.ps1` in PowerShell. This guided tool sets up recommended disk sizing, CPUID masks, and authentic hardware/SMBIOS spoofing.

4. **Install Windows & First Boot**
   - Boot your VM and install Windows (Windows 10 or 11).
   - *Tip:* Uncheck "Enable EFI" in VM settings if creating a Legacy BIOS VM for maximum compatibility.

5. **Guest-Side Anti-Detection**
   - Inside your running VM, open `Powershell Scripts\Inside-VM`.
   - Run `Enable PS Scripts.bat` as Administrator.
   - Run `Run-Inside-VM.ps1` to apply deep guest hardening (GPU, SCSI, MAC, and registry cleaning).
   - **Restart the VM** when prompted.

6. **Verify Undetectability**
   - Inside the VM, run `VM-Checker.ps1` to view your live **Cloak Score %** and confirm all tests pass clean!
