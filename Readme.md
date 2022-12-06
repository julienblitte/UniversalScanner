# What is Universal Network Scanner
*Universal Network Scanner* is a multi-brand ultra-fast network discovery tool based on multicast and broadcast discovery. 
This network discovery scanner is implemented based on a flexible framework to ease implementation of any vanilla discovery IP protocol such as SSDP/UPnP, mDNS, proprietary discovery protocols, etc. 

# Licence
This application and all the source code is released under licence LGPL 3.0.
You can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
You can refer to the license content at this link: https://www.gnu.org/licenses/lgpl-3.0.html

# Legal notice
All the implementation is done during my free time and are my own work and released under the above LGPL license.
All protocols are analysed by reverse engineering in territory of French Republic (France), by observation of network packet traffic and without any decompilation of code, in order to aim of system interoperability.
All trademarks are the property of their respective owners.

# Warranty
This tool is delivered as it, without any warranty. If you want specific support, or specific version, contact me.

# Protocols supported
## Generic protocols
* [x] SSDP (UPnP)
* [x] WS-Discovery (ONVIF)
* [x] DNS-SD (Zeroconf)
* [x] GigE Vision

## Proprietary protocols
* [x] Dahua camera discovery protocol
* [x] Hikvision discovery protocol
* [x] Axis discovery protocol
* [x] Bosch discovery protocol
* [x] Google cast discovery protocol
* [x] Hanwha (Samsung) discovery protocol
* [x] Vivotek discovery protocol
* [x] Sony discovery protocol
* [x] 360Vision discovery protocol
* [x] NiceVision discovery protocol
* [x] Panasonic discovery protocol
* [x] Arecont discovery protocol
* [x] Ubiquiti discovery protocol
* [x] VStarCam discovery protocol
* [x] Eaton discovery protocol
* [x] Microchip discovery protocol
* [x] Advantech discovery protocol
* [x] Lantronix discovery protocol
* [x] Eden Optima Box discovery protocol
* [x] CyberPower discovery protocol

## Vendors supported by design
* 👌 Uniview: WS-Discovery
* 👌 Flir: SSDP and GigE Vision
* 👌 Siqura: SSDP and WS-Discovery
* 👌 Mobotix: WS-Discovery
* 👌 GCE Electronics: Microchip (enhanced)
* 👌 ELA Access Control: Microchip
* 👌 Vauban Access Control: Lantronix
* 👌 Eden Access Control (sub-controller): Lantronix

## Protocols in implementation
* [ ] Foscam discovery protocol
* [ ] Dlink discovery protocol
* [ ] Hid discovery protocol

## Currently looking for
* 👀 Looking for a 2N device owner

## Protocol compare
Detailed list in the file [doc/protocols.html](https://htmlpreview.github.io/?https://github.com/julienblitte/UniversalScanner/blob/master/doc/protocols.html)

# Advanced tweaking
Some advanced settings can be changed in the registry on variables under the key ```HKEY_CURRENT_USER\Software\UniversalScanner```

value                        | description
-----------------------------|--------------------------------------------------------------------------
```enableIPv6```             | enables ipv6 for protocols supporting it
```forceGenericProtocols```  | shows all protocols found on each device
```forceZeroConf```          | shows ZeroConf secondary ip address of device 
```onvifVerbatim```          | failback to ONVIF Device Manager dump for WSDiscovery payload
```debugMode```              | enable advanced log and network collection system
```dahuaNetScan```           | Dahua subnet exhaustive scan for broken firmware (mainly Thermal cameras)

# Participate
If you own some device that are currently in the implementation list, you can contact me if you want to help for technical tests.
If you want to propose a new protocol, you can send me relevant data following this [procedure](https://github.com/julienblitte/UniversalScanner/blob/master/doc/Collect%20data%20for%20new%20protocol.docx).

**Current helps is wanted for: Foscam cameras, Dlink cameras, Hid access control, Lantronix device (such as Vauban acces control)**.

If you have such devices, and are happy to help, please contact me.

# Greetings
Thank you to:
* http://ipcamtalk.com forum users,
* http://ipvm.com forum users,
* Patrick Gorce
* Geza Gyorfi,
* John Honovich,
* Nathan Lafontaine,
* Brian Rhodes,
* John Scanlan,
* Alastair Stevenson,
* Patrick Vielle,
* And all other contributors
