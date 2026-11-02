# SecureState Lab: Research Foundations and Team Learning Guide

## Purpose

This guide ensures that Group 9 understands the operating-system and cybersecurity concepts behind the prototype. The application is a research instrument; building it is not a substitute for understanding the system being studied.

## 1. What is an operating system?

An operating system (OS) is system software that manages computer hardware and provides common services to application programs. It coordinates processor time, memory, storage, input/output devices, users, processes, files and network resources.

A useful mental model is that applications request services through operating-system interfaces; the OS mediates access to hardware and shared resources. The OS is not simply the desktop interface. The graphical desktop is one user-facing component.

### Core components

- **Kernel:** privileged core that manages resources and enforces fundamental isolation and access rules.
- **System calls:** controlled interfaces through which user-space programs request kernel services.
- **Processes and threads:** executing program instances and their units of execution.
- **Memory management:** allocation, address-space isolation, virtual memory and protection.
- **File systems:** organisation, storage and access control for persistent data.
- **Device drivers and I/O:** controlled interaction with hardware and peripheral devices.
- **User and permission model:** identities, groups, privileges and access decisions.
- **Services/daemons:** background processes that provide system functions.
- **Networking stack:** communication protocols, sockets, routing and filtering.
- **Logging and auditing:** records that support monitoring, troubleshooting and investigation.

## 2. How an OS works: a practical execution path

1. Firmware initialises hardware and selects a boot device.
2. A bootloader loads the operating-system kernel and required startup data.
3. The kernel initialises memory management, drivers, scheduling and core subsystems.
4. The system starts the initial user-space process and service manager.
5. Services and login/session components start.
6. A user launches an application; the OS creates a process and assigns resources and an execution context.
7. The application requests protected operations through system calls and OS services.
8. The kernel checks permissions and mediates access to memory, files, devices and networking resources.

The details differ between Windows and Linux. Do not assume that similarly named features have identical implementation or semantics.

## 3. What is cybersecurity?

Cybersecurity is the practice of protecting systems, networks, applications and information against unauthorised access, disruption, modification, disclosure and destruction.

The confidentiality, integrity and availability (CIA) model is a useful starting point:
- **Confidentiality:** information is accessible only to authorised parties.
- **Integrity:** information and system state are protected against unauthorised or improper change.
- **Availability:** systems and information remain accessible when needed.

Security is achieved through layered technical controls, secure configuration, monitoring, patching, operational processes and informed users—not through one tool.

## 4. Threat, vulnerability, exploit, risk and misconfiguration

- **Threat:** a circumstance or actor capable of causing harm.
- **Vulnerability:** a weakness in design, implementation or configuration that could be exploited or otherwise cause harm.
- **Exploit:** a method or code that takes advantage of a vulnerability.
- **Misconfiguration:** a system setting that deviates from an intended secure or operational baseline. It may create exposure, but it is not automatically a software vulnerability.
- **Attack surface:** the set of interfaces, services, accounts, components and paths through which a system may be attacked.
- **Risk:** a contextual assessment of likelihood and impact, considering threats, weaknesses, exposure and existing controls.
- **Patch:** a vendor-provided update that may fix defects, including security vulnerabilities. An installed update record does not alone prove that every relevant vulnerability is fixed.

A finding must be described precisely. For example, an enabled firewall profile is evidence about one control state; it does not prove the whole host is secure. A listening port is an exposure indicator, not proof of a vulnerability or internet reachability.

## 5. Operating-system security mechanisms

| Mechanism | Security purpose | Questions to investigate |
|---|---|---|
| Authentication | Establishes an identity | Who is allowed to sign in, and how is identity verified? |
| Authorisation and permissions | Controls what an identity can do | Are privileges limited to what is necessary? |
| Process and memory isolation | Limits interference between processes | Can one process access another process's protected memory? |
| Firewall | Filters network traffic under defined rules | Are relevant profiles enabled and policies appropriate? |
| Secure updates | Corrects known defects | Are updates available, installed and verified? |
| Logging and auditing | Records security-relevant events | Are useful events collected and retained? |
| Service management | Controls background components | Are unnecessary services exposed or running? |
| Encryption and secure boot | Protects data and boot integrity | What threats do these controls address, and what are their limits? |

## 6. Why Windows and Linux comparison is not a command comparison

Windows and Linux differ in architecture, administration, security interfaces, package/update models, identity and service management. The research should compare the **security objective and evidence quality**, not merely run equivalent-looking commands.

Examples:
- Windows firewall profiles are inspected through Windows networking/security interfaces; Linux firewall state may be managed through nftables, iptables, firewalld or distribution tooling.
- Windows installed hotfixes are not equivalent to a complete pending-update assessment.
- Linux package-manager output depends on distribution and repository state.
- Windows local Administrators membership and Linux sudo/wheel membership are not perfectly equivalent privilege models.
- Windows Event Log and Linux journald/syslog have different collection and retention behaviours.

Record OS edition, version, distribution, kernel/build, tool availability and collection errors. State where equivalence is limited.

## 7. The research problem and proposed contribution

SecureState Lab investigates a focused operational question: can a small cross-platform prototype assess selected security configuration states, preserve inspectable evidence, and help verify whether controlled remediation restores an expected state in isolated Windows and Linux environments?

The proposed contribution is an experimentally evaluated workflow joining:
1. selected control criteria;
2. platform-specific evidence collection;
3. explicit PASS/FAIL/UNKNOWN/NOT_APPLICABLE outcomes;
4. independent verification with native tools;
5. before-and-after remediation assessment.

This is not a claim that no existing scanner performs these functions. The literature review must establish what existing studies and tools already do, where their scope differs, and whether this particular evaluation offers a useful contribution.

## 8. How to read and critique a research paper

For every paper, the assigned reader must answer:

1. What problem did the authors investigate?
2. What was the research objective or question?
3. What system, dataset or population was studied?
4. What method, tools and evaluation metrics were used?
5. What were the actual findings? Quote no statistic unless it appears in the paper.
6. What are the strengths of the method?
7. What limitations do the authors acknowledge?
8. What additional limitations can be reasonably inferred from the method or scope?
9. How does the paper relate to SecureState Lab?
10. What should our team adopt, avoid or test differently?

Distinguish author-stated limitations from the group's own critical analysis. Do not label a feature absent unless the full paper supports that conclusion.

## 9. Evidence discipline

Every assessment should preserve:
- host and OS identity;
- collection time and tool/source;
- control identifier and criterion;
- raw or sufficiently detailed supporting evidence;
- result status and rationale;
- limitations, missing permissions and collection errors;
- remediation action (if any);
- independent verification evidence;
- post-remediation result.

Use UNKNOWN when evidence is insufficient. Do not convert missing evidence into PASS. Do not infer that a host is vulnerable solely from a product-name match or a listening port.

## 10. Safety and ethics

Use only systems the team owns or is authorised to assess. Perform configuration experiments in isolated virtual machines with snapshots. Keep the initial assessment read-only. Document every experimental change, preserve a rollback path, and restore the baseline. Never test disruptive changes on a personal, university or production machine.

## 11. Individual learning check

Each member should be able to explain, without reading the screen:
- what an OS and kernel do;
- user mode versus kernel mode;
- process versus service;
- authentication versus authorisation;
- vulnerability versus misconfiguration versus exploit;
- why firewall, patching, least privilege and logging matter;
- what one SecureState Lab check measures;
- what its evidence proves and does not prove;
- how an independent native-tool verification is performed;
- one limitation of the prototype and one limitation of a reviewed paper.
