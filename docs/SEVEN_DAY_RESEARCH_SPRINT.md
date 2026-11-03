# Group 9: Seven-Day Research and Submission Sprint

## Working rule

The group must understand the work well enough to defend it. The prototype, literature review and experiments are parallel workstreams with daily integration. Do not fabricate measurements, paper findings or screenshots.

## Day 1 — Establish shared foundations and research question

**Whole team**
- Read `RESEARCH_FOUNDATIONS_AND_TEAM_LEARNING.md`.
- Hold a 60–90 minute whiteboard session: OS architecture, kernel/user space, processes, permissions, services, networking and logging.
- Agree on exact VM versions, project scope, control definitions and safe test boundaries.

**Deliverables**
- One-page concept map of an OS and its security boundaries.
- Agreed research problem, aim, objectives and research questions.
- Environment register (host OS, VM OS/version, resources, snapshots).

## Day 2 — Literature review and standards

Assign one candidate paper to each member. The seventh candidate is a reserve/replacement, not a reason to weaken verification. Each reader produces a structured critical review using the guide. A second member checks the DOI and bibliographic metadata.

**Deliverables**
- Six verified paper-review sheets (or a clearly documented replacement where a candidate cannot be verified).
- Comparative literature matrix: problem, method, data, evaluation, findings, strengths, limitations, relevance.
- Standards mapping for firewall, patching, least privilege and logging.

## Day 3 — Research gap and system design

**Whole team**
- Compare papers and existing tool capabilities.
- Define the exact contribution without claiming novelty beyond evidence.
- Agree on assessment criteria and what PASS, FAIL, UNKNOWN and NOT_APPLICABLE mean.
- Review the architecture, workflow and experimental protocol.

**Deliverables**
- Research-gap argument supported by sources.
- Architecture and workflow diagrams.
- Functional/non-functional requirements.
- Eight test-case protocols (four controls per OS), with expected evidence and independent verification commands.

## Day 4 — Prototype integration and controlled baseline

- Freeze feature scope; no cosmetic feature expansion.
- Pull the agreed GitHub branch and run compile/tests.
- Capture baseline inventory and control assessments in both VMs.
- Record tool failures and environmental differences.

**Deliverables**
- Reproducible setup instructions.
- Baseline evidence pack.
- Test log showing command, timestamp, output, result and operator.
- Known limitations list.

## Day 5 — Controlled experiments and verification

- Snapshot both VMs.
- Apply only safe, reversible changes that are part of the approved protocol.
- Run automated assessment and independent native verification.
- Restore/remediate and reassess.
- Record incomplete or failed experiments honestly.

**Deliverables**
- Completed experiment matrix.
- Raw result files and screenshots where useful.
- Before/after evidence.
- Calculated metrics only from recorded observations.

## Day 6 — Analysis and report

- Compare automated outcomes with independent verification.
- Calculate detection rate, false-positive rate, agreement, remediation success and execution time only where denominators and ground truth are defined.
- Discuss limitations, threats to validity and differences between OS environments.
- Draft report and presentation.

**Deliverables**
- Results tables and charts based on actual evidence.
- Complete report draft.
- Presentation slides and demonstration sequence.

## Day 7 — Rehearsal, audit and submission

- Every member explains one OS concept, one paper, one control and one limitation.
- Re-run the demonstration from a clean documented state.
- Check citations, DOI links, figure/table numbering, page count and names.
- Remove unsupported claims and clearly label any unperformed experiment.
- Submit source code, report and presentation according to lecturer instructions.

## Role allocation

| Member | Primary responsibility | Required cross-check |
|---|---|---|
| John Emmanuel Sani | Research integration, architecture, final technical coherence | Must understand every module and defend research gap |
| Okezue Vivian Adaugo | Literature matrix and methodology coordination | Verify claims against original papers |
| Nyam Nomdora Micheal | Windows VM experiments and native verification | Another member independently reviews evidence |
| David Genesis | Linux VM experiments and native verification | Another member independently reviews evidence |
| Christian Zaphaniah | Prototype tests, evidence records and result tables | Verify test denominators and reproducibility |
| Laban Abraham | Report figures, references and presentation/demo coordination | Cross-check technical accuracy with implementers |

Roles are ownership assignments, not silos. Every member reads the foundations guide and participates in the final rehearsal.

## Metrics: definitions before calculation

- **Detection rate (sensitivity):** correctly identified deliberately introduced, in-scope non-compliant test conditions divided by all such ground-truth conditions tested.
- **False-positive rate:** compliant test conditions incorrectly reported as non-compliant divided by all compliant conditions tested.
- **Independent verification agreement:** automated outcomes that agree with the independently established state divided by all comparable evaluated outcomes. Report UNKNOWN and non-comparable cases separately.
- **Remediation success rate:** test cases restored to the defined compliant state and confirmed independently divided by test cases for which remediation was attempted.
- **Execution time:** elapsed time from assessment start to completion, measured consistently and reported per OS/control and as a summary.

Do not use the word "accuracy" without defining the denominator and ground-truth procedure. A small convenience test set cannot support broad claims about all Windows or Linux systems.

## Submission integrity checklist

- [ ] Actual papers verified and read; metadata and DOI checked.
- [ ] Research gap supported by literature, not invented.
- [ ] Criteria and expected states defined before experiments.
- [ ] Windows and Linux versions documented.
- [ ] Raw evidence retained and anonymised where appropriate.
- [ ] No simulated values presented as measured results.
- [ ] Every chart/table traceable to recorded observations.
- [ ] Limitations and unperformed tests explicitly stated.
- [ ] Every member can explain the project, not just their assigned section.
