# User-Engaged-Network-Diagnosis

This pipeline is designed to enhance network security analysis by linking **3GPP specification inconsistencies** with **CVE records** and **user-experienced symptoms**. It primarily focuses on identifying vulnerabilities within **4G/5G mobile network protocols**. By leveraging advanced parsing techniques and **large language models (LLMs)**, the pipeline provides a preliminary exploration from protocol specifications to observable network behavior and potential security risks.

## Features

- **Specification Inconsistencies Detection**  
  Parse 4G/5G network specifications to identify conflicting segments that may lead to security vulnerabilities.

- **CVE Mapping**  
  Align identified inconsistenciess with known Common Vulnerabilities and Exposures (CVEs) to assess potential real-world risks and symptoms.

- **LLM-Enhanced Analysis**  
  Utilizes GPT-4o to enhance the extraction and interpretation of specification inconsistencies.

- **User Engagement Integration**  
  Integrate inferred symptoms to contextualize network diagnostics *(In the future, these symptoms could be replaced or complemented by real user-reported data collected from follow-up user studies.)*
  
- **Reproducible Workflows**  
  Provide Jupyter notebooks and Python scripts to support transparent, replicable research and analysis.

## Repository Structure

- `Reproduce_cellularlint_codes.ipynb`  
  Reproduce CellularLint parsing logic as a baseline for identifying inconsistencies.

- `Parser_for_Sec_conflict_Segments.ipynb`  
  Extract security-related conflict segments from 4G/5G specifications.

- `LLM_enhanced_extraction_for_spec_conflict.ipynb`  
  Apply GPT-4o to structure and normalize the extracted specification inconsistencies.

- `cve__extraction.py`  
  Crawl and structure cellular-related CVEs from online sources.

- `cve_predict_usersymptomes.ipynb`  
  Use GPT-4o to infer user-experienced symptoms based on CVE descriptions.

- `Spec_CVEs_match.ipynb`  
  Match extracted specification inconsistencies to known CVEs.

## Output Results

- `cellular_cves_from_chipsets_org_final.csv`  
  Dataset of cellular-related CVEs sourced from [chipsets.org](https://www.chipsets.org/).

- `conflict_segments_4G.txt`  
  Conflict segments extracted from 4G specifications using [CellularLint](https://github.com/ucsb-seclab/CellularLint).

- `conflict_segments_gpt_enhanced.xlsx`  
  LLM-enhanced conflict segment analysis of 4G specifications.

- `conflict_segments_normalized_extracted.csv`  
  Normalized and structured version of the conflict segment dataset.

- `cve_dataset_with_descriptions.csv`  
  Enriched CVE dataset with detailed textual descriptions from NVD.

- `cve_dataset_with_gpt4o_symptoms.csv`  
  CVE dataset augmented with GPT-4o inferred user-experienced symptoms.

- `conflict_segments_gpt_enhanced.xlsx`  
  LLM-processed version of 4G conflict segments for structured analysis.

- `conflict_segments_normalized_extracted.csv`  
  Normalized conflict segment dataset after LLM processing.

- `boosted_spec_to_cve_matches_full.csv`  
  Full mapping of all specification inconsistencies to relevant CVEs.

- `boosted_spec_to_cve_matches_top1.csv`  
  Top-1 ranked mappings between specification inconsistencies and CVEs.

- `spec_to_cve_final_high_confidence.csv`  
  Final high-confidence mapping from spec inconsistencies to CVEs and inferred user symptoms, validated by GPT-4o.
  
## Getting Started

### Prerequisites

- Python 3.10 or higher  
- Jupyter Notebook

## References

- [CellularLint: Systematic Detection of Specification Inconsistencies in Cellular Networks](https://github.com/ucsb-seclab/CellularLint)  
- [chipsets.org: Cellular Vulnerabilities Database](https://www.chipsets.org/)
