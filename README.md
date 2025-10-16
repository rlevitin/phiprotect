# phiprotect

> Protected Health Information Detection and Anonymization for R

`phiprotect` is an R package for detecting, classifying, and anonymizing Protected Health Information (PHI) in healthcare datasets. It implements risk-based classification following HIPAA guidelines and provides statistical disclosure control methods appropriate for each risk level.

## Features

- **Automated PHI Detection**: Pattern-based detection of PHI in column names
- **Risk-Based Classification**: Categorizes PHI as HIGH, MEDIUM, LOW, or NONE
- **Smart Anonymization**: Applies appropriate anonymization strategies based on risk level
- **Zero-Exposure Introspection**: Analyze database schemas without accessing actual PHI
- **Audit Trails**: Complete logging of all anonymization methods applied
- **Flexible Rules**: Customizable detection rules for organization-specific identifiers
- **Database Support**: Works with both in-memory data frames and database tables (via dbplyr)

## Installation

```r
# Install from local directory
devtools::install("path/to/phiprotect")

# Or install dependencies directly
install.packages(c("dplyr", "stringr", "purrr", "tibble", "readr"))

# Optional dependencies
install.packages(c("arrow", "DBI", "dbplyr"))
```

## Quick Start

### Basic PHI Detection

```r
library(phiprotect)

# Create sample data
df <- data.frame(
  Pat_ID1 = 1:10,
  LAST_NAME = c("Smith", "Jones", "Brown", "Davis", "Wilson",
                "Taylor", "Anderson", "Thomas", "Jackson", "White"),
  FIRST_NAME = c("John", "Jane", "Bob", "Alice", "Charlie",
                 "Diana", "Eve", "Frank", "Grace", "Henry"),
  Age = c(45, 52, 38, 61, 29, 44, 55, 33, 67, 41)
)

# Detect PHI in the data
structure <- detect_phi_in_data(df)
print(structure)
#   column     r_type phi   phi_reason    risk_level
#   Pat_ID1    integer FALSE              NONE
#   LAST_NAME  character TRUE  Last name    HIGH
#   FIRST_NAME character TRUE  First name   HIGH
#   Age        numeric FALSE              NONE

# Generate a readable report
generate_phi_report(structure, "patients")
```

### Anonymize Data

```r
# Anonymize the data
result <- anonymize_data(df, structure)

# View anonymized data
print(result$data)
#   Pat_ID1 LAST_NAME   FIRST_NAME Age
#   1       Person_001  Person_001  45
#   2       Person_002  Person_002  52
#   ...

# View audit log
generate_anonymization_audit_log(result$log, "patients")
```

### Extract Anonymized Sample

```r
# One-step sampling and anonymization
result <- extract_anonymized_sample(df, sample_size = 5)

# Save to file
save_anonymized_data(result, "anonymized_sample.parquet")
```

### Database Integration

```r
library(DBI)
library(dbplyr)

# Connect to database
con <- dbConnect(odbc::odbc(), ...)
patients_tbl <- tbl(con, "vw_Patient")

# Detect PHI without accessing data (0-row introspection)
structure <- describe_structure_with_phi(patients_tbl)

# Filter to safe columns only
safe_cols <- filter_columns_by_risk(structure, exclude_risk = c("HIGH", "MEDIUM"))

# Use safe columns in queries
safe_query <- patients_tbl %>%
  select(all_of(safe_cols)) %>%
  collect()
```

### Custom PHI Rules

```r
# Add organization-specific identifiers
custom_rules <- list(
  "PATIENT_KEY" = list(reason = "Custom patient ID", risk = "HIGH"),
  "DEPT_CODE" = list(reason = "Department code", risk = "LOW")
)

# Merge with defaults
rules <- load_custom_phi_rules(custom_rules, merge_with_defaults = TRUE)

# Use custom rules
structure <- detect_phi_in_data(df, rules = rules)
```

## Risk Levels and Anonymization Strategies

### HIGH Risk (Direct Identifiers)
- **Detects**: Names, SSN, MRN, birth dates, contact info, free text notes
- **Anonymization**: Suppression or synthetic data replacement
  - Names → `Person_001`, `Person_002`, etc.
  - Medical records → `ID_000001`, `ID_000002`, etc.
  - Birth dates → Year only + random noise (±1-3 years)
  - Phone → `555-0000`
  - Email → `anonymous@example.com`
  - Addresses → `123 Privacy St`

### MEDIUM Risk (Semi-Identifying)
- **Detects**: Account IDs, geographic locations, initials, financial info
- **Anonymization**: Generalization and controlled perturbation
  - Account IDs → Hashed format `ACCT_12345678`
  - Geographic locations → Partially masked or "Various"
  - Initials → Generic `A.B.`

### LOW Risk (Institutional Identifiers)
- **Detects**: Staff IDs, facility codes, institution IDs
- **Anonymization**: Minimal noise addition
  - Numeric values → Small random perturbations (±1%)
  - Character values → Mostly unchanged

## Validation and Safety

```r
# Validate that a column selection is PHI-safe
validate_column_selection(
  c("Pat_ID1", "Age"),
  structure,
  max_risk = "NONE"
)
# TRUE (passes validation)

# This would fail
validate_column_selection(
  c("LAST_NAME"),
  structure,
  max_risk = "NONE",
  stop_on_violation = FALSE
)
# FALSE (violation detected)
```

## Workflow Example

Complete workflow for extracting anonymized samples from production database:

```r
library(phiprotect)
library(DBI)

# 1. Connect to database
con <- dbConnect(odbc::odbc(), ...)

# 2. Get table reference
patients_tbl <- tbl(con, "vw_Patient")

# 3. Detect PHI structure (0-row introspection - no PHI accessed)
structure <- describe_structure_with_phi(patients_tbl)

# 4. Save structure report
save_phi_structure(structure, "data/outputs/patient_structure.csv", "vw_Patient")

# 5. Extract anonymized sample
sample_result <- extract_anonymized_sample(
  patients_tbl,
  sample_size = 300,
  structure_info = structure
)

# 6. Save anonymized data
save_anonymized_data(sample_result, "data/outputs/patient_sample.parquet")

# 7. Disconnect
dbDisconnect(con)
```

## API Reference

### Detection Functions
- `flag_phi()` - Detect PHI in a single column name
- `detect_phi_in_data()` - Detect PHI in all columns of a data frame
- `describe_structure_with_phi()` - Safe structure description with PHI flags
- `filter_columns_by_risk()` - Filter columns by risk level
- `summarize_phi_detection()` - Summarize detection results

### Anonymization Functions
- `anonymize_data()` - Anonymize data based on risk levels
- `extract_anonymized_sample()` - One-step sampling and anonymization

### Rule Management
- `get_default_phi_rules()` - Get default HIPAA PHI rules
- `load_custom_phi_rules()` - Load custom rules

### Utility Functions
- `generate_phi_report()` - Generate human-readable PHI report
- `generate_anonymization_audit_log()` - Generate audit log
- `save_phi_structure()` - Export PHI structure to CSV
- `save_anonymized_data()` - Save anonymized data (CSV or Parquet)
- `validate_column_selection()` - Validate PHI-safe column selection

## HIPAA Compliance

This package implements pattern-based detection following HIPAA Safe Harbor guidelines for the 18 identifiers:

1. Names
2. Geographic subdivisions smaller than state
3. Dates (birth, admission, discharge, death, etc.)
4. Telephone numbers
5. Fax numbers
6. Email addresses
7. Social Security numbers
8. Medical record numbers
9. Health plan beneficiary numbers
10. Account numbers
11. Certificate/license numbers
12. Vehicle identifiers
13. Device identifiers/serial numbers
14. URLs
15. IP addresses
16. Biometric identifiers
17. Full-face photos
18. Any other unique identifying characteristics

**Note**: Automated detection is a tool to assist compliance but should be reviewed by qualified personnel. Always validate PHI detection results for your specific use case.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourusername/phiprotect/issues
- Documentation: See package vignettes and function help (`?function_name`)
