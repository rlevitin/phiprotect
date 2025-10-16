# Installation Guide for phiprotect

## Prerequisites

Before installing `phiprotect`, ensure you have:
- R >= 4.0.0
- RStudio (recommended)
- devtools or remotes package

## Installation Steps

### 1. Install Dependencies

```r
# Required packages
install.packages(c("dplyr", "stringr", "purrr", "tibble", "readr"))

# Optional packages (for full functionality)
install.packages(c("arrow", "DBI", "dbplyr", "testthat"))
```

### 2. Install phiprotect

```r
# Option 1: Install from local directory
devtools::install("C:/Users/rlevi/OneDrive/Code/MosaiqDash/phiprotect")

# Option 2: Using remotes
remotes::install_local("C:/Users/rlevi/OneDrive/Code/MosaiqDash/phiprotect")
```

### 3. Verify Installation

```r
library(phiprotect)

# Check version
phiprotect_version()

# Run a quick test
df <- data.frame(
  Pat_ID1 = 1:5,
  LAST_NAME = c("Smith", "Jones", "Brown", "Davis", "Wilson"),
  Age = c(45, 52, 38, 61, 29)
)

structure <- detect_phi_in_data(df)
print(structure)
```

## Running Tests

To verify the package is working correctly:

```r
# Load the package
library(phiprotect)
library(testthat)

# Run all tests
test_dir("tests/testthat")
```

## Troubleshooting

### Issue: Cannot load package

**Solution**: Make sure all dependencies are installed:
```r
install.packages(c("dplyr", "stringr", "purrr", "tibble", "readr"))
```

### Issue: Tests failing

**Solution**: Update to latest package versions:
```r
update.packages(ask = FALSE)
```

### Issue: Arrow/Parquet errors

**Solution**: Install arrow package:
```r
install.packages("arrow")
```

## Next Steps

After installation:
1. Read the README.md for usage examples
2. Check function documentation with `?function_name`
3. Review the test files for real-world examples
4. Customize PHI rules for your organization if needed

## Updating phiprotect

To update to a newer version:

```r
# Reinstall from local directory
devtools::install("C:/Users/rlevi/OneDrive/Code/MosaiqDash/phiprotect", force = TRUE)
```

## Integration with MosaiqDash

To use phiprotect in your MosaiqDash project:

```r
# In your MosaiqDash scripts
library(phiprotect)

# Replace direct calls to flag_phi with:
result <- phiprotect::flag_phi(col_name)

# Replace anonymization code with:
anonymized <- phiprotect::anonymize_data(data, structure_info)
```
