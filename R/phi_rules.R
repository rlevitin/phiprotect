#' PHI Detection Rules
#'
#' This module defines the rule-based system for identifying Protected Health
#' Information (PHI) in column names. Rules are organized by risk level and
#' can be customized for different healthcare contexts.

#' Get default HIPAA PHI detection rules
#'
#' Returns a list of regex patterns mapped to PHI identification metadata.
#' Each rule includes a reason (description) and risk level classification.
#'
#' Risk levels:
#' - HIGH: Direct identifiers requiring strong anonymization
#' - MEDIUM: Likely PHI requiring moderate protection
#' - LOW: Potential PHI requiring minimal protection
#'
#' @return Named list of PHI rules, each with reason and risk level
#' @export
#' @examples
#' rules <- get_default_phi_rules()
#' names(rules)  # See all patterns
get_default_phi_rules <- function() {
  list(
    # HIGH RISK: Direct identifiers
    "(^|_)LAST(_|$)" = list(reason = "Last name", risk = "HIGH"),
    "(^|_)FIRST(_|$)" = list(reason = "First name", risk = "HIGH"),
    "NAME$" = list(reason = "Name field", risk = "HIGH"),
    "^PAT_NAME$" = list(reason = "Patient name", risk = "HIGH"),
    "^Patient_Name$" = list(reason = "Patient name", risk = "HIGH"),
    "^MRN$" = list(reason = "Medical record number", risk = "HIGH"),
    "(^|_)IDA(_|$)" = list(reason = "Medical record number (IDA)", risk = "HIGH"),
    "(^|_)IDB(_|$)" = list(reason = "Secondary MRN (IDB)", risk = "HIGH"),
    "^MED_ID$" = list(reason = "Medical record identifier", risk = "HIGH"),
    "(^|_)SSN(_|$)" = list(reason = "Social security number", risk = "HIGH"),
    "(^|_)SOCIAL(_|_SECURITY|$)" = list(reason = "Social security number", risk = "HIGH"),
    "^notes$" = list(reason = "Free-text notes", risk = "HIGH"),

    # HIGH RISK: Contact information
    "ADDRESS|ADR[0-9]" = list(reason = "Address", risk = "HIGH"),
    "PHONE|CELL|MOBILE" = list(reason = "Phone number", risk = "HIGH"),
    "EMAIL|E_MAIL" = list(reason = "Email address", risk = "HIGH"),
    "CONTACT" = list(reason = "Contact information", risk = "HIGH"),

    # HIGH RISK: Sensitive dates
    "BIRTH|DOB" = list(reason = "Date of birth", risk = "HIGH"),

    # MEDIUM RISK: Financial and account identifiers
    "(^|_)ACCOUNT(_|_ID|$)" = list(reason = "Account identifier", risk = "MEDIUM"),
    "BILLING|FINANCIAL" = list(reason = "Financial information", risk = "MEDIUM"),

    # MEDIUM RISK: Location and demographic details
    "CITY|STATE|POSTAL|ZIP" = list(reason = "Geographic location", risk = "MEDIUM"),
    "COUNTY|COUNTRY" = list(reason = "Geographic location", risk = "MEDIUM"),

    # MEDIUM RISK: Clinical identifiers that could be sensitive
    "(^|_)INITIALS(_|$)" = list(reason = "Personal initials", risk = "MEDIUM"),
    "PAGER|FAX" = list(reason = "Communication number", risk = "MEDIUM"),

    # LOW RISK: Institutional identifiers (less personally identifying)
    "INST_ID|INSTITUTION" = list(reason = "Institution identifier", risk = "LOW"),
    "FACILITY|FAC_ID" = list(reason = "Facility identifier", risk = "LOW"),
    "STAFF_ID|PROVIDER_ID" = list(reason = "Staff identifier", risk = "LOW"),
    "LOCATION_ID" = list(reason = "Location identifier", risk = "LOW")
  )
}

#' Load custom PHI rules from a list
#'
#' Allows you to provide custom PHI detection rules that override or extend
#' the default HIPAA rules. Useful for organization-specific identifiers.
#'
#' @param custom_rules Named list of rules in the same format as default rules
#' @param merge_with_defaults If TRUE, merge with defaults; if FALSE, replace entirely
#' @return Combined rule set
#' @export
#' @examples
#' custom <- list(
#'   "PATIENT_KEY" = list(reason = "Custom patient ID", risk = "HIGH")
#' )
#' rules <- load_custom_phi_rules(custom, merge_with_defaults = TRUE)
load_custom_phi_rules <- function(custom_rules, merge_with_defaults = TRUE) {
  if (!is.list(custom_rules)) {
    stop("custom_rules must be a list")
  }

  if (merge_with_defaults) {
    defaults <- get_default_phi_rules()
    # Custom rules override defaults
    c(defaults, custom_rules)
  } else {
    custom_rules
  }
}

#' Validate PHI rule structure
#'
#' @param rules List of PHI rules to validate
#' @return TRUE if valid, throws error otherwise
#' @keywords internal
validate_phi_rules <- function(rules) {
  if (!is.list(rules)) {
    stop("PHI rules must be a list")
  }

  for (pattern in names(rules)) {
    rule <- rules[[pattern]]
    if (!is.list(rule)) {
      stop(sprintf("Rule for pattern '%s' must be a list", pattern))
    }
    if (!"reason" %in% names(rule)) {
      stop(sprintf("Rule for pattern '%s' missing 'reason' field", pattern))
    }
    if (!"risk" %in% names(rule)) {
      stop(sprintf("Rule for pattern '%s' missing 'risk' field", pattern))
    }
    if (!rule$risk %in% c("HIGH", "MEDIUM", "LOW")) {
      stop(sprintf("Rule for pattern '%s' has invalid risk level: %s", pattern, rule$risk))
    }
  }

  TRUE
}
