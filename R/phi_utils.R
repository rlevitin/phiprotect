#' PHI Protection Utilities
#'
#' Helper functions for reporting, validation, and workflow management.

#' Generate PHI detection report
#'
#' Creates a human-readable report of PHI detection results with summary
#' statistics and column listings by risk level.
#'
#' @param structure_info PHI structure info from detect_phi_in_data()
#' @param table_name Optional name of the table being analyzed
#' @return Invisible NULL (prints report to console)
#' @export
#' @examples
#' df <- data.frame(Pat_ID1 = 1:10, LAST_NAME = letters[1:10], Age = 20:29)
#' structure <- detect_phi_in_data(df)
#' generate_phi_report(structure, "patients")
generate_phi_report <- function(structure_info, table_name = "data") {
  if (!is.data.frame(structure_info)) {
    stop("structure_info must be a data frame")
  }

  cat(sprintf("\n=== PHI Detection Report: %s ===\n", table_name))
  cat(sprintf("Total columns: %d\n", nrow(structure_info)))

  # Summary by risk level
  summary <- structure_info |>
    dplyr::group_by(risk_level) |>
    dplyr::summarise(count = dplyr::n(), .groups = "drop") |>
    dplyr::arrange(dplyr::desc(risk_level))

  cat("\nRisk Level Summary:\n")
  for (i in 1:nrow(summary)) {
    cat(sprintf("  %s: %d columns\n", summary$risk_level[i], summary$count[i]))
  }

  # List columns by risk level
  for (risk in c("HIGH", "MEDIUM", "LOW", "NONE")) {
    cols <- structure_info |>
      dplyr::filter(risk_level == risk)

    if (nrow(cols) > 0) {
      cat(sprintf("\n%s RISK columns (%d):\n", risk, nrow(cols)))
      for (j in 1:nrow(cols)) {
        phi_mark <- ifelse(cols$phi[j], sprintf(" [%s]", cols$phi_reason[j]), "")
        cat(sprintf("  - %s (%s)%s\n", cols$column[j], cols$r_type[j], phi_mark))
      }
    }
  }

  cat("\n")
  invisible(NULL)
}

#' Generate anonymization audit log
#'
#' Creates a human-readable audit log documenting all anonymization methods
#' applied to PHI columns.
#'
#' @param anonymization_log Log from anonymize_data()
#' @param table_name Optional name of the table
#' @return Invisible NULL (prints log to console)
#' @export
#' @examples
#' df <- data.frame(Pat_ID1 = 1:5, LAST_NAME = c("Smith", "Jones", "Brown", "Davis", "Wilson"))
#' structure <- detect_phi_in_data(df)
#' result <- anonymize_data(df, structure)
#' generate_anonymization_audit_log(result$log, "patients")
generate_anonymization_audit_log <- function(anonymization_log, table_name = "data") {
  if (!is.list(anonymization_log)) {
    stop("anonymization_log must be a list")
  }

  cat(sprintf("\n=== Anonymization Audit Log: %s ===\n", table_name))
  cat(sprintf("Columns anonymized: %d\n\n", length(anonymization_log)))

  if (length(anonymization_log) == 0) {
    cat("No columns were anonymized.\n\n")
    return(invisible(NULL))
  }

  for (col_name in names(anonymization_log)) {
    log_entry <- anonymization_log[[col_name]]
    cat(sprintf("Column: %s\n", col_name))
    cat(sprintf("  Risk Level: %s\n", log_entry$risk))
    cat(sprintf("  Method: %s\n", log_entry$method))
    cat(sprintf("  Reason: %s\n\n", log_entry$reason))
  }

  invisible(NULL)
}

#' Save PHI structure to CSV
#'
#' Exports PHI detection results to a CSV file for documentation and review.
#'
#' @param structure_info PHI structure info from detect_phi_in_data()
#' @param output_path File path for CSV output
#' @param table_name Optional table name to include in the output
#' @return Invisible NULL
#' @export
#' @examples
#' \dontrun{
#' df <- data.frame(Pat_ID1 = 1:10, LAST_NAME = letters[1:10])
#' structure <- detect_phi_in_data(df)
#' save_phi_structure(structure, "phi_report.csv", "patients")
#' }
save_phi_structure <- function(structure_info, output_path, table_name = NULL) {
  if (!is.data.frame(structure_info)) {
    stop("structure_info must be a data frame")
  }

  output_df <- structure_info

  if (!is.null(table_name)) {
    output_df <- output_df |>
      dplyr::mutate(table = table_name, .before = 1)
  }

  readr::write_csv(output_df, output_path)
  message(sprintf("PHI structure saved to: %s", output_path))

  invisible(NULL)
}

#' Save anonymized data to file
#'
#' Exports anonymized data with automatic format detection (CSV or Parquet).
#' Parquet is recommended for larger datasets as it preserves data types and
#' is more space-efficient.
#'
#' @param anonymized_result Result from anonymize_data() or extract_anonymized_sample()
#' @param output_path File path for output (extension determines format)
#' @param format Optional explicit format: "csv" or "parquet" (auto-detected if NULL)
#' @return Invisible NULL
#' @export
#' @examples
#' \dontrun{
#' df <- data.frame(Pat_ID1 = 1:5, LAST_NAME = c("Smith", "Jones", "Brown", "Davis", "Wilson"))
#' structure <- detect_phi_in_data(df)
#' result <- anonymize_data(df, structure)
#' save_anonymized_data(result, "anonymized_sample.parquet")
#' }
save_anonymized_data <- function(anonymized_result, output_path, format = NULL) {
  if (!is.list(anonymized_result) || !"data" %in% names(anonymized_result)) {
    stop("anonymized_result must be output from anonymize_data() or extract_anonymized_sample()")
  }

  # Auto-detect format from file extension
  if (is.null(format)) {
    if (stringr::str_detect(output_path, "\\.parquet$")) {
      format <- "parquet"
    } else if (stringr::str_detect(output_path, "\\.csv$")) {
      format <- "csv"
    } else {
      format <- "csv"  # Default to CSV
      warning("Could not detect format from file extension, using CSV")
    }
  }

  # Save based on format
  if (format == "parquet") {
    if (!requireNamespace("arrow", quietly = TRUE)) {
      stop("Package 'arrow' is required for Parquet output. Install with: install.packages('arrow')")
    }
    arrow::write_parquet(anonymized_result$data, output_path)
  } else {
    readr::write_csv(anonymized_result$data, output_path)
  }

  message(sprintf("Anonymized data saved to: %s", output_path))

  # Save audit log if available
  if ("log" %in% names(anonymized_result) && length(anonymized_result$log) > 0) {
    log_path <- stringr::str_replace(output_path, "\\.(csv|parquet)$", "_audit_log.txt")
    sink(log_path)
    generate_anonymization_audit_log(anonymized_result$log)
    sink()
    message(sprintf("Audit log saved to: %s", log_path))
  }

  invisible(NULL)
}

#' Validate PHI-safe column selection
#'
#' Checks if a column selection contains only non-PHI or acceptable-risk columns.
#' Useful for validating queries before execution.
#'
#' @param column_names Character vector of column names to validate
#' @param structure_info PHI structure info from detect_phi_in_data()
#' @param max_risk Maximum acceptable risk level ("NONE", "LOW", "MEDIUM", "HIGH")
#' @param stop_on_violation If TRUE, stops with error; if FALSE, returns FALSE
#' @return TRUE if valid, FALSE or error if invalid
#' @export
#' @examples
#' df <- data.frame(Pat_ID1 = 1:10, LAST_NAME = letters[1:10], Age = 20:29)
#' structure <- detect_phi_in_data(df)
#'
#' # This will pass (Age is not PHI)
#' validate_column_selection(c("Pat_ID1", "Age"), structure, max_risk = "NONE")
#'
#' # This will fail (LAST_NAME is HIGH risk)
#' validate_column_selection(c("LAST_NAME"), structure, max_risk = "NONE", stop_on_violation = FALSE)
validate_column_selection <- function(column_names, structure_info,
                                     max_risk = "NONE",
                                     stop_on_violation = TRUE) {
  risk_order <- c("NONE", "LOW", "MEDIUM", "HIGH")
  max_risk_level <- which(risk_order == max_risk)

  if (length(max_risk_level) == 0) {
    stop("max_risk must be one of: NONE, LOW, MEDIUM, HIGH")
  }

  violations <- structure_info |>
    dplyr::filter(column %in% !!column_names) |>
    dplyr::filter(which(risk_order == risk_level) > max_risk_level)

  if (nrow(violations) > 0) {
    violation_msg <- sprintf(
      "Column selection contains %d columns exceeding max risk level '%s':\n%s",
      nrow(violations),
      max_risk,
      paste(sprintf("  - %s (%s risk: %s)", violations$column, violations$risk_level, violations$phi_reason),
            collapse = "\n")
    )

    if (stop_on_violation) {
      stop(violation_msg)
    } else {
      warning(violation_msg)
      return(FALSE)
    }
  }

  TRUE
}

#' Get phiprotect package version
#'
#' @return Character string with package version
#' @export
phiprotect_version <- function() {
  utils::packageVersion("phiprotect")
}
