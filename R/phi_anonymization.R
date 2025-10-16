#' PHI Anonymization Functions
#'
#' Functions for anonymizing Protected Health Information based on risk levels.
#' Implements statistical disclosure control strategies appropriate for each
#' risk category.

#' Anonymize data based on PHI risk levels
#'
#' Applies different anonymization strategies to each column based on its
#' detected PHI risk level. This is the main entry point for anonymization.
#'
#' @param data Data frame to anonymize
#' @param structure_info PHI structure metadata from detect_phi_in_data()
#' @param strategies Optional named list of custom anonymization strategies
#' @return List with two elements:
#'   - data: Anonymized data frame
#'   - log: Named list documenting anonymization methods applied
#' @export
#' @examples
#' df <- data.frame(
#'   Pat_ID1 = 1:5,
#'   LAST_NAME = c("Smith", "Jones", "Brown", "Davis", "Wilson"),
#'   Age = c(45, 52, 38, 61, 29)
#' )
#' structure <- detect_phi_in_data(df)
#' result <- anonymize_data(df, structure)
#' result$data  # Anonymized data
#' result$log   # Audit log
anonymize_data <- function(data, structure_info, strategies = NULL) {
  if (nrow(data) == 0) {
    message("No data to anonymize")
    return(list(data = data, log = list()))
  }

  if (!is.data.frame(structure_info) || !"risk_level" %in% names(structure_info)) {
    stop("structure_info must be output from detect_phi_in_data()")
  }

  message(sprintf("Anonymizing %d rows...", nrow(data)))
  anonymized_data <- data
  anonymization_log <- list()

  # Get PHI columns by risk level
  phi_cols <- structure_info |>
    dplyr::filter(phi == TRUE) |>
    dplyr::select(column, risk_level, phi_reason, r_type)

  if (nrow(phi_cols) == 0) {
    message("  No PHI columns detected - returning original data")
    return(list(data = anonymized_data, log = anonymization_log))
  }

  message(sprintf("  Found %d PHI columns to anonymize", nrow(phi_cols)))

  for (i in 1:nrow(phi_cols)) {
    col_name <- phi_cols$column[i]
    risk_level <- phi_cols$risk_level[i]
    reason <- phi_cols$phi_reason[i]
    r_type <- phi_cols$r_type[i]

    if (!col_name %in% names(anonymized_data)) {
      next  # Column not in actual data
    }

    # Apply anonymization by risk level
    if (risk_level == "HIGH") {
      anonymized_data <- anonymize_high_risk(anonymized_data, col_name, r_type, reason)
      anonymization_log[[col_name]] <- list(
        risk = "HIGH",
        method = "Suppression/Synthetic",
        reason = reason
      )

    } else if (risk_level == "MEDIUM") {
      anonymized_data <- anonymize_medium_risk(anonymized_data, col_name, r_type, reason)
      anonymization_log[[col_name]] <- list(
        risk = "MEDIUM",
        method = "Generalization/Perturbation",
        reason = reason
      )

    } else if (risk_level == "LOW") {
      anonymized_data <- anonymize_low_risk(anonymized_data, col_name, r_type, reason)
      anonymization_log[[col_name]] <- list(
        risk = "LOW",
        method = "Minimal noise",
        reason = reason
      )
    }
  }

  list(data = anonymized_data, log = anonymization_log)
}

#' High-risk anonymization: suppress or replace with synthetic data
#'
#' Applies aggressive anonymization for direct identifiers like names, SSNs,
#' contact information, and dates of birth.
#'
#' @param data Data frame to anonymize
#' @param col_name Column name to anonymize
#' @param r_type R data type of the column
#' @param reason PHI reason from detection
#' @return Data frame with anonymized column
#' @keywords internal
anonymize_high_risk <- function(data, col_name, r_type, reason) {
  if (stringr::str_detect(reason, "name|Name")) {
    # Replace names with synthetic ones
    n_unique <- length(unique(data[[col_name]]))
    synthetic_names <- paste0("Person_", sprintf("%03d", 1:n_unique))
    data[[col_name]] <- factor(synthetic_names[as.numeric(as.factor(data[[col_name]]))])

  } else if (stringr::str_detect(reason, "record number|identifier|ID")) {
    # Replace IDs with sequential synthetic IDs
    data[[col_name]] <- paste0("ID_", sprintf("%06d", 1:nrow(data)))

  } else if (stringr::str_detect(reason, "birth|date of birth")) {
    # Generalize birth dates to year only with noise
    if (r_type %in% c("POSIXct", "Date")) {
      years <- as.numeric(format(data[[col_name]], "%Y"))
      # Add random noise of +/- 1-3 years
      noisy_years <- years + sample(-3:3, length(years), replace = TRUE)
      data[[col_name]] <- as.Date(paste0(noisy_years, "-01-01"))
    }

  } else if (stringr::str_detect(reason, "phone|Phone")) {
    # Replace with format-preserving fake numbers
    data[[col_name]] <- "555-0000"

  } else if (stringr::str_detect(reason, "email|Email")) {
    # Replace with generic email
    data[[col_name]] <- "anonymous@example.com"

  } else if (stringr::str_detect(reason, "address|Address")) {
    # Replace with generic address
    data[[col_name]] <- "123 Privacy St"

  } else if (stringr::str_detect(reason, "notes|Notes")) {
    # Replace free text with placeholder
    data[[col_name]] <- "[REDACTED TEXT]"

  } else {
    # Default: suppress (set to NA)
    data[[col_name]] <- NA
  }

  data
}

#' Medium-risk anonymization: generalization and controlled perturbation
#'
#' Applies moderate anonymization for geographic info, account IDs, and
#' other semi-identifying information.
#'
#' @param data Data frame to anonymize
#' @param col_name Column name to anonymize
#' @param r_type R data type of the column
#' @param reason PHI reason from detection
#' @return Data frame with anonymized column
#' @keywords internal
anonymize_medium_risk <- function(data, col_name, r_type, reason) {
  if (stringr::str_detect(reason, "geographic|location")) {
    # Generalize geographic info
    if (r_type == "character") {
      # For states/cities, keep but add some noise by random sampling
      unique_vals <- unique(data[[col_name]])
      if (length(unique_vals) > 5) {
        # Replace some with "Various"
        mask <- sample(c(TRUE, FALSE), nrow(data), replace = TRUE, prob = c(0.3, 0.7))
        data[[col_name]][mask] <- "Various"
      }
    }

  } else if (stringr::str_detect(reason, "account|Account")) {
    # Hash account identifiers
    data[[col_name]] <- paste0("ACCT_", sprintf("%08d", abs(as.numeric(as.factor(data[[col_name]])))))

  } else if (stringr::str_detect(reason, "initials|Initials")) {
    # Replace initials with generic ones
    data[[col_name]] <- "A.B."

  } else {
    # Default: add some controlled noise for numeric, generalize for character
    if (r_type %in% c("numeric", "integer")) {
      data[[col_name]] <- data[[col_name]] + sample(-5:5, nrow(data), replace = TRUE)
    } else {
      # Keep first few characters only
      data[[col_name]] <- substr(data[[col_name]], 1, 3)
    }
  }

  data
}

#' Low-risk anonymization: minimal noise addition
#'
#' Applies minimal perturbation for institutional identifiers and other
#' low-risk columns.
#'
#' @param data Data frame to anonymize
#' @param col_name Column name to anonymize
#' @param r_type R data type of the column
#' @param reason PHI reason from detection
#' @return Data frame with anonymized column
#' @keywords internal
anonymize_low_risk <- function(data, col_name, r_type, reason) {
  if (r_type %in% c("numeric", "integer")) {
    # Add small random noise
    col_data <- data[[col_name]]
    col_data_clean <- col_data[!is.na(col_data)]

    if (length(col_data_clean) > 0) {
      noise_range <- max(1, abs(max(col_data_clean) * 0.01))
      noise <- runif(nrow(data), -noise_range, noise_range)
      data[[col_name]] <- data[[col_name]] + noise
    }
  }
  # For character/factor, leave mostly unchanged (already low risk)
  data
}

#' Extract anonymized sample from data
#'
#' Convenience function that combines sampling with anonymization.
#'
#' @param data Data frame or database table to sample from
#' @param sample_size Number of rows to sample
#' @param structure_info Optional pre-computed PHI structure info
#' @param rules Optional custom PHI rules
#' @param collect If data is a database table, whether to collect to memory
#' @return List with data, log, and structure_info
#' @export
#' @examples
#' df <- data.frame(
#'   Pat_ID1 = 1:100,
#'   LAST_NAME = sample(c("Smith", "Jones", "Brown"), 100, replace = TRUE),
#'   Age = sample(20:80, 100, replace = TRUE)
#' )
#' result <- extract_anonymized_sample(df, sample_size = 10)
#' result$data          # Anonymized sample
#' result$log           # Anonymization log
#' result$structure_info  # PHI detection results
extract_anonymized_sample <- function(data, sample_size = 300,
                                     structure_info = NULL,
                                     rules = NULL,
                                     collect = TRUE) {
  # Handle database tables
  if (inherits(data, "tbl_sql")) {
    if (collect) {
      sample_data <- data |>
        dplyr::head(sample_size) |>
        dplyr::collect()
    } else {
      sample_data <- data |> dplyr::head(sample_size)
    }
  } else {
    # In-memory data - take random sample
    if (nrow(data) > sample_size) {
      sample_data <- data[sample(1:nrow(data), sample_size), ]
    } else {
      sample_data <- data
    }
  }

  # Detect PHI if not provided
  if (is.null(structure_info)) {
    structure_info <- detect_phi_in_data(sample_data, rules)
  }

  # Anonymize
  anonymized_result <- anonymize_data(sample_data, structure_info)

  list(
    data = anonymized_result$data,
    log = anonymized_result$log,
    structure_info = structure_info
  )
}
