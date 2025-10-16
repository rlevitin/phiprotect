#' PHI Detection Functions
#'
#' Core functions for detecting Protected Health Information (PHI) in
#' column names and data structures.

#' Detect PHI in a single column name
#'
#' Evaluates a column name against PHI detection rules and returns whether
#' it contains PHI, along with the reason and risk level.
#'
#' @param col_name Character string of the column name to evaluate
#' @param rules Optional custom PHI rules (defaults to HIPAA rules)
#' @return List with three elements:
#'   - phi: Logical, TRUE if PHI detected
#'   - reason: Character, description of why PHI was flagged
#'   - risk_level: Character, one of "HIGH", "MEDIUM", "LOW", or "NONE"
#' @export
#' @examples
#' flag_phi("LAST_NAME")
#' # $phi: TRUE, $reason: "Last name", $risk_level: "HIGH"
#'
#' flag_phi("Pat_ID1")
#' # $phi: FALSE, $reason: "", $risk_level: "NONE"
flag_phi <- function(col_name, rules = NULL) {
  if (is.null(rules)) {
    rules <- get_default_phi_rules()
  }

  nm <- toupper(col_name)

  for (pattern in names(rules)) {
    if (stringr::str_detect(nm, pattern)) {
      rule <- rules[[pattern]]
      return(list(
        phi = TRUE,
        reason = rule$reason,
        risk_level = rule$risk
      ))
    }
  }

  list(phi = FALSE, reason = "", risk_level = "NONE")
}

#' Detect PHI in all columns of a data frame
#'
#' Analyzes all column names in a data frame or tibble and returns a summary
#' data frame with PHI flags for each column.
#'
#' @param data Data frame or tibble to analyze
#' @param rules Optional custom PHI rules
#' @return Tibble with columns: column, r_type, phi, phi_reason, risk_level
#' @export
#' @examples
#' df <- data.frame(
#'   Pat_ID1 = 1:10,
#'   LAST_NAME = letters[1:10],
#'   Age = 20:29
#' )
#' detect_phi_in_data(df)
detect_phi_in_data <- function(data, rules = NULL) {
  if (!is.data.frame(data)) {
    stop("data must be a data frame or tibble")
  }

  cols <- names(data)
  types <- vapply(data, function(x) class(x)[1], character(1))

  phi_df <- purrr::map_dfr(cols, function(cn) {
    res <- flag_phi(cn, rules)
    tibble::tibble(
      column = cn,
      r_type = types[[cn]],
      phi = res$phi,
      phi_reason = res$reason,
      risk_level = res$risk_level
    )
  })

  phi_df
}

#' Describe data structure with PHI flags (0-row introspection)
#'
#' Safely describes the structure of a data frame without accessing actual
#' data values. This is the recommended approach for production databases
#' to avoid PHI exposure during analysis.
#'
#' @param data Data frame, tibble, or database table reference
#' @param rules Optional custom PHI rules
#' @param collect_sample Logical, if TRUE and data is a database table,
#'   collect 0 rows to infer types (default TRUE)
#' @return Tibble with structure metadata including PHI flags
#' @export
#' @examples
#' # For in-memory data
#' df <- data.frame(Pat_ID1 = integer(), LAST_NAME = character())
#' describe_structure_with_phi(df)
#'
#' # For database tables (requires dbplyr)
#' \dontrun{
#' con <- DBI::dbConnect(...)
#' patients_tbl <- dplyr::tbl(con, "vw_Patient")
#' describe_structure_with_phi(patients_tbl)
#' }
describe_structure_with_phi <- function(data, rules = NULL, collect_sample = TRUE) {
  if (is.null(rules)) {
    rules <- get_default_phi_rules()
  }

  # Handle database tables (tbl_sql objects)
  if (inherits(data, "tbl_sql") && collect_sample) {
    zero <- tryCatch({
      dplyr::head(data, n = 0) |> dplyr::collect()
    }, error = function(e) {
      warning(sprintf("Could not introspect table: %s", e$message))
      return(NULL)
    })

    if (is.null(zero)) return(NULL)

    data <- zero
  }

  # Now analyze as regular data frame
  detect_phi_in_data(data, rules)
}

#' Filter columns by PHI risk level
#'
#' Returns column names filtered by specified risk levels. Useful for
#' selecting only safe columns for analysis.
#'
#' @param structure_info Output from detect_phi_in_data() or describe_structure_with_phi()
#' @param exclude_risk Character vector of risk levels to exclude (e.g., c("HIGH", "MEDIUM"))
#' @param include_risk Character vector of risk levels to include (overrides exclude_risk)
#' @return Character vector of column names
#' @export
#' @examples
#' df <- data.frame(Pat_ID1 = 1:10, LAST_NAME = letters[1:10], Age = 20:29)
#' structure <- detect_phi_in_data(df)
#'
#' # Get only non-PHI columns
#' safe_cols <- filter_columns_by_risk(structure, exclude_risk = c("HIGH", "MEDIUM", "LOW"))
#'
#' # Get only LOW and NONE risk columns
#' low_risk_cols <- filter_columns_by_risk(structure, exclude_risk = c("HIGH", "MEDIUM"))
filter_columns_by_risk <- function(structure_info, exclude_risk = NULL, include_risk = NULL) {
  if (!is.data.frame(structure_info) || !"risk_level" %in% names(structure_info)) {
    stop("structure_info must be output from detect_phi_in_data() or describe_structure_with_phi()")
  }

  if (!is.null(include_risk)) {
    # Include mode: only return columns with specified risk levels
    filtered <- structure_info |>
      dplyr::filter(risk_level %in% !!include_risk)
  } else if (!is.null(exclude_risk)) {
    # Exclude mode: return all columns except specified risk levels
    filtered <- structure_info |>
      dplyr::filter(!risk_level %in% !!exclude_risk)
  } else {
    # No filtering
    filtered <- structure_info
  }

  filtered$column
}

#' Summarize PHI detection results
#'
#' @param structure_info Output from detect_phi_in_data() or describe_structure_with_phi()
#' @return Tibble with counts by risk level
#' @export
#' @examples
#' df <- data.frame(Pat_ID1 = 1:10, LAST_NAME = letters[1:10], Age = 20:29)
#' structure <- detect_phi_in_data(df)
#' summarize_phi_detection(structure)
summarize_phi_detection <- function(structure_info) {
  if (!is.data.frame(structure_info) || !"risk_level" %in% names(structure_info)) {
    stop("structure_info must be output from detect_phi_in_data() or describe_structure_with_phi()")
  }

  summary <- structure_info |>
    dplyr::group_by(risk_level) |>
    dplyr::summarise(
      column_count = dplyr::n(),
      columns = paste(column, collapse = ", "),
      .groups = "drop"
    ) |>
    dplyr::arrange(dplyr::desc(risk_level))

  summary
}
