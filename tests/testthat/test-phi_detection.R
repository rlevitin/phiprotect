test_that("flag_phi detects HIGH risk PHI correctly", {
  # Test direct identifiers
  expect_equal(flag_phi("LAST_NAME")$risk_level, "HIGH")
  expect_equal(flag_phi("FIRST_NAME")$risk_level, "HIGH")
  expect_equal(flag_phi("PAT_NAME")$risk_level, "HIGH")
  expect_equal(flag_phi("IDA")$risk_level, "HIGH")
  expect_equal(flag_phi("IDB")$risk_level, "HIGH")
  expect_equal(flag_phi("MED_ID")$risk_level, "HIGH")
  expect_equal(flag_phi("BIRTH_DTTM")$risk_level, "HIGH")
  expect_equal(flag_phi("notes")$risk_level, "HIGH")

  # Test contact information
  expect_equal(flag_phi("Pat_Home_Phone")$risk_level, "HIGH")
  expect_equal(flag_phi("EMail")$risk_level, "HIGH")
  expect_equal(flag_phi("DirectMailAddress")$risk_level, "HIGH")

  # Verify phi flag is TRUE
  expect_true(flag_phi("LAST_NAME")$phi)
  expect_true(flag_phi("BIRTH_DTTM")$phi)
})

test_that("flag_phi detects MEDIUM risk PHI correctly", {
  expect_equal(flag_phi("ACCOUNT_ID")$risk_level, "MEDIUM")
  expect_equal(flag_phi("INITIALS")$risk_level, "MEDIUM")
  expect_equal(flag_phi("City")$risk_level, "MEDIUM")
  expect_equal(flag_phi("State_Province")$risk_level, "MEDIUM")
  expect_equal(flag_phi("Postal")$risk_level, "MEDIUM")

  # Verify phi flag is TRUE
  expect_true(flag_phi("ACCOUNT_ID")$phi)
  expect_true(flag_phi("City")$phi)
})

test_that("flag_phi detects LOW risk PHI correctly", {
  expect_equal(flag_phi("STAFF_ID")$risk_level, "LOW")
  expect_equal(flag_phi("INST_ID")$risk_level, "LOW")
  expect_equal(flag_phi("Location_ID")$risk_level, "LOW")
  expect_equal(flag_phi("FAC_ID")$risk_level, "LOW")

  # Verify phi flag is TRUE
  expect_true(flag_phi("STAFF_ID")$phi)
  expect_true(flag_phi("INST_ID")$phi)
})

test_that("flag_phi identifies non-PHI columns correctly", {
  expect_equal(flag_phi("Duration_time")$risk_level, "NONE")
  expect_equal(flag_phi("Activity")$risk_level, "NONE")
  expect_equal(flag_phi("CGroup")$risk_level, "NONE")
  expect_equal(flag_phi("Create_DtTm")$risk_level, "NONE")
  expect_equal(flag_phi("Pat_ID1")$risk_level, "NONE")

  # Verify phi flag is FALSE
  expect_false(flag_phi("Duration_time")$phi)
  expect_false(flag_phi("Activity")$phi)
  expect_false(flag_phi("Pat_ID1")$phi)
})

test_that("flag_phi returns correct structure", {
  result <- flag_phi("LAST_NAME")

  expect_type(result, "list")
  expect_named(result, c("phi", "reason", "risk_level"))
  expect_type(result$phi, "logical")
  expect_type(result$reason, "character")
  expect_type(result$risk_level, "character")
})

test_that("flag_phi is case insensitive", {
  expect_equal(flag_phi("last_name")$risk_level, "HIGH")
  expect_equal(flag_phi("LAST_NAME")$risk_level, "HIGH")
  expect_equal(flag_phi("Last_Name")$risk_level, "HIGH")
})

test_that("detect_phi_in_data works on data frames", {
  df <- data.frame(
    Pat_ID1 = 1:10,
    LAST_NAME = letters[1:10],
    Age = 20:29
  )

  result <- detect_phi_in_data(df)

  expect_s3_class(result, "data.frame")
  expect_equal(nrow(result), 3)
  expect_named(result, c("column", "r_type", "phi", "phi_reason", "risk_level"))

  # Check specific results
  expect_false(result$phi[result$column == "Pat_ID1"])
  expect_true(result$phi[result$column == "LAST_NAME"])
  expect_false(result$phi[result$column == "Age"])
})

test_that("filter_columns_by_risk excludes HIGH risk", {
  df <- data.frame(
    Pat_ID1 = 1:5,
    LAST_NAME = letters[1:5],
    Age = 20:24
  )

  structure <- detect_phi_in_data(df)
  safe_cols <- filter_columns_by_risk(structure, exclude_risk = "HIGH")

  expect_true("Pat_ID1" %in% safe_cols)
  expect_true("Age" %in% safe_cols)
  expect_false("LAST_NAME" %in% safe_cols)
})

test_that("filter_columns_by_risk include_risk works", {
  df <- data.frame(
    Pat_ID1 = 1:5,
    LAST_NAME = letters[1:5],
    STAFF_ID = 1:5,
    Age = 20:24
  )

  structure <- detect_phi_in_data(df)
  only_none <- filter_columns_by_risk(structure, include_risk = "NONE")

  expect_true("Pat_ID1" %in% only_none)
  expect_true("Age" %in% only_none)
  expect_false("LAST_NAME" %in% only_none)
  expect_false("STAFF_ID" %in% only_none)
})

test_that("summarize_phi_detection produces correct summary", {
  df <- data.frame(
    Pat_ID1 = 1:5,
    LAST_NAME = letters[1:5],
    STAFF_ID = 1:5,
    Age = 20:24
  )

  structure <- detect_phi_in_data(df)
  summary <- summarize_phi_detection(structure)

  expect_s3_class(summary, "data.frame")
  expect_true("risk_level" %in% names(summary))
  expect_true("column_count" %in% names(summary))

  # Check counts
  high_count <- summary$column_count[summary$risk_level == "HIGH"]
  expect_equal(high_count, 1)  # LAST_NAME

  low_count <- summary$column_count[summary$risk_level == "LOW"]
  expect_equal(low_count, 1)  # STAFF_ID

  none_count <- summary$column_count[summary$risk_level == "NONE"]
  expect_equal(none_count, 2)  # Pat_ID1, Age
})

test_that("custom PHI rules work", {
  custom_rules <- list(
    "CUSTOM_ID" = list(reason = "Custom identifier", risk = "HIGH")
  )

  rules <- load_custom_phi_rules(custom_rules, merge_with_defaults = TRUE)

  result <- flag_phi("CUSTOM_ID", rules = rules)
  expect_equal(result$risk_level, "HIGH")
  expect_equal(result$reason, "Custom identifier")

  # Default rules should still work
  result2 <- flag_phi("LAST_NAME", rules = rules)
  expect_equal(result2$risk_level, "HIGH")
})

test_that("custom rules can override defaults", {
  custom_rules <- list(
    "LAST_NAME" = list(reason = "Override last name", risk = "MEDIUM")
  )

  rules <- load_custom_phi_rules(custom_rules, merge_with_defaults = FALSE)

  result <- flag_phi("LAST_NAME", rules = rules)
  expect_equal(result$risk_level, "MEDIUM")
  expect_equal(result$reason, "Override last name")
})
