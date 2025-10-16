test_that("anonymize_data anonymizes HIGH risk columns", {
  df <- data.frame(
    Pat_ID1 = 1:5,
    LAST_NAME = c("Smith", "Jones", "Brown", "Davis", "Wilson"),
    Age = c(45, 52, 38, 61, 29),
    stringsAsFactors = FALSE
  )

  structure <- detect_phi_in_data(df)
  result <- anonymize_data(df, structure)

  # Check that data was anonymized
  expect_false(any(result$data$LAST_NAME == "Smith"))
  expect_false(any(result$data$LAST_NAME == "Jones"))

  # Check that non-PHI columns remain unchanged
  expect_equal(result$data$Pat_ID1, df$Pat_ID1)
  expect_equal(result$data$Age, df$Age)

  # Check log
  expect_true("LAST_NAME" %in% names(result$log))
  expect_equal(result$log$LAST_NAME$risk, "HIGH")
})

test_that("anonymize_data handles multiple HIGH risk columns", {
  df <- data.frame(
    FIRST_NAME = c("John", "Jane", "Bob"),
    LAST_NAME = c("Smith", "Jones", "Brown"),
    Age = c(45, 52, 38),
    stringsAsFactors = FALSE
  )

  structure <- detect_phi_in_data(df)
  result <- anonymize_data(df, structure)

  # Both name columns should be anonymized
  expect_false(any(result$data$FIRST_NAME == "John"))
  expect_false(any(result$data$LAST_NAME == "Smith"))

  # Age should remain
  expect_equal(result$data$Age, df$Age)

  # Check log has both columns
  expect_true("FIRST_NAME" %in% names(result$log))
  expect_true("LAST_NAME" %in% names(result$log))
})

test_that("anonymize_data handles birth dates correctly", {
  df <- data.frame(
    Pat_ID1 = 1:3,
    BIRTH_DTTM = as.Date(c("1975-06-15", "1980-03-20", "1990-11-10"))
  )

  structure <- detect_phi_in_data(df)
  result <- anonymize_data(df, structure)

  # Birth dates should be generalized to year with noise
  expect_s3_class(result$data$BIRTH_DTTM, "Date")

  # Original dates should not be present
  expect_false(any(result$data$BIRTH_DTTM == as.Date("1975-06-15")))
})

test_that("anonymize_data handles MEDIUM risk columns", {
  df <- data.frame(
    Pat_ID1 = 1:3,
    City = c("Boston", "New York", "Chicago"),
    ACCOUNT_ID = c("ACC001", "ACC002", "ACC003"),
    stringsAsFactors = FALSE
  )

  structure <- detect_phi_in_data(df)
  result <- anonymize_data(df, structure)

  # Account IDs should be hashed
  expect_true(all(grepl("^ACCT_", result$data$ACCOUNT_ID)))

  # Check log
  expect_equal(result$log$ACCOUNT_ID$risk, "MEDIUM")
  expect_equal(result$log$City$risk, "MEDIUM")
})

test_that("anonymize_data handles LOW risk columns", {
  df <- data.frame(
    Pat_ID1 = 1:5,
    STAFF_ID = c(100, 200, 300, 400, 500),
    Age = c(45, 52, 38, 61, 29)
  )

  structure <- detect_phi_in_data(df)
  result <- anonymize_data(df, structure)

  # STAFF_ID should have minimal noise added
  expect_true(all(result$data$STAFF_ID != df$STAFF_ID))

  # But should be close to original values
  expect_true(all(abs(result$data$STAFF_ID - df$STAFF_ID) < 10))

  # Check log
  expect_equal(result$log$STAFF_ID$risk, "LOW")
})

test_that("anonymize_data returns audit log", {
  df <- data.frame(
    LAST_NAME = c("Smith", "Jones"),
    City = c("Boston", "Chicago"),
    stringsAsFactors = FALSE
  )

  structure <- detect_phi_in_data(df)
  result <- anonymize_data(df, structure)

  expect_type(result$log, "list")
  expect_true(length(result$log) > 0)

  # Check log structure
  expect_true("LAST_NAME" %in% names(result$log))
  expect_named(result$log$LAST_NAME, c("risk", "method", "reason"))
})

test_that("anonymize_data handles empty data", {
  df <- data.frame(
    Pat_ID1 = integer(),
    LAST_NAME = character()
  )

  structure <- detect_phi_in_data(df)
  result <- anonymize_data(df, structure)

  expect_equal(nrow(result$data), 0)
  expect_type(result$log, "list")
})

test_that("anonymize_data handles data with no PHI", {
  df <- data.frame(
    Pat_ID1 = 1:5,
    Age = c(45, 52, 38, 61, 29),
    Duration = c(10, 20, 15, 25, 30)
  )

  structure <- detect_phi_in_data(df)
  result <- anonymize_data(df, structure)

  # Data should be unchanged
  expect_equal(result$data, df)

  # Log should be empty
  expect_equal(length(result$log), 0)
})

test_that("extract_anonymized_sample works", {
  df <- data.frame(
    Pat_ID1 = 1:100,
    LAST_NAME = sample(c("Smith", "Jones", "Brown"), 100, replace = TRUE),
    Age = sample(20:80, 100, replace = TRUE),
    stringsAsFactors = FALSE
  )

  result <- extract_anonymized_sample(df, sample_size = 10)

  expect_equal(nrow(result$data), 10)
  expect_true("log" %in% names(result))
  expect_true("structure_info" %in% names(result))

  # LAST_NAME should be anonymized
  expect_false(any(result$data$LAST_NAME %in% c("Smith", "Jones", "Brown")))
})

test_that("extract_anonymized_sample respects sample size", {
  df <- data.frame(
    Pat_ID1 = 1:50,
    Age = 20:69
  )

  result <- extract_anonymized_sample(df, sample_size = 20)
  expect_equal(nrow(result$data), 20)
})

test_that("extract_anonymized_sample handles data smaller than sample size", {
  df <- data.frame(
    Pat_ID1 = 1:5,
    Age = 20:24
  )

  result <- extract_anonymized_sample(df, sample_size = 100)
  expect_equal(nrow(result$data), 5)
})
