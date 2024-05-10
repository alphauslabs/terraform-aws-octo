variable "principal" {
  default     = "131920598436"
  description = "The Alphaus account that will have access to your account. Do not change."
  type        = string
}

variable "external_id" {
  default     = "2eCuy2PXAOhJON7d5L47yXA6FW3"
  description = "The external id that Alphaus cloud will use to assume the role ARN. Do not change."
  type        = string
}

variable "cur_s3_bucket_option" {
  description = "Create new or use an existing bucket."
  type        = string
  default     = "CREATE_NEW"
}

variable "cur_s3_bucket_name" {
  default     = "alphaus-cur-export"
  description = "The target S3 bucket. Should already exists if USE_EXISTING."
  type        = string
}

variable "cur_s3_bucket_region" {
  default     = "us-east-1"
  description = "The S3 bucket region. Leave the default if CREATE_NEW."
  type        = string
}

variable "cur_s3_prefix" {
  default     = "pre"
  description = "The prefix that AWS adds to the report name. Your prefix can't include spaces."
  type        = string
}

variable "cur_report_name" {
  default     = "curreport"
  description = "The report name. Must be unique, is case sensitive, and can't include spaces."
  type        = string
}

variable "acces_key" {
  description = "The access key of you AWS account. (Note: We do not store this information)"
  type        = string
}

variable "secret_key" {
  description = "The secret key of you AWS account. (Note: We do not store this information)"
  type        = string
}