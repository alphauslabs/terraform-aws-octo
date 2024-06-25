variable "access_key" {
  description = "(For authentication purpose only) The access key of your AWS account. Leave empty when using AWS CLI."
  type        = string
}

variable "secret_key" {
  description = "(For authentication purpose only) The secret key of your AWS account. Leave empty when using AWS CLI."
  type        = string
}

variable "use_stackset" {
  description = "(Only applicable on Master account) Use stackset to deploy API Access to all sub-accounts. (Only set to True if you want to deploy api access to all sub-accounts under organization)"
  type        = bool
}

variable "external_id" {
  description = "The external id that Alphaus cloud will use to assume the role ARN. This can be get from the provided sample terraform file layout in Octo"
  type        = string

  validation {
    condition     = length(var.external_id) != 0 || var.external_id != null
    error_message = "External ID must not be empty"
  }
}

# With default values
variable "principal" {
  default     = "131920598436"
  description = "The Alphaus account that will have access to your account. Do not change."
  type        = string

  validation {
    condition     = var.principal == "131920598436"
    error_message = "Do not change the principal value."
  }
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

variable "stackset_name" {
  default     = "alphaus-api-access-stackset"
  description = "The name of the stackset that will be created."
  type        = string
}

