# Additional provider configuration for us-east-1 (required for Lambda@Edge)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}
