# Terraform configuration for Universal WAF Advanced Features
# Deploys Lambda@Edge and ALB Lambda with full protection capabilities

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region for ALB Lambda"
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name"
  default     = "universal-waf-advanced"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  default     = "prod"
}

variable "waf_mode" {
  description = "WAF operation mode (BLOCK, MONITOR, LOG)"
  default     = "BLOCK"
}

variable "bot_protection_level" {
  description = "Bot protection level (LOW, MEDIUM, HIGH, AGGRESSIVE)"
  default     = "MEDIUM"
}

variable "geo_blacklist" {
  description = "List of country codes to block"
  type        = list(string)
  default     = []
}

variable "rate_limit_requests" {
  description = "Rate limit requests per window"
  default     = 100
}

# Provider for ALB Lambda
provider "aws" {
  region = var.aws_region
}

# Provider for Lambda@Edge (must be us-east-1)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

# WAF Configuration JSON
locals {
  waf_config = jsonencode({
    geoBlacklist        = var.geo_blacklist
    geoWhitelist        = []
    ipWhitelist         = ["127.0.0.1/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    ipBlacklist         = []
    ipReputationBlock   = true
    rateLimitEnabled    = true
    rateLimitRequests   = var.rate_limit_requests
    rateLimitWindow     = 60
    rateLimitBurst      = 150
    rateLimitAction     = "RATE_LIMIT"
    bruteForceEnabled   = true
    bruteForceThreshold = 5
    bruteForceWindow    = 300
    bruteForceBlockDuration = 3600
    bruteForceEndpoints = ["/login", "/auth", "/admin", "/api/auth"]
    allowedMethods      = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    blockedMethods      = ["TRACE", "TRACK", "CONNECT"]
    methodAction        = "BLOCK"
    uploadEnabled       = true
    uploadMaxSize       = 10485760
    uploadBlockedExtensions = [".php", ".asp", ".jsp", ".exe", ".sh"]
    uploadAction        = "BLOCK"
    blockTor            = false
    blockVpn            = false
    blockProxy          = false
    blockHosting        = false
    anonymousIpAction   = "CHALLENGE_JS"
    botProtectionEnabled = true
    botProtectionLevel  = var.bot_protection_level
    botJsChallenge      = true
    botFingerprint      = true
    botBehavioral       = true
    botBlockHeadless    = false
    botRatePerMinute    = 60
    ddosEnabled         = true
    ddosRequestThreshold = 1000
    ddosBurstMultiplier = 3
    ddosBlockDuration   = 300
    ddosChallengeMode   = true
    ddosGeoAnomaly      = true
    ddosUAAnomaly       = true
    sqliEnabled         = true
    sqliAction          = "BLOCK"
    sqliLevel           = "MODERATE"
    xssEnabled          = true
    xssAction           = "BLOCK"
    xssLevel            = "MODERATE"
    csrfEnabled         = false
    logAllRequests      = false
    logBlockedOnly      = true
    logFormat           = "JSON"
    captchaProvider     = "RECAPTCHA_V3"
    challengePassDuration = 3600
  })
}

# IAM Role for Lambda
resource "aws_iam_role" "waf_lambda_role" {
  name = "${var.project_name}-lambda-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = [
            "lambda.amazonaws.com",
            "edgelambda.amazonaws.com"
          ]
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "waf_lambda_basic" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.waf_lambda_role.name
}

resource "aws_iam_role_policy" "waf_lambda_cloudwatch" {
  name = "${var.project_name}-cloudwatch-policy"
  role = aws_iam_role.waf_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Lambda@Edge Function (must be in us-east-1)
resource "aws_lambda_function" "waf_edge" {
  provider = aws.us_east_1

  function_name = "${var.project_name}-edge-${var.environment}"
  role          = aws_iam_role.waf_lambda_role.arn
  handler       = "advanced.handler"
  runtime       = "nodejs20.x"
  publish       = true
  memory_size   = 128
  timeout       = 5

  filename         = "${path.module}/../lambda-edge-advanced.zip"
  source_code_hash = filebase64sha256("${path.module}/../lambda-edge-advanced.zip")

  environment {
    variables = {
      WAF_CONFIG = local.waf_config
    }
  }
}

# ALB Lambda Function
resource "aws_lambda_function" "waf_alb" {
  function_name = "${var.project_name}-alb-${var.environment}"
  role          = aws_iam_role.waf_lambda_role.arn
  handler       = "advanced.handler"
  runtime       = "nodejs20.x"
  memory_size   = 512
  timeout       = 10

  filename         = "${path.module}/../lambda-alb-advanced.zip"
  source_code_hash = filebase64sha256("${path.module}/../lambda-alb-advanced.zip")

  environment {
    variables = {
      WAF_CONFIG = local.waf_config
    }
  }
}

# Lambda permission for ALB
resource "aws_lambda_permission" "alb_invoke" {
  statement_id  = "AllowALBInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.waf_alb.function_name
  principal     = "elasticloadbalancing.amazonaws.com"
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "waf_edge_logs" {
  provider = aws.us_east_1

  name              = "/aws/lambda/${aws_lambda_function.waf_edge.function_name}"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "waf_alb_logs" {
  name              = "/aws/lambda/${aws_lambda_function.waf_alb.function_name}"
  retention_in_days = 14
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "waf_blocks" {
  alarm_name          = "${var.project_name}-blocks-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "BlockedRequests"
  namespace           = "WAF"
  period              = "300"
  statistic           = "Sum"
  threshold           = "100"
  alarm_description   = "Alert when WAF blocks exceed threshold"

  dimensions = {
    FunctionName = aws_lambda_function.waf_alb.function_name
  }
}

# Outputs
output "waf_edge_lambda_arn" {
  description = "Lambda@Edge function ARN (use for CloudFront)"
  value       = aws_lambda_function.waf_edge.qualified_arn
}

output "waf_edge_lambda_version" {
  description = "Lambda@Edge function version"
  value       = aws_lambda_function.waf_edge.version
}

output "waf_alb_lambda_arn" {
  description = "ALB Lambda function ARN"
  value       = aws_lambda_function.waf_alb.arn
}

output "waf_config" {
  description = "WAF configuration applied"
  value       = local.waf_config
  sensitive   = true
}
