# Terraform configuration for Universal WAF deployment

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
  description = "AWS region"
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name"
  default     = "universal-waf"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  default     = "prod"
}

# Provider
provider "aws" {
  region = var.aws_region
}

# IAM Role for Lambda functions
resource "aws_iam_role" "waf_lambda_role" {
  name = "${var.project_name}-lambda-role"

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

# Lambda@Edge function (must be in us-east-1)
resource "aws_lambda_function" "waf_edge" {
  provider = aws.us_east_1

  function_name = "${var.project_name}-edge"
  role          = aws_iam_role.waf_lambda_role.arn
  handler       = "lambda-edge/index.handler"
  runtime       = "nodejs20.x"
  publish       = true
  memory_size   = 128
  timeout       = 5

  filename         = "${path.module}/../lambda-edge.zip"
  source_code_hash = filebase64sha256("${path.module}/../lambda-edge.zip")

  environment {
    variables = {
      WAF_CONFIG = jsonencode({
        mode = "BLOCK"
        rules = [
          "SQLI-001", "XSS-001", "PT-001", "CMDI-001",
          "NOSQLI-001", "SSRF-001", "BOT-001", "METH-001", "NULL-001"
        ]
        rateLimit = {
          enabled          = true
          windowMs         = 60000
          maxRequests      = 100
          blockDurationMs  = 300000
        }
      })
    }
  }
}

# ALB Lambda function
resource "aws_lambda_function" "waf_alb" {
  function_name = "${var.project_name}-alb"
  role          = aws_iam_role.waf_lambda_role.arn
  handler       = "lambda-alb/index.handler"
  runtime       = "nodejs20.x"
  memory_size   = 256
  timeout       = 10

  filename         = "${path.module}/../lambda-alb.zip"
  source_code_hash = filebase64sha256("${path.module}/../lambda-alb.zip")
}

# Lambda permission for ALB
resource "aws_lambda_permission" "alb_invoke" {
  statement_id  = "AllowALBInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.waf_alb.function_name
  principal     = "elasticloadbalancing.amazonaws.com"
}

# CloudWatch Log Group for ALB Lambda
resource "aws_cloudwatch_log_group" "waf_alb_logs" {
  name              = "/aws/lambda/${aws_lambda_function.waf_alb.function_name}"
  retention_in_days = 7
}

# Outputs
output "waf_edge_lambda_arn" {
  description = "Lambda@Edge function ARN (use for CloudFront)"
  value       = aws_lambda_function.waf_edge.qualified_arn
}

output "waf_alb_lambda_arn" {
  description = "ALB Lambda function ARN"
  value       = aws_lambda_function.waf_alb.arn
}
