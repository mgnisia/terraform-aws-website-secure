// Cloning Terraform src code to /var/folders/lk/d1lpvhvd3c987jzyhjfhn860f9m6fv/T/terraform_src...
#  code has been checked out.

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

variable "rotate_interval" {
  description = "Rotation interval in days for origin secret value."
  type        = string
  default     = "7"
}

variable "log_retention" {
  description = "Log retention period for HTTP API access logs"
  type        = string
  default     = "30"
}

data "archive_file" "lambda_function_file" {
  type        = "zip"
  source_file = "index.js"
  output_path = "lambda_function.zip"
}


resource "aws_secretsmanager_secret" "origin_verify_secret" {
  name = "OriginVerifySecret"
  // CF Property(GenerateSecretString) = {
  //   SecretStringTemplate = "{"HEADERVALUE": "RandomPassword"}"
  //   GenerateStringKey = "HEADERVALUE"
  //   ExcludePunctuation = True
  // }
}

resource "aws_lambda_permission" "rotate_function_invoke_permission" {
  function_name = aws_lambda_function.origin_secret_rotate_function.arn
  action        = "lambda:InvokeFunction"
  principal     = "secretsmanager.amazonaws.com"
}

resource "aws_secretsmanager_secret_rotation" "origin_verify_rotate_schedule" {
  rotation_lambda_arn = aws_lambda_function.origin_secret_rotate_function.arn
  rotation_rules = {
    AutomaticallyAfterDays = var.rotate_interval
  }
  secret_id = aws_secretsmanager_secret.origin_verify_secret.id
}

resource "aws_iam_role" "origin_secret_rotate_execution_role" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_lambda_function" "origin_secret_rotate_function" {
  description      = "Secrets Manager Rotation Lambda"
  handler          = "index.lambda_handler"
  runtime          = "python3.11"
  filename         = local.rotate_secret_lambda_zip
    function_name    = "${var.prefix}-${var.name}-secret-rotation"

  source_code_hash = data.archive_file.lambda_rotate_secret.output_base64sha256
  environment {
    variables = {
      CFDISTROID = module.cloudfront.cloudfront_distribution_id
      HEADERNAME = "x-origin-verify"
      ORIGINURL  = "${aws_apigatewayv2_api.api_gateway.api_endpoint}"
    }
  }
  role = aws_iam_role.origin_secret_rotate_execution_role.arn
}

locals {
  authorizer_lambda_zip    = "${var.prefix}-authorizer-lambda.zip"
  rotate_secret_lambda_zip = "${var.prefix}-rotate-secret-lambda.zip"
}


data "archive_file" "lambda_authorizer" {
  type        = "zip"
  source_file = "lambda-cloudfront-secret-rotation/authorizer.py"
  output_path = local.authorizer_lambda_zip
}

data "archive_file" "lambda_rotate_secret" {
  type        = "zip"
  source_file = "lambda-cloudfront-secret-rotation/rotate-secret.py"
  output_path = local.rotate_secret_lambda_zip
}

resource "aws_lambda_function" "authorizer_lambda" {
  description      = "Authorizer Lambda Function"
  filename         = local.authorizer_lambda_zip
  source_code_hash = data.archive_file.lambda_authorizer.output_base64sha256
  runtime          = "python3.7"
  timeout          = 900
  handler          = "index.lambda_handler"
  function_name    = "${var.prefix}-${var.name}-authorizer-lambda"
  role             = aws_iam_role.authorizer_lambda_function_role.arn
}

resource "aws_iam_role" "authorizer_lambda_function_role" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = [
            "lambda.amazonaws.com"
          ]
        }
        Action = [
          "sts:AssumeRole"
        ]
      }
    ]
  })
  path = "/"
}



resource "aws_iam_policy" "authorizer_lambda_function_role" {
  name        = "ecr-push-policy"
  description = "Policy to allow pushing to all ECR repositories"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:CreateLogGroup"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:logs:*:${data.aws_caller_identity.current.account_id}:log-group:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:logs:*:${data.aws_caller_identity.current.account_id}:log-group:*:log-stream:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:OriginVerifySecret-*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "authorizer_lambda_function_role" {
  role       = aws_iam_role.authorizer_lambda_function_role.name
  policy_arn = aws_iam_policy.authorizer_lambda_function_role.arn
}


resource "aws_apigatewayv2_api" "api_gateway" {
  protocol_type = "HTTP"
  name          = "APIGateway"
}

resource "aws_apigatewayv2_route" "api_gw_route" {
  api_id             = aws_apigatewayv2_api.api_gateway.id
  route_key          = "$default"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_api_gateway_authorizer.api_gw_authorizer.arn
  target             = join("/", ["integrations", aws_apigatewayv2_integration.api_gw_integration.id])
}

resource "aws_apigatewayv2_integration" "api_gw_integration" {
  api_id                 = aws_apigatewayv2_api.api_gateway.id
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  integration_uri        = "arn:${data.aws_partition.current.partition}:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/${var.lambda_arn}/invocations"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_stage" "api_gw_stage" {
  name        = "$default"
  auto_deploy = True
  api_id      = aws_apigatewayv2_api.api_gateway.id
  access_log_settings = {
    DestinationArn = aws_lb_target_group.api_log_group.arn
    # Format = "{"requestId":"$context.requestId", "ip": "$context.identity.sourceIp","caller":"$context.identity.caller","user":"$context.identity.user","requestTime":"$context.requestTime","routeKey":"$context.routeKey","status":"$context.status"}"
  }
}

resource "aws_api_gateway_authorizer" "api_gw_authorizer" {
  name        = "LambdaAuthorizer"
  rest_api_id = aws_apigatewayv2_api.api_gateway.id
  type        = "REQUEST"
  // CF Property(EnableSimpleResponses) = True
  authorizer_uri  = "arn:${data.aws_partition.current.partition}:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/${aws_lambda_function.authorizer_lambda.arn}/invocations"
  identity_source = "$request.header.x-origin-verify"
}

resource "aws_lambda_permission" "authorizer_lambda_permission" {
  action        = "lambda:InvokeFunction"
  principal     = "apigateway.amazonaws.com"
  function_name = aws_lambda_function.authorizer_lambda.function_name
  source_arn    = "arn:${data.aws_partition.current.partition}:execute-api:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${aws_apigatewayv2_api.api_gateway.id}/${"*"}/*"
}

# resource "aws_lambda_permission" "sample_website_lambda_permission" {
#   action        = "lambda:InvokeFunction"
#   principal     = "apigateway.amazonaws.com"
#   function_name = var.lambda_arn
#   source_arn    = "arn:${data.aws_partition.current.partition}:execute-api:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${aws_apigatewayv2_api.api_gateway.id}/${"*"}/*"
# }

resource "aws_lb_target_group" "api_log_group" {
  name = "HTTPApiAccessLogs"
  // CF Property(RetentionInDays) = var.log_retention
}

# resource "aws_cloudfront_distribution" "cloud_front_distribution" {
#   // CF Property(DistributionConfig) = {
#   //   Origins = [
#   //     {
#   //       Id = "apiGwOrigin"
#   //       CustomOriginConfig = {
#   //         HTTPSPort = 443
#   //         OriginProtocolPolicy = "https-only"
#   //         OriginSSLProtocols = [
#   //           "TLSv1.2"
#   //         ]
#   //       }
#   //       DomainName = "${aws_apigatewayv2_api.api_gateway.id}.execute-api.${data.aws_region.current.name}.amazonaws.com"
#   //       OriginCustomHeaders = [
#   //         {
#   //           HeaderName = "x-origin-verify"
#   //           HeaderValue = join("", ["{{resolve:secretsmanager:", aws_secretsmanager_secret.origin_verify_secret.id, ":SecretString:HEADERVALUE}}"])
#   //         }
#   //       ]
#   //     }
#   //   ]
#   //   Enabled = True
#   //   DefaultCacheBehavior = {
#   //     AllowedMethods = [
#   //       "GET",
#   //       "HEAD",
#   //       "OPTIONS"
#   //     ]
#   //     TargetOriginId = "apiGwOrigin"
#   //     ViewerProtocolPolicy = "redirect-to-https"
#   //     ForwardedValues = {
#   //       QueryString = "false"
#   //     }
#   //   }
#   // }
# }
