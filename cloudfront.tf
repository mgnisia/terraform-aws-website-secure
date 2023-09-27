data "aws_canonical_user_id" "current" {}

data "aws_secretsmanager_secret" "secrets" {
  arn = aws_secretsmanager_secret.origin_verify_secret.arn
}

data "aws_secretsmanager_secret_version" "current" {
  secret_id = data.aws_secretsmanager_secret.secrets.id
}

module "cloudfront" {
  source  = "terraform-aws-modules/cloudfront/aws"
  version = "3.2.1"

  aliases = [var.domain]

  is_ipv6_enabled = true
  # default_root_object = "index.html"
  price_class = "PriceClass_100"

  create_origin_access_identity = false
  # origin_access_identities = {
  #   website = "Access website content"
  # }

  origin = {
    # s3 = {
    #   domain_name = module.website-bucket.s3_bucket_bucket_regional_domain_name
    #   # s3_origin_config = {
    #   #   origin_access_identity = "website"
    #   # }
    # }
    api = {
      connection_attempts      = 3
      connection_timeout       = 10
      domain_name              = trim(aws_apigatewayv2_api.api_gateway.api_endpoint, "https://")
      origin_access_control_id = null
      origin_id                = "apiGwOrigin"
      origin_path              = null
      custom_header = {
        secret = {
          name  = "x-origin-verify"
          value = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current.secret_string))["HEADERVALUE"]
          # value = "LRM7T1B2tPdcE8xxzRqfwHPK0UKcYDyf"
        }
      }
      custom_origin_config = {
        http_port                = 80
        https_port               = 443
        origin_keepalive_timeout = 5
        origin_protocol_policy   = "https-only"
        origin_read_timeout      = 30
        origin_ssl_protocols     = ["TLSv1.2"]
      }
    }

    dummy = {
      domain_name = "example.com"
      custom_origin_config = {
        http_port              = 80
        https_port             = 443
        origin_protocol_policy = "match-viewer"
        origin_ssl_protocols   = ["TLSv1.2"]
      }
    }
  }

  default_cache_behavior = {
    target_origin_id       = "apiGwOrigin"
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD"]
    compress        = true
    query_string    = true

    lambda_function_association = {
      viewer-request = {
        lambda_arn = module.lambda_function["check-auth"].lambda_function_qualified_arn
      }

      origin-response = {
        lambda_arn   = module.lambda_function["http-headers"].lambda_function_qualified_arn
        include_body = false
      }

      origin-request = {
        lambda_arn   = module.lambda_function["rewrite-trailing-slash"].lambda_function_qualified_arn
        include_body = false
      }
    }
  }

  ordered_cache_behavior = [
    {
      path_pattern           = var.cognito_path_parse_auth
      target_origin_id       = "dummy"
      viewer_protocol_policy = "redirect-to-https"

      allowed_methods = ["GET", "HEAD", "OPTIONS"]
      cached_methods  = ["GET", "HEAD"]
      compress        = true
      query_string    = true

      lambda_function_association = {
        viewer-request = {
          lambda_arn = module.lambda_function["parse-auth"].lambda_function_qualified_arn
        }
      }
    },
    {
      path_pattern           = var.cognito_path_refresh_auth
      target_origin_id       = "dummy"
      viewer_protocol_policy = "redirect-to-https"

      allowed_methods = ["GET", "HEAD", "OPTIONS"]
      cached_methods  = ["GET", "HEAD"]
      compress        = true
      query_string    = true

      lambda_function_association = {
        viewer-request = {
          lambda_arn = module.lambda_function["refresh-auth"].lambda_function_qualified_arn
        }
      }
    },
    {
      path_pattern           = var.cognito_path_logout
      target_origin_id       = "dummy"
      viewer_protocol_policy = "redirect-to-https"

      allowed_methods = ["GET", "HEAD", "OPTIONS"]
      cached_methods  = ["GET", "HEAD"]
      compress        = true
      query_string    = true

      lambda_function_association = {
        viewer-request = {
          lambda_arn = module.lambda_function["sign-out"].lambda_function_qualified_arn
        }
      }
    },

  ]

  viewer_certificate = {
    acm_certificate_arn = var.acm_arn
    ssl_support_method  = "sni-only"
  }

  logging_config = {
    bucket = module.log_bucket.s3_bucket_bucket_domain_name
  }

}

module "website-bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "v3.15.1"

  bucket                  = "s3-${var.s3_bucket_name}"
  force_destroy           = true
  restrict_public_buckets = true
  ignore_public_acls      = true
  block_public_acls       = true
  block_public_policy     = true

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "aws:kms"
      }
    }
  }

  versioning = {
    enabled = true
  }

  logging = {
    target_bucket = module.log_bucket.s3_bucket_id
    target_prefix = "log/"
  }
}

module "log_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "v3.15.1"

  bucket                   = "logs-${random_pet.this.id}"
  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"
  grant = [{
    type       = "CanonicalUser"
    permission = "FULL_CONTROL"
    id         = data.aws_canonical_user_id.current.id
    }, {
    type       = "CanonicalUser"
    permission = "FULL_CONTROL"
    id         = "c4c1ede66af53448b93c283ce9448c4ba468c9432aa01d700d3878632f77d2d0"
    # Ref. https://github.com/terraform-providers/terraform-provider-aws/issues/12512
    # Ref. https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html
  }]

  force_destroy           = true
  restrict_public_buckets = true
  ignore_public_acls      = true
  block_public_acls       = true
  block_public_policy     = true

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "aws:kms"
      }
    }
  }

  versioning = {
    enabled = true
  }
}
