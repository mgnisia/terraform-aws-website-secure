locals {
  callback_urls = concat(["https://${var.domain}${var.cognito_path_parse_auth}"], formatlist("%s${var.cognito_path_parse_auth}", var.cognito_additional_redirects))
  logout_urls   = concat(["https://${var.domain}${var.cognito_path_logout}"], formatlist("%s${var.cognito_path_logout}", var.cognito_additional_redirects))
  functions = toset(
    ["check-auth", "http-headers", "parse-auth", "refresh-auth", "rewrite-trailing-slash", "sign-out"]
  )
}

resource "random_pet" "this" {
  length = 2
}
data "aws_route53_zone" "this" {
  name = var.route53_zone_name
}

module "lambda_function" {
  for_each = local.functions

  source = "./modules/lambda"

  name     = var.name
  function = each.value
  configuration = jsondecode(<<EOF
{
  "userPoolArn": "${var.user_pool_arn}",
  "clientId": "${var.client_id}",
  "clientSecret": "${var.client_secret}",
  "oauthScopes": ["openid"],
  "cognitoAuthDomain": "${var.cognito_domain_prefix}.${var.domain}",
  "redirectPathSignIn": "${var.cognito_path_parse_auth}",
  "redirectPathSignOut": "${var.cognito_path_logout}",
  "redirectPathAuthRefresh": "${var.cognito_path_refresh_auth}",
  "cookieSettings": { "idToken": null, "accessToken": null, "refreshToken": null, "nonce": null },
  "mode": "spaMode",
  "httpHeaders": {
      "Content-Security-Policy": "default-src 'none'; img-src 'self' https://fastapi.tiangolo.com; script-src 'self' https://code.jquery.com https://stackpath.bootstrapcdn.com https://cdn.jsdelivr.net 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com; object-src 'none'; connect-src 'self' https://*.amazonaws.com https://*.amazoncognito.com",
      "Strict-Transport-Security": "max-age=31536000; includeSubdomains; preload",
      "Referrer-Policy": "same-origin",
      "X-XSS-Protection": "1; mode=block",
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options":  "nosniff"
  },
  "logLevel": "none",
  "nonceSigningSecret": "jvfg108gfhjhg!&%j91kt",
  "cookieCompatibility": "amplify",
  "additionalCookies": {},
  "requiredGroup": ""
}
EOF
  )

  providers = {
    aws = aws.us-east-1
  }
}

# module "acm" {
#   source  = "terraform-aws-modules/acm/aws"
#   version = "4.3.1"

#   domain_name               = var.domain
#   subject_alternative_names = ["*.${var.domain}"]
#   zone_id                   = data.aws_route53_zone.this.id

#   providers = {
#     aws = aws.us-east-1
#   }
# }

module "records" {
  source  = "terraform-aws-modules/route53/aws//modules/records"
  version = "2.10.1"

  zone_id = data.aws_route53_zone.this.zone_id

  records = [
    {
      # FIXME
      name = ""
      type = "A"
      alias = {
        name    = module.cloudfront.cloudfront_distribution_domain_name
        zone_id = module.cloudfront.cloudfront_distribution_hosted_zone_id
      }
    },
  ]
}

