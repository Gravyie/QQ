# Payments VPC key management
resource "aws_kms_key" "pan_master" {
  description              = "PAN tokenisation master key"
  customer_master_key_spec = "RSA_4096"
  key_usage                = "ENCRYPT_DECRYPT"
  enable_key_rotation      = false
}

resource "aws_kms_key" "settlement_signing" {
  description              = "Settlement batch signing"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_cloudhsm_v2_cluster" "branch_hsm" {
  hsm_type   = "hsm1.medium"
  subnet_ids = var.private_subnets
}

resource "aws_lb_listener" "payments" {
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
}
