output "kms_key_id" {
  description = "LocalStack KMS key ID"
  value       = aws_kms_key.demo.key_id
}

output "kms_key_arn" {
  description = "LocalStack KMS key ARN"
  value       = aws_kms_key.demo.arn
}

output "secret_id" {
  description = "LocalStack Secrets Manager secret ID"
  value       = aws_secretsmanager_secret.demo.id
}
