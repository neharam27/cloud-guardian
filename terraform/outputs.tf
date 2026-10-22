output "lambda_function_name" {
  description = "Name of the scanner Lambda."
  value       = aws_lambda_function.scanner.function_name
}

output "findings_table_name" {
  description = "DynamoDB table holding findings history."
  value       = aws_dynamodb_table.findings.name
}

output "approvals_table_name" {
  description = "DynamoDB table holding one-time clean-up approvals (hashed) and their outcomes."
  value       = aws_dynamodb_table.approvals.name
}

output "cleanup_mode" {
  description = "dry_run (links only show what would happen) or live (links really delete)."
  value       = var.cleanup_mode
}

output "approver_url" {
  description = "Public base URL of the confirmation page. Links in emails are this plus ?t=<one-time token>."
  value       = aws_lambda_function_url.approver.function_url
}

output "sns_topic_arn" {
  description = "Topic that receives scan reports."
  value       = aws_sns_topic.reports.arn
}

output "invoke_command" {
  description = "Run the scanner once, right now, and print the result."
  value       = "aws lambda invoke --function-name ${aws_lambda_function.scanner.function_name} --region ${var.region} --cli-binary-format raw-in-base64-out --payload '{}' /dev/stdout"
}
