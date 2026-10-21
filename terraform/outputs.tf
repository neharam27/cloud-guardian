output "lambda_function_name" {
  description = "Name of the scanner Lambda."
  value       = aws_lambda_function.scanner.function_name
}

output "sns_topic_arn" {
  description = "Topic that receives scan reports."
  value       = aws_sns_topic.reports.arn
}

output "invoke_command" {
  description = "Run the scanner once, right now, and print the result."
  value       = "aws lambda invoke --function-name ${aws_lambda_function.scanner.function_name} --region ${var.region} --cli-binary-format raw-in-base64-out --payload '{}' /dev/stdout"
}
