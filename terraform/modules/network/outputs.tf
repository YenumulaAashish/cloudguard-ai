output "vpc_id" {
  description = "Vpc id."
  value       = aws_vpc.this.id
}
output "public_subnet_id" {
  description = "Public subnet id."
  value       = aws_subnet.public.id
}
output "private_subnet_id" {
  description = "Private subnet id."
  value       = aws_subnet.private.id
}
