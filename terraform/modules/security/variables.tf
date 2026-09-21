variable "name" {
  description = "Name supplied by the root module."
  type        = string
}
variable "vpc_id" {
  description = "Vpc id supplied by the root module."
  type        = string
}
variable "allowed_ssh_cidrs" {
  description = "Allowed ssh cidrs supplied by the root module."
  type        = set(string)
}
variable "tags" {
  description = "Tags supplied by the root module."
  type        = map(string)
}
