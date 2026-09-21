variable "name" {
  description = "Name supplied by the root module."
  type        = string
}
variable "tags" {
  description = "Tags supplied by the root module."
  type        = map(string)
}
