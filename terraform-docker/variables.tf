variable "nginx_image" {
  description = "Nginx Docker image"
  type        = string
  default     = "nginx:latest"
}

variable "nginx_container_name" {
  description = "Name of the Nginx container"
  type        = string
  default     = "nginx_container"
}

variable "nginx_internal_port" {
  description = "Internal port for Nginx"
  type        = number
  default     = 80
}

variable "nginx_external_port" {
  description = "External port for Nginx"
  type        = number
  default     = 8080
}
