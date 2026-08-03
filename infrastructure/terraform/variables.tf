variable "aws_region" {
  description = "Target AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Target execution environment name (production/staging/dev)"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  description = "IP CIDR boundary address block for target AWS VPC virtual network"
  type        = string
  default     = "10.0.0.0/16"
}

variable "api_cpu" {
  description = "CPU units allocated to FastAPI API container task definition"
  type        = number
  default     = 256
}

variable "api_memory" {
  description = "Memory size allocated to FastAPI API container task definition"
  type        = number
  default     = 512
}

variable "worker_cpu" {
  description = "CPU units allocated to Celery worker container task definition"
  type        = number
  default     = 256
}

variable "worker_memory" {
  description = "Memory size allocated to Celery worker container task definition"
  type        = number
  default     = 512
}
