# Security group for ElastiCache
resource "aws_security_group" "redis" {
  name        = "guardianmail-sg-redis-${var.environment}"
  description = "Access to Redis nodes"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Redis Subnet Group
resource "aws_elasticache_subnet_group" "redis" {
  name       = "guardianmail-redis-subnets-${var.environment}"
  subnet_ids = [aws_subnet.private_a.id]
}

# Redis Cluster
resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "guardianmail-redis-${var.environment}"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379
  security_group_ids   = [aws_security_group.redis.id]
  subnet_group_name    = aws_elasticache_subnet_group.redis.name

  tags = {
    Environment = var.environment
  }
}
