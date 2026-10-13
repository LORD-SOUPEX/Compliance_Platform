terraform {
  required_version = ">= 0.12"
}

resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
  acl    = "authenticated-read"
}
