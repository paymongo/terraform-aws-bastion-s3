data "aws_ami" "amazon-linux-2" {
  most_recent = true
  owners      = ["amazon"]
  name_regex  = "^amzn2-ami-hvm.*-ebs"

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

data "aws_subnet" "subnets" {
  count = var.elb_subnets != [] ? length(var.elb_subnets) : length(var.elb_subnets_mapping)

  id = var.elb_subnets != [] ? var.elb_subnets[count.index] : var.elb_subnets_mapping[count.index].subnet_id
}
