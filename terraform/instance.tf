// Key pairs
resource "aws_key_pair" "coe_557_hw3" {
  key_name   = "coe-557-hw3-key"
  public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICXWSc5axqwKLbewH6SyoH3CHu9T0ykCtlQT5SAw8eF1 coe557 hw3"
}

// Instances EC2
resource "aws_instance" "coe_557_hw3_server" {
  ami = "ami-0281b0943230d40d1"
  instance_type = "t3.medium"
  availability_zone = var.av_zone
  subnet_id = "subnet-046ea35c3305c5095"
  key_name = aws_key_pair.coe_557_hw3.key_name
  vpc_security_group_ids = [
    "sg-09206ea43c7f6aab9"
  ]
  tags = {
    Name = "coe-557-hw3-instance"
  }
}