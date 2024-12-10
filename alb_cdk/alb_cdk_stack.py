from aws_cdk import (
    # Duration,
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_elasticloadbalancingv2 as elbv2,
    CfnOutput,
    # aws_sqs as sqs,
)
from aws_cdk.aws_elasticloadbalancingv2_targets import InstanceTarget
import aws_cdk as cdk
from constructs import Construct

class AlbCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here

        # Parameters
        instance_type = cdk.CfnParameter(
            self, "InstanceType",
            type="String",
            allowed_values=["t2.micro", "t2.small"],
            default="t2.micro",
            description="EC2 instance type"
        )

        key_pair_param = cdk.CfnParameter(
            self, "KeyPair",
            type="String",
            description="KeyPair for EC2 instances"
        )

        your_ip = cdk.CfnParameter(
            self, "YourIp",
            type="String",
            description="IP address in CIDR"
        )

        # VPC
        vpc = ec2.Vpc(
            self, "EngineeringVpc",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/18"),
            max_azs=2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PUBLIC,
                    name="PublicSubnet1",
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PUBLIC,
                    name="PublicSubnet2",
                    cidr_mask=24
                )
            ]
        )

        # Security Group
        security_grp = ec2.SecurityGroup(
            self, "WebserversSG",
            vpc=vpc,
            description="Allow SSH and HTTP access",
            allow_all_outbound=True
        )
        security_grp.add_ingress_rule(ec2.Peer.ipv4(your_ip.value_as_string), ec2.Port.tcp(22), "SSH Access")
        security_grp.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(80), "HTTP Access")

        # KeyPair
        key_pair_obj = ec2.KeyPair.from_key_pair_name(self, "KeyPairResource", key_pair_param.value_as_string)

        # IAM Role
        instance_role = iam.Role(
            self, "InstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            description="Role for EC2 instances to access S3"
        )

        # Add S3 permissions to the role
        instance_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:GetObject"],
                resources=["arn:aws:s3:::seis665-public/*"]
            )
        )

        # EC2 Instances
        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            "yum update -y",
            "yum install -y git httpd php",
            "service httpd start",
            "chkconfig httpd on",
            "aws s3 cp s3://seis665-public/index.php /var/www/html/"
        )
        web1 = ec2.Instance(
            self, "web1",
            instance_type=ec2.InstanceType(instance_type.value_as_string),
            machine_image=ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=[vpc.public_subnets[0]]),
            security_group=security_grp,
            key_pair=key_pair_obj,
            user_data=user_data
        )

        web2 = ec2.Instance(
            self, "web2",
            instance_type=ec2.InstanceType(instance_type.value_as_string),
            machine_image=ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=[vpc.public_subnets[1]]),
            security_group=security_grp,
            key_pair=key_pair_obj,
            user_data=user_data
        )

        # Load Balancer
        lb = elbv2.ApplicationLoadBalancer(
            self, "EngineeringLB",
            vpc=vpc,
            internet_facing=True,
            load_balancer_name="EngineeringLB",
            vpc_subnets=ec2.SubnetSelection(
                subnets=[vpc.public_subnets[0], vpc.public_subnets[1]]
            )
        )

        listener = lb.add_listener(
            "Listener",
            port=80,
            open=True
        )

        target_group = listener.add_targets(
            "EngineeringWebservers",
            port=80,
            targets=[
                InstanceTarget(instance=web1),
                InstanceTarget(instance=web2)
            ],
            health_check=elbv2.HealthCheck(
                path="/",
                interval=cdk.Duration.seconds(30),
                timeout=cdk.Duration.seconds(5),
                healthy_threshold_count=2,
                unhealthy_threshold_count=2
            )
        )

        # Add this after creating the load balancer
        security_grp.add_ingress_rule(
            ec2.Peer.security_group_id(lb.connections.security_groups[0].security_group_id),
            ec2.Port.tcp(80),
            "Allow traffic from ALB"
        )

        # Output
        CfnOutput(
            self, "WebUrl",
            value=lb.load_balancer_dns_name,
            description="Load Balancer DNS Name"
        )