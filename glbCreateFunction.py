import ipaddress
import json
import logging

import boto3
import urllib3
from botocore.config import Config

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

http = urllib3.PoolManager()
SUCCESS = "SUCCESS"
FAILED = "FAILED"
DEFAULT_INSTANCE_TYPE = ["t3.micro"]
SUPPORTED_INSTANCE_TYPES = [
    "c5.xlarge",
    "c5.2xlarge",
    "c6g.medium",
    "c6g.large",
    "c6gd.large",
    "c6i.large",
    "c6i.xlarge",
    "c6i.2xlarge",
    "dl1.24xlarge",
    "g4dn.xlarge",
    "g4dn.2xlarge",
    "g4dn.4xlarge",
    "inf1.xlarge",
    "inf1.2xlarge",
    "m1.small",
    "m4.large",
    "m5.large",
    "m6i.large",
    "m6i.xlarge",
    "m6i.2xlarge",
    "m6i.4xlarge",
    "r3.2xlarge",
    "r3.4xlarge",
    "r3.8xlarge",
    "r4.xlarge",
    "r5.large",
    "r5.xlarge",
    "r5b.xlarge",
    "r6i.xlarge",
    "t3.micro",
    "t3.small",
    "t3.medium",
    "t3.large",
    "t3.xlarge",
    "t3.2xlarge",
    "x1e.xlarge",
    "x2iedn.xlarge",
]

# Initialize Boto3 client
# Configure retries and timeouts
config = Config(retries={"max_attempts": 5, "mode": "standard"}, connect_timeout=2, read_timeout=15)

ec2_client = boto3.client("ec2", config=config)
logger.info("Client initialized successfully")


def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event, default=str)}")
    request_type = event["RequestType"].lower()
    response_data = {"status": "NONE"}

    ec2_parameters = event["ResourceProperties"]["ec2_vars"]
    ec2_vars = {
        "vpc_id": ec2_parameters.get("VPC_ID"),
        "security_group_ids": [ec2_parameters.get("SECURITY_GROUP_ID")],
        "iam_instance_profile": ec2_parameters.get("INSTANCE_PROFILE_ARN"),
        "user_data": ec2_parameters.get("USER_DATA"),
        "instance_types": ec2_parameters.get("INSTANCE_TYPES"),
        "image_id": ec2_parameters.get("IMAGE_ID"),
        "is_public": ec2_parameters.get("IS_PUBLIC") == "true",
        "instance_name": ec2_parameters.get("INSTANCE_NAME"),
        "ebs_volume_size": int(ec2_parameters.get("EBS_VOLUME_SIZE")),
        "private_ip": ec2_parameters.get("PRIVATE_IP", None),
        "num_instances": int(ec2_parameters.get("NUM_INSTANCES")),
        "ami_id": ec2_parameters.get("AMI_ID"),
        "custom_subnet_attr": ec2_parameters.get("SUBNET_CUSTOM_ATTR", None),
        "private_ip_last_octate": ec2_parameters.get("PRIVATE_IP_LAST_OCTATE", None),
        "additional_tags": ec2_parameters.get("ADD_TAG", None),
    }

    try:
        if request_type == "create":

            instance_types = validate_instance_type(ec2_vars["instance_types"])
            for instance_type in instance_types:
                image_id = ec2_vars["ami_id"] or get_latest_compatible_ami_id(ec2_vars["image_id"])
                device_name = describe_ami_id(image_id)["DeviceName"]
                subnets = get_subnets(ec2_vars["vpc_id"])
                az_names = get_availability_zones()
                available_azs = get_instance_type_availability(instance_type, az_names)
                filtered_subnets = filter_subnets(
                    subnets, ec2_vars["is_public"], available_azs, custom_attr=ec2_vars["custom_subnet_attr"]
                )

                for subnet in filtered_subnets:
                    subnet_id = subnet["SubnetId"]
                    az = subnet["AvailabilityZone"]

                    try:
                        if ec2_vars["private_ip_last_octate"]:
                            private_ip = calculate_private_ip(ec2_vars["private_ip_last_octate"], subnet["CidrBlock"])
                        else:
                            private_ip = ec2_vars["private_ip"]

                        instance_id = create_instance(
                            image_id,
                            instance_type,
                            ec2_vars["security_group_ids"],
                            subnet_id,
                            ec2_vars["is_public"],
                            ec2_vars["iam_instance_profile"],
                            ec2_vars["ebs_volume_size"],
                            ec2_vars["instance_name"],
                            ec2_vars["user_data"],
                            private_ip,
                            ec2_vars["num_instances"],
                            device_name,
                            ec2_vars["additional_tags"],
                        )
                        instance_ids_list = []
                        private_ips_list = []
                        public_ips_list = []
                        private_dns_list = []
                        public_dns_list = []
                        if wait_for_instance_running(instance_id):
                            instance = describe_instance(instance_id)
                            instance_ids_list.append(instance_id)
                            private_ips_list.append(instance.get("PrivateIpAddress", ""))
                            public_ips_list.append(instance.get("PublicIpAddress", ""))
                            private_dns_list.append(instance.get("PrivateDnsName", ""))
                            public_dns_list.append(instance.get("PublicDnsName", ""))
                            # Generate response Data for the instance.
                            response_data["status"] = SUCCESS
                            response_data["InstanceIds"] = instance_ids_list
                            response_data["PrivateIpAddresses"] = private_ips_list
                            response_data["PublicIpAddresses"] = public_ips_list
                            response_data["PrivateDnsNames"] = private_dns_list
                            response_data["PublicDnsNames"] = public_dns_list
                            send(
                                event, context, SUCCESS, response_data, physical_resource_id=event["LogicalResourceId"]
                            )
                            logger.info(
                                f"Instance {instance_id} created successfully in {'public' if ec2_vars['is_public'] else 'private'} subnet {subnet_id} in availability zone {az}."
                            )
                            return
                    except Exception as e:
                        logger.error(
                            f"Error in creating or starting instance in subnet {subnet_id} and AZ {az}: {str(e)}"
                        )
                        continue

                response_data["status"] = "Failed to create and start the instance in any of the available subnets."
                send(event, context, FAILED, response_data, physical_resource_id=event["LogicalResourceId"])
                logger.error("Failed to create and start the instance in any of the available subnets.")
                return

        elif request_type == "delete":
            return handle_delete(event, context, ec2_vars["vpc_id"], response_data)
        else:
            send(event, context, SUCCESS, response_data, physical_resource_id=event["LogicalResourceId"])

    except Exception as error:
        error_msg = f"Error processing request: {error}"
        logger.exception(error_msg)
        response_data["status"] = error_msg
        send(event, context, FAILED, response_data, physical_resource_id=event["LogicalResourceId"], error=error_msg)
        return


def handle_delete(event, context, vpc_id, responseData):
    try:
        delete_all_instances_in_vpc(vpc_id)
        responseData["status"] = SUCCESS
        send(event, context, SUCCESS, responseData, physical_resource_id=event["LogicalResourceId"])
        logger.info("All instances terminated successfully.")
    except Exception as e:
        logger.exception(f"Error terminating instances: {str(e)}")
        responseData["status"] = "Failed to terminate the instance."
        send(event, context, FAILED, responseData, physical_resource_id=event["LogicalResourceId"])


def validate_instance_type(instance_types: list):
    instance_types_list = []
    for instance_type in instance_types:
        if instance_type not in SUPPORTED_INSTANCE_TYPES:
            logger.info(f"Invalid instance type: {instance_type}. Using default instance type: {DEFAULT_INSTANCE_TYPE}")
            instance_types_list.extend(DEFAULT_INSTANCE_TYPE)
        else:
            instance_types_list.append(instance_type)
    return instance_types_list


def get_latest_compatible_ami_id(image_id):
    filter_ami = (
        "al2023-ami-2023*-x86_64" if image_id == "amazonlinux-2024-x86_64" else "amzn2-ami-hvm-2.0.2023*-x86_64-gp2"
    )

    try:
        paginator = ec2_client.get_paginator("describe_images")
        filters = [
            {"Name": "name", "Values": [filter_ami]},
            {"Name": "architecture", "Values": ["x86_64"]},
            {"Name": "root-device-type", "Values": ["ebs"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "owner-alias", "Values": ["amazon"]},
        ]
        response_iterator = paginator.paginate(Filters=filters)

        images = []
        for page in response_iterator:
            images.extend(page["Images"])

        if not images:
            raise ValueError("No available AMI found.")

        sorted_images = sorted(images, key=lambda x: x["CreationDate"], reverse=True)
        logger.info(f"Found {len(sorted_images)} images for Amazon Linux")
        return sorted_images[0]["ImageId"]

    except Exception as e:
        logger.error(f"Error describing images: {str(e)}")
        raise


def get_subnets(vpc_id, private_ip=None):
    paginator = ec2_client.get_paginator("describe_subnets")
    subnets = []
    page_iterator = paginator.paginate(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])

    for page in page_iterator:
        subnets.extend(page.get("Subnets", []))

    logger.info(f"Found {len(subnets)} subnets in VPC {vpc_id}")

    if private_ip:
        filtered_subnets = []
        for subnet in subnets:
            subnet_cidr = ipaddress.IPv4Network(subnet["CidrBlock"])
            if ipaddress.IPv4Address(private_ip) in subnet_cidr:
                filtered_subnets.append(subnet)

        if not filtered_subnets:
            raise ValueError(
                f"The provided private IP address {private_ip} does not belong to any subnet in VPC {vpc_id}."
            )

        logger.info(f"Filtered {len(filtered_subnets)} subnets based on the provided private IP address {private_ip}")
        return filtered_subnets

    return subnets


def get_availability_zones():
    az_names = [az["ZoneName"] for az in ec2_client.describe_availability_zones()["AvailabilityZones"]]
    logger.info(f"Available AZs: {az_names}")
    return az_names


def get_instance_type_availability(instance_type, az_names):
    paginator = ec2_client.get_paginator("describe_instance_type_offerings")
    available_azs = []
    for az in az_names:
        page_iterator = paginator.paginate(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}, {"Name": "location", "Values": [az]}],
        )
        for page in page_iterator:
            if page.get("InstanceTypeOfferings", []):
                available_azs.append(az)
    logger.info(f"Instance type {instance_type} available in AZs: {available_azs}")
    if not available_azs:
        raise ValueError(f"Instance type {instance_type} is not available in any availability zone.")

    return available_azs


def filter_subnets(
    subnets, is_public, available_azs, custom_attr=None, public_attr_value=True, private_attr_value=False
):
    filtered_subnets = []
    # Check if custom_attr is a subnet ID
    if custom_attr and custom_attr.startswith("subnet-"):
        for subnet in subnets:
            if subnet["SubnetId"] == custom_attr:
                logger.info(f"Using specified subnet: {subnet['SubnetId']} in AZ {subnet['AvailabilityZone']}")
                return [subnet]  # Return immediately if the custom subnet is found

        raise ValueError(f"Specified subnet with ID {custom_attr} not found in the provided VPC.")

    # Check if custom_attr is an AZ
    if custom_attr and custom_attr in available_azs:
        for subnet in subnets:
            if subnet["AvailabilityZone"] == custom_attr:
                if (is_public and subnet.get("MapPublicIpOnLaunch", False)) or (
                    not is_public and not subnet.get("MapPublicIpOnLaunch", False)
                ):
                    filtered_subnets.append(subnet)

        if not filtered_subnets:
            raise ValueError(f"No suitable subnets found in the specified AZ {custom_attr} for the provided VPC.")

        logger.info(f"Filtered subnets based on AZ {custom_attr}: {filtered_subnets}")
        return filtered_subnets

    # Default filtering if no custom attribute is provided
    for subnet in subnets:
        if subnet["AvailabilityZone"] in available_azs:
            if (is_public and subnet.get("MapPublicIpOnLaunch", False)) or (
                not is_public and not subnet.get("MapPublicIpOnLaunch", False)
            ):
                filtered_subnets.append(subnet)

    if not filtered_subnets:
        raise ValueError(
            f"No {'public' if is_public else 'private'} subnets available in the provided VPC and availability zones."
        )

    logger.info(f"Filtered subnets: {filtered_subnets}")
    return filtered_subnets


def create_instance(
    image_id,
    instance_type,
    security_group_ids,
    subnet_id,
    is_public,
    iam_instance_profile,
    ebs_volume_size,
    instance_name,
    user_data,
    private_ip,
    num_instances,
    device_name,
    additional_tags,
):
    try:
        network_interfaces = [
            {
                "AssociatePublicIpAddress": is_public,
                "DeleteOnTermination": True,
                "DeviceIndex": 0,
                "SubnetId": subnet_id,
                "Groups": security_group_ids,
            }
        ]

        if private_ip:
            network_interfaces[0]["PrivateIpAddress"] = private_ip
        # Prepare the tags
        base_tags = [{"Key": "Name", "Value": instance_name}]
        if additional_tags:
            if isinstance(additional_tags, dict):
                extra_tags = [additional_tags]
            elif isinstance(additional_tags, list):
                extra_tags = additional_tags
            else:
                raise ValueError("add_tag must be a dictionary or a list of dictionaries.")
            all_tags = base_tags + extra_tags
        else:
            all_tags = base_tags

        instance = ec2_client.run_instances(
            BlockDeviceMappings=[
                {
                    "DeviceName": device_name,
                    "Ebs": {"DeleteOnTermination": True, "VolumeSize": ebs_volume_size, "VolumeType": "gp3"},
                }
            ],
            ImageId=image_id,
            UserData=user_data,
            InstanceType=instance_type,
            MinCount=num_instances,
            MaxCount=num_instances,
            Monitoring={"Enabled": False},
            IamInstanceProfile={"Arn": iam_instance_profile},
            EbsOptimized=False,
            InstanceInitiatedShutdownBehavior="stop",
            TagSpecifications=[{"ResourceType": "instance", "Tags": all_tags}],
            NetworkInterfaces=network_interfaces,
        )
        return instance["Instances"][0]["InstanceId"]
    except Exception as e:
        logger.error(f"Error creating instance: {str(e)}")
        raise


def delete_all_instances_in_vpc(vpc_id):
    try:
        # Use a paginator to retrieve all instances in the VPC
        paginator = ec2_client.get_paginator("describe_instances")
        page_iterator = paginator.paginate(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])

        instance_ids = []
        for page in page_iterator:
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    instance_ids.append(instance["InstanceId"])

        if instance_ids:
            ec2_client.terminate_instances(InstanceIds=instance_ids)
            logger.info(f"Terminated instances: {instance_ids}")

            waiter = ec2_client.get_waiter("instance_terminated")
            waiter.wait(InstanceIds=instance_ids)
            logger.info("All instances in the VPC have been terminated.")
        else:
            logger.info("No instances found in the VPC.")
    except Exception as e:
        logger.error(f"Error terminating instances in VPC {vpc_id}: {str(e)}")
        raise


def wait_for_instance_running(instance_id):
    waiter = ec2_client.get_waiter("instance_running")
    try:
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 10, "MaxAttempts": 30})
        logger.info(f"Instance {instance_id} is running.")
        return True
    except Exception as e:
        logger.error(f"Error waiting for instance {instance_id} to run: {str(e)}")
        return False


def calculate_private_ip(last_octet, cidr_block):
    """
    Calculate the private IP address based on the last octet and the subnet's CIDR block.
    """
    try:
        # Convert CIDR block to IP network
        subnet = ipaddress.IPv4Network(cidr_block)
        # Extract the prefix (e.g., 10.0.1.0) and append the last octet
        base_ip = str(subnet.network_address).rsplit(".", 1)[0]
        private_ip = f"{base_ip}.{last_octet}"

        # Validate if the generated IP is in the subnet
        if ipaddress.IPv4Address(private_ip) in subnet:
            logger.info(f"Generated private IP: {private_ip}")
            return private_ip
        else:
            raise ValueError("Generated private IP is not in the subnet range.")
    except Exception as e:
        logger.error(f"Error calculating private IP: {str(e)}")
        raise ValueError("Invalid subnet or last octet provided.")


def describe_ami_id(image_id):
    try:
        response = ec2_client.describe_images(ImageIds=[image_id])
        images = response.get("Images", [])
        if not images:
            raise ValueError("No available AMI found.")
        image = images[0]
        block_device_mappings = image.get("BlockDeviceMappings", [])
        return block_device_mappings[0]

    except Exception as e:
        logger.error(f"Error describing images: {str(e)}")
        raise


def describe_instance(instance_id):
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instances = []
        for reservation in response["Reservations"]:
            instances.extend(reservation["Instances"])
        if instances:
            logger.info(f"Described instance: {instance_id}")
            return instances[0]
        else:
            logger.error(f"No instance found with ID {instance_id}")
            return None
    except Exception as e:
        logger.error(f"Error describing instance {instance_id}: {str(e)}")
        raise


def send(event, context, response_status, response_data, physical_resource_id=None, no_echo=False, error=None):
    response_url = event["ResponseURL"]

    generic_error_message = (
        f"See the details in CloudWatch Log Stream: {context.log_stream_name} LogGroup: {context.log_group_name}"
    )
    response_body = json.dumps(
        {
            "Status": response_status,
            "Reason": error or generic_error_message,
            "PhysicalResourceId": physical_resource_id or context.log_stream_name,
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "NoEcho": no_echo,
            "Data": response_data,
        }
    )

    headers = {"content-type": "", "content-length": str(len(response_body))}
    try:
        response = http.request("PUT", response_url, body=response_body.encode("utf-8"), headers=headers)
        logger.info("Status code: " + response.reason)
    except Exception as e:
        logger.error(f"send(..) failed executing requests.put(..): {str(e)}")
