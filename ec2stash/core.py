#!/usr/bin/env python

import sys
import logging
import base64
import boto3
import botocore



logger = logging.getLogger("ec2stash")


class EC2stash(object):
    """Summary

    Attributes:
        cfg (dict): Config with all related parameters
        ssm (boto3.client): SSM boto3.client
        target (list): SSM target
    """

    def __init__(self, cfg):
        """Init class

        Args:
            args (object): Description
        """
        self.cfg = cfg
        self.credentials = {}
        try:
            self.ssm = self.get_client("ssm")
        except botocore.exceptions.ClientError as e:
            logger.critical(e)
            exit(1)

    def get_client(self, service):
        """boto3.client helper
        can return a simple boto3.client or execute an sts assume_role action

        Args:
            service (string): AWS service 

        Returns:
            boto3.client: client to execute action into a specific account and region
        """
        if self.cfg["iam"] == "":
            return boto3.client(service, region_name=self.cfg["region"])

        if self.credentials == {}:
            logger.info("assume Role: {}".format(self.cfg["iam"]))
            sts_client = boto3.client("sts")
            self.credentials = sts_client.assume_role(
                RoleArn=self.cfg["iam"],
                RoleSessionName="ssm-run")["Credentials"]

        return boto3.client(
            service,
            region_name=self.cfg["region"],
            aws_access_key_id=self.credentials["AccessKeyId"],
            aws_secret_access_key=self.credentials["SecretAccessKey"],
            aws_session_token=self.credentials["SessionToken"])

    def extract(self, items, search="Name"):
        result = []
        for key in items:
            for val, val2 in key.items():
                if val == search:
                    result.append(str(val2))
        return result

    def parse_tags(self, string):
        """Parsing string to define the Target to send the command
        for additional info please read here
        http://docs.aws.amazon.com/systems-manager/latest/userguide/send-commands-multiple.html

        Returns:
            list of dict: Target to filter the instaces registered into SSM
        """
        tag_list = []
        if string == "":
            return tag_list
        for tags in string.split(","):
            t = tags.split("=")
            tag_list.append({"Key": t[0], "Value": t[1]})

        return tag_list

    def get_tags(self, raw_tags):
        """Convert Key Value to a dict
        Args:
            raw_tags (dict): A dict of key / value pairs
        Returns:
            dict: Filter-friendly tag list
        """
        tags = {}
        try:
            for tag in raw_tags:
                tags[tag["Key"]] = tag["Value"].encode("utf-8")
        except (IndexError, TypeError):
            pass
        return tags

    def setup(self):
        try:
            logger.info("Creating KMS Key: {}".format(self.cfg["kms"]))
            kms = self.get_client('kms')
            key_id = kms.create_key(
                Description=self.cfg["kms"],
                KeyUsage='ENCRYPT_DECRYPT',
                Tags=[{
                    'TagKey': 'Name',
                    'TagValue': self.cfg["kms"]
                }])["KeyMetadata"]["KeyId"]

            logger.info("Creating KMS alias {} for key {}".format(
                self.cfg["kms"], key_id))
            result = kms.create_alias(
                AliasName=self.cfg["kms"], TargetKeyId=key_id)
            return (result["ResponseMetadata"]["HTTPStatusCode"] == 200)
        except:
            logger.error(sys.exc_info()[1])
            sys.exit(1)

    def erase(self):
        try:
            logger.info("Deleting KMS Key: {}".format(self.cfg["kms"]))
            kms = self.get_client('kms')
            for alias in kms.list_aliases()["Aliases"]:
                if alias["AliasName"] == self.cfg["kms"]:
                    logger.info(
                        "Schedule key {} for deletion".format(self.cfg["kms"]))
                    result = kms.schedule_key_deletion(
                        KeyId=alias["TargetKeyId"], PendingWindowInDays=7)
                    return (
                        result["ResponseMetadata"]["HTTPStatusCode"] == 200)
            logger.error("KMS AliasName NOT found : {} in {}".format(
                self.cfg["kms"], self.cfg["region"]))
            return False
        except:
            logger.error(sys.exc_info()[1])
            sys.exit(1)

    def blockerase(self):
        try:
            logger.info("Restoring KMS Key: {}".format(self.cfg["kms"]))
            kms = self.get_client('kms')
            key_id = None
            for alias in kms.list_aliases()["Aliases"]:
                if alias["AliasName"] == self.cfg["kms"]:
                    logger.info(
                        "Cancel key deletion for {}".format(self.cfg["kms"]))
                    result = kms.cancel_key_deletion(
                        KeyId=alias["TargetKeyId"], )
                    return (
                        result["ResponseMetadata"]["HTTPStatusCode"] == 200)
            logger.error("KMS AliasName NOT found : {} in {}".format(
                self.cfg["kms"], self.cfg["region"]))
            return False
        except:
            logger.error(sys.exc_info()[1])
            sys.exit(1)

    def describe_parameters(self):
        try:
            pms = self.ssm.describe_parameters(Filters=[{
                'Key':
                'KeyId',
                'Values': [self.cfg["kms"]]
            }])["Parameters"]
        except:
            logger.error(sys.exc_info()[1])
            sys.exit(1)
        return self.extract(pms)

    def get_parameter(self, parm, autosalt=True):
        try:
            secret = self.ssm.get_parameter(
                Name=parm, WithDecryption=True)["Parameter"]["Value"]

            if secret.startswith("salt:"):

                if not autosalt:
                    return secret

                logger.debug("secret with salt")
                kms = self.get_client('kms')
                return kms.decrypt(
                    CiphertextBlob=base64.b64decode(secret[5:]), )["Plaintext"]
            else:
                return secret
        except:
            logger.error(sys.exc_info()[1])
            sys.exit(1)

    def delete_parameter(self, secret):
        if secret in self.describe_parameters():
            try:
                result = self.ssm.delete_parameter(Name=str(secret))
            except:
                logger.error(sys.exc_info()[1])
                sys.exit(1)
        else:
            return True
        # work around to check if the secret is deleted
        #  ssm.delete_parameter does not return nothing
        return (result["ResponseMetadata"]["HTTPStatusCode"] == 200)

    def put_parameter(self, secret, value, stype, overwrite, salt):
        try:
            if salt:
                kms = self.get_client('kms')
                enc = kms.encrypt(
                    KeyId=self.cfg["kms"],
                    Plaintext=value, )
                final_value = "salt:{}".format(
                    base64.b64encode(enc['CiphertextBlob']).decode('utf-8'))
            else:
                final_value = str(value)

            if stype == "SecureString":
                result = self.ssm.put_parameter(
                    Name=str(secret),
                    Description=str(secret),
                    Value=final_value,
                    Type=stype,
                    KeyId=self.cfg["kms"],
                    Overwrite=overwrite, )
            else:
                result = self.ssm.put_parameter(
                    Name=str(secret),
                    Description=str(secret),
                    Value=final_value,
                    Type=stype,
                    Overwrite=overwrite, )
        except:
            logger.error(sys.exc_info()[1])
            sys.exit(1)
        return (result["ResponseMetadata"]["HTTPStatusCode"] == 200)

    def tag_parameter(self, secret, value, purge):
        if purge:
            tag_list = self.ssm.list_tags_for_resource(
                ResourceType='Parameter', ResourceId=secret)["TagList"]

            tags = self.get_tags(tag_list).keys()
            if len(tags) > 0:
                self.ssm.remove_tags_from_resource(
                    ResourceType='Parameter', ResourceId=secret, TagKeys=tags)

        result = self.ssm.add_tags_to_resource(
            ResourceType='Parameter',
            ResourceId=secret,
            Tags=self.parse_tags(value))
        return (result["ResponseMetadata"]["HTTPStatusCode"] == 200)

    def get_tag_parameter(self, secret):
        try:
            tag_list = self.ssm.list_tags_for_resource(
                ResourceType='Parameter', ResourceId=secret)["TagList"]

            return self.get_tags(tag_list)
        except:
            logger.error(sys.exc_info()[1])
            sys.exit(1)
