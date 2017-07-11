#!/usr/bin/env python

import sys
import logging
import re
import json
import os
from functools import wraps
import click
from botocore.vendored import requests
from core import EC2stash

# Setup simple logging for INFO
logging.getLogger("botocore").setLevel(logging.CRITICAL)
logger = logging.getLogger("ec2stash")
handler = logging.StreamHandler(sys.stdout)
FORMAT = "[%(asctime)s][%(levelname)s] %(message)s"
handler.setFormatter(logging.Formatter(FORMAT))
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def catch_exceptions(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        """
        Invokes ``func``, catches expected errors, prints the error message and
        exits sceptre with a non-zero exit code.
        """
        try:
            return func(*args, **kwargs)
        except:
            logger.error(sys.exc_info()[1])
            sys.exit(1)

    return decorated


@click.group()
@click.version_option(prog_name="ec2stash")
@click.pass_context
@click.option(
    "--iam", default=os.environ.get("AWS_SSM_ROLE", ""), help="IAM to assume")
@click.option(
    "--region",
    default=os.environ.get("AWS_DEFAULT_REGION", "eu-west-1"),
    help="AWS region")
@click.option("--kms", default="alias/ec2stash", help="KMS Key")
def cli(ctx, iam, region, kms):  # pragma: no cover
    ctx.obj = {
        "options": {},
        "region": region,
        "iam": iam,
        "kms": kms,
    }
    pass


@cli.command(name="setup")
@click.pass_context
@catch_exceptions
def setup(ctx):
    if EC2stash(ctx.obj).setup():
        logger.info("Setup Completed")
    else:
        logger.error("Setup FAILED")


@cli.command(name="erase")
@click.pass_context
@catch_exceptions
def erase(ctx):
    if click.confirm(
            "Do you want to delete KMS key {} ?".format(ctx.obj["kms"]),
            abort=True):
        if EC2stash(ctx.obj).erase():
            logger.info("Action Completed")
        else:
            logger.error("Action FAILED")


@cli.command(name="blockerase")
@click.pass_context
@catch_exceptions
def blockerase(ctx):
    if click.confirm(
            "Do you want to block the deletion KMS key {} ?".format(
                ctx.obj["kms"]),
            abort=True):
        if EC2stash(ctx.obj).blockerase():
            logger.info("Key Restored")
        else:
            logger.error("Action FAILED")


@cli.command(name="backup")
# @click.option("--password",
#     default="",
#     help="password to encrypt: default empty no encryption")
@click.option(
    "--output", default="stdout", help="Output File: default stdout")
@click.pass_context
@catch_exceptions
def backup(ctx, output):
    backup = {}
    stash = EC2stash(ctx.obj)
    for secret in stash.describe_parameters():
        backup[secret] = {
            "value": stash.get_parameter(secret, False),
            "tags": stash.get_tag_parameter(secret)
        }

    if output == "stdout":
        click.echo(json.dumps(backup, indent=4))
    else:
        with open(output, "w") as text_file:
            text_file.write(json.dumps(backup, indent=4))


@cli.command(name="restore")
@click.argument('vault')
@click.pass_context
@catch_exceptions
def restore(ctx, vault):
    if os.path.exists(vault):
        with open(vault) as data_file:
            data = json.load(data_file)

        stash = EC2stash(ctx.obj)
        for secret, metadata in data.items():

            tag = []
            if metadata != {}:
                for key, val in metadata["tags"].items():
                    tag.append("{}={}".format(key, val))

            stash.put_parameter(secret, metadata["value"], True, False)
            stash.tag_parameter(secret, ",".join(tag), True)
        logger.info("Restore Completed")
    else:
        logger.error("Vault NOT found")


@cli.command(name="list")
@click.pass_context
@catch_exceptions
def list(ctx):
    print "\n".join(EC2stash(ctx.obj).describe_parameters())


@cli.command(name="get")
@click.argument('secret')
@click.pass_context
def get(ctx, secret):
    print EC2stash(ctx.obj).get_parameter(secret)


@cli.command(name="delete")
@click.argument('secret')
@click.pass_context
@catch_exceptions
def delete(ctx, secret):
    if click.confirm(
            "Do you want to delete the secret {} ?".format(secret),
            abort=True):
        if EC2stash(ctx.obj).delete_parameter(secret):
            logger.info("secret {} deleted".format(secret))
        else:
            logger.error("secret {} NOT deleted".format(secret))
    else:
        logger.info("Abort: secret {} not delete".format(secret))


@cli.command(name="put")
@click.argument('secret')
@click.argument('value')
@click.option('--overwrite/--no-overwrite', default=True)
@click.option(
    "--stype", type=click.Choice(["String", "StringList", "SecureString"]), default="SecureString",
    help="String Type default:SecureString")
@click.option('--salt/--no-salt', default=False)
@click.pass_context
@catch_exceptions
def put(ctx, secret, value, stype, overwrite, salt):
    if EC2stash(ctx.obj).put_parameter(secret, value, stype, overwrite, salt):
        logger.info("secret {} saved".format(secret))
    else:
        logger.error("secret {} NOT saved".format(secret))


@cli.command(name="gettag")
@click.argument('secret')
@click.pass_context
@catch_exceptions
def gettag(ctx, secret):
    click.echo(EC2stash(ctx.obj).get_tag_parameter(secret))


@cli.command(name="tag")
@click.argument('secret')
@click.argument('value')
@click.option('--purge/--no-purge', default=False)
@click.pass_context
@catch_exceptions
def tag(ctx, secret, value, purge):
    if EC2stash(ctx.obj).tag_parameter(secret, value, purge):
        logger.info("secret {} tagged".format(secret))
    else:
        logger.error("secret {} NOT tagged".format(secret))


@cli.command(name="render")
@click.argument('location')
@click.option("--output", default="stdout", help="Output File: default stdout")
@click.pass_context
@catch_exceptions
def render(ctx, location, output):
    obj = EC2stash(ctx.obj)

    if location.startswith("http"):
        # logger.info("download template: {}".format(location))
        response = requests.get(location, stream=True)
        content = response.content

    elif location.startswith("s3://"):
        # logger.info("download S3 template: {}".format(location))

        bucket = location.replace("s3://", "").split("/")[0]
        key = location.replace("s3://{}/".format(bucket), "")
        s3_client = obj.get_client("s3")
        content = s3_client.get_object(Bucket=bucket, Key=key)['Body'].read()

    else:
        # logger.info("local file {} ".format(location))
        tmp_file = location
        content = open(tmp_file, 'r').read()

    # var lookup and replacement
    match = re.findall('{{(.*)}}', content)
    for secret in match:
        content = content.replace('{{' + str(secret) + '}}',
                                  obj.get_parameter(secret))

    # check all vars are replaced
    check = re.findall('{{(.*)}}', content)
    if len(check) > 0:
        logger.error("parameters not resolved:")
        print "\n".join(check)
    else:
        if output == "stdout":
            click.echo(content)
        else:
            with open(output, "w") as text_file:
                text_file.write(content)

            logger.info("templated render into the file: {}".format(output))


if __name__ == '__main__':
    from os import sys, path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
    cli()
