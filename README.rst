===============
EC2 Stash Store
===============

.. image:: https://circleci.com/gh/giuliocalzolari/ec2stash/tree/master.svg?style=svg
    :target: https://circleci.com/gh/giuliocalzolari/ec2stash/tree/master

.. image:: https://badge.fury.io/py/ec2stash.png
    :target: https://badge.fury.io/py/ec2stash


Config
------

this script is designed to run across multiple accounts and across multiple regions you can switch between regions/accounts using some OS vars

To execute an assume role action::

  $ export AWS_SSM_ROLE=arn:aws:iam::111111111:role/admin


Command
-------
::

  $ ec2stash -h
  Usage: ec2stash [OPTIONS] COMMAND [ARGS]...

  Options:
    --iam TEXT     IAM to assume
    --region TEXT  AWS region
    --kms TEXT     KMS Key
    --help         Show this message and exit.

  Commands:
    backup
    blockerase
    delete
    erase
    get
    gettag
    list
    put
    render
    restore
    setup
    tag



License
-------

ec2stash is licensed under the `MIT <LICENSE>`_.
