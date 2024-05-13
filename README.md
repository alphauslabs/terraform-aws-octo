# terraform-aws-octo
Terraform module for AWS account setup in OCTO

## Terms

We use the term `payer` = master account and `linked` = sub account.

## Pre-requisites

1. You shoud have permission on `'organization:Describe*'` action in order to proceed, this will help us to determine if the account is a linked or payer account.

2. For using stackset to setup multiple account API access:

    - User access to the payer account in your AWS Management Console
    - User permissions to use StackSets in your AWS Management Console
    - Activate trusted access with AWS Organizations. See [Activating trusted access with AWS Organizations](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-enable-trusted-access.html) in the AWS CloudFormation User Guide.

## General Guide

By importing this module you can setup needed resources for onboarding AWS accounts to OCTO. These module will create IAM roles and policies in order to give Alphaus access to some API operation on your account. These module will also create a CUR definition and S3 bucket to store the CUR report. This module will require you to enter your `access_key` and `secret_key` for authenticating purposes only. You can also use AWS CLI for the same purpose.

(Optional for payer account only) You can also use this module to setup multiple account API access using stackset. If you have multiple accounts that you want to onboard to OCTO, you can use this module to setup the needed resources for enabling API Access on all sub-account in your organization.
