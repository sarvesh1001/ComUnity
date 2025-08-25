#!/usr/bin/env python3
"""
Certificate Expiry Monitoring with CloudWatch Alarms
"""
import boto3
from datetime import datetime, timedelta
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

ssm = boto3.client('ssm')
cloudwatch = boto3.client('cloudwatch')

def check_cert_expiry():
    try:
        # Get expiry date from SSM
        response = ssm.get_parameter(Name='/authservice/cert_expiry', WithDecryption=True)
        expiry_str = response['Parameter']['Value']
        expiry_date = datetime.fromisoformat(expiry_str)
        
        # Calculate days until expiry
        days_left = (expiry_date - datetime.utcnow()).days
        
        # Send metric to CloudWatch
        cloudwatch.put_metric_data(
            Namespace='AuthService',
            MetricData=[{
                'MetricName': 'CertificateExpiryDays',
                'Value': days_left,
                'Unit': 'Count',
                'Dimensions': [
                    {'Name': 'Service', 'Value': 'Authentication'},
                    {'Name': 'Environment', 'Value': 'Production'}
                ]
            }]
        )
        
        logger.info(f"Certificate expiry: {days_left} days remaining")
        return days_left
    except Exception as e:
        logger.error(f"Error monitoring certificate expiry: {str(e)}")
        return None

if __name__ == "__main__":
    check_cert_expiry()