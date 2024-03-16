#!/bin/bash

BUCKET=$(aws ssm get-parameter --name /resources/s3/ForensicsDataBucket/Name  | jq -r ".Parameter.Value")

TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
EC2_INSTANCE_ID=`curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id`

if [[ ! -d $EC2_INSTANCE_ID ]];then
  mkdir $EC2_INSTANCE_ID
fi
cd $EC2_INSTANCE_ID

# w -i
w -i >w-$(date --utc +%Y%m%d_%H%M%SZ).txt

# who -a
who -a >who-$(date --utc +%Y%m%d_%H%M%SZ).txt

# ps aux
ps aux >ps-aux-$(date --utc +%Y%m%d_%H%M%SZ).txt

# lsof
lsof >lsof-$(date --utc +%Y%m%d_%H%M%SZ).txt

# netstat -anp
netstat -anp >netstat-anp-$(date --utc +%Y%m%d_%H%M%SZ).txt

# lsmod
lsmod >lsmod-$(date --utc +%Y%m%d_%H%M%SZ).txt

# lime
TOTAL_RAM=$(free |grep Mem |awk {'print $2'})
FREE_SPACE=$(df |grep /$ |awk {'print $4'})

# ~10 sec /gb of ram, 16GB ram = 3 min
if [[ $TOTAL_RAM -lt $FREE_SPACE && $TOTAL_RAM  -lt 17000000 ]];then
  CUR_DIR=`pwd`
  if [[ ! -d /root/LiME ]];then
    cd /root
    git clone https://github.com/504ensicsLabs/LiME.git
  fi

  cd /root/LiME/src
  make
  cd $CUR_DIR
  rmmod lime
  insmod /root/LiME/src/lime-$(uname -r).ko "path=ramdump-$(date --utc +%Y%m%d_%H%M%SZ).mem format=lime"
else
  echo "Skipping RAM Dump."
fi

if [[ $BUCKET != "" ]];then
  cd ../
  aws s3 cp --recursive $EC2_INSTANCE_ID/ s3://${BUCKET}/$EC2_INSTANCE_ID/$(date --utc +%Y%m%d_%H%M%SZ)/
else
  echo "Bucket name not found."
fi